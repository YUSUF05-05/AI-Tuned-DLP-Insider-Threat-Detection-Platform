"""
database/sqlite_audit.py  (Phase 9; extended in Phase 10 Step 0)

Durable, queryable persistence for fully-enriched DLPEvents. This is what
turns logs/*.jsonl from "the record" into "the durability fallback" -- the
JSONL logs keep being written (Phase 3-8 already do this, unchanged), and
this module is an ADDITIONAL sink the pipeline writes to, not a replacement.

THREAD SAFETY (the actual point of this module, not an afterthought):
collectors/file_collector.py runs on watchdog's own Observer thread;
collectors/http_collector.py's Flask app runs on a separate thread started
in run_pipeline_demo.py. Both can call insert_event() at any moment. This
class uses ONE shared sqlite3.Connection guarded by a single
threading.RLock for every read and write -- see the class docstring below
for why that's the right amount of engineering for this project's actual
concurrency level, rather than a connection pool or one-connection-per-thread
scheme.

PHASE 10 STEP 0 ADDITIONS (see docs/DATABASE.md for the full writeup):
  - `read_only=True` mode: opens the connection via SQLite's URI read-only
    mode and skips schema init entirely. This is what dashboard/api.py uses
    -- the dashboard is a SEPARATE process from run_pipeline_demo.py and
    must never be able to write to the audit trail, enforced here at the
    connection level, not just by "the dashboard code just doesn't call
    insert_event()" convention.
  - `_migrate_schema()`: a small forward-compat shim so a database file
    created by a PRE-Step-0 schema.sql (missing the new behavioral_*
    columns) gets them added via ALTER TABLE rather than failing every
    insert. See its own docstring for what this deliberately does NOT
    attempt to migrate.
  - `insert_event(event, behavior=...)`: persists the FULL Phase 8
    BehavioralContext, not just the adjustment integer (schema.sql has the
    column-level rationale).
  - `severity_counts()` / `verify_integrity()`: read-only aggregate and
    self-check methods the dashboard's summary view is built on.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from common.event_schema import DLPEvent
from correlation.behavior_tracker import BehavioralContext
from detectors.engine import needs_ai_review

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "database" / "audit_trail.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

# Every append-only trigger schema.sql now creates -- verify_integrity() and
# the read_only constructor's sanity checks both compare against this list so
# there is exactly one place that has to stay in sync with schema.sql.
_EXPECTED_IMMUTABILITY_TRIGGERS = {
    "trg_events_no_update", "trg_events_no_delete",
    "trg_detections_no_update", "trg_detections_no_delete",
    "trg_obfuscation_no_update", "trg_obfuscation_no_delete",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class SQLiteAuditStore:
    """
    Thread-safe wrapper around a single shared SQLite connection.

    WHY ONE SHARED CONNECTION + A LOCK, NOT A CONNECTION PER THREAD:
    SQLite only ever allows one writer at a time no matter how many
    connections exist -- a per-thread-connection design still needs
    external serialization to avoid "database is locked" errors under
    concurrent writes, it just moves the complexity around rather than
    removing it. One connection + one threading.RLock is the simpler,
    equally-correct choice for this project's real concurrency level (a
    handful of collector threads, not a pooled web service), and is easy
    for a reviewer to verify correct by inspection rather than by trusting
    a pooling library.

    `check_same_thread=False` only disables Python's OWN thread-affinity
    check (which would otherwise raise on first cross-thread use) -- the
    Lock is what actually makes concurrent access safe, not that flag by
    itself. WAL mode is enabled so Phase 10's dashboard (or a person poking
    around in DB Browser for SQLite) can read the database while the
    pipeline is still writing to it, without blocking either side.
    `busy_timeout` covers cross-PROCESS contention (e.g. exactly that: the
    pipeline running while someone has the same file open in a DB browser).

    read_only=True (Phase 10): opens the SAME file through a SQLite URI
    read-only connection (`file:...?mode=ro`) instead. No schema init runs
    -- CREATE TABLE/TRIGGER/INDEX IF NOT EXISTS are idempotent no-ops on an
    already-correct schema, but they are still, mechanically, write
    attempts, and a read-only connection can't perform them (nor should it
    try). The database file must already exist; this class will not create
    one out from under a read-only caller. Every write method
    (insert_event) raises PermissionError immediately in this mode, before
    ever touching SQLite, so a future write path added to a read-only
    caller (e.g. the dashboard) fails loudly and immediately in Python
    rather than surfacing as a confusing sqlite3 "attempt to write a
    readonly database" error three layers down.
    """

    def __init__(
        self,
        db_path: str | Path = DEFAULT_DB_PATH,
        schema_path: str | Path = SCHEMA_PATH,
        read_only: bool = False,
    ):
        self.db_path = Path(db_path)
        self.read_only = read_only
        self._lock = threading.RLock()

        if read_only:
            if not self.db_path.exists():
                raise FileNotFoundError(
                    f"Audit database not found at {self.db_path} -- "
                    "SQLiteAuditStore(read_only=True) will not create one (that "
                    "would itself be a write). Run the pipeline "
                    "(run_pipeline_demo.py) at least once first, or pass "
                    "read_only=False."
                )
            db_uri = self.db_path.resolve().as_uri()
            db_uri += ("&mode=ro" if "?" in db_uri else "?mode=ro")
            self._conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            # No _init_schema()/_migrate_schema() here -- both are write
            # paths (CREATE ... IF NOT EXISTS / ALTER TABLE), which a
            # read-only connection cannot perform and, per this class's own
            # design goal for read_only mode, should never attempt.
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            with self._lock:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._conn.execute("PRAGMA busy_timeout=30000")
                self._init_schema(schema_path)
                self._migrate_schema()

    def _init_schema(self, schema_path: str | Path) -> None:
        schema_sql = Path(schema_path).read_text(encoding="utf-8")
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def _migrate_schema(self) -> None:
        """
        Forward-compat shim for a database created before this phase's
        schema change added the behavioral_* columns to `events`.
        CREATE TABLE IF NOT EXISTS in schema.sql only handles a brand-new
        database file; an already-existing `events` table is left exactly
        as it was. This adds any missing behavioral_* columns with
        ALTER TABLE ... ADD COLUMN, which SQLite supports for simple column
        additions (no data loss; existing rows get NULL in the new
        columns, same as if `behavior` had been None on the original
        insert_event() call).

        What this deliberately does NOT attempt: retrofitting the FK
        `ON DELETE CASCADE` -> `NO ACTION` change onto an already-existing
        `detections`/`obfuscation` table, since SQLite cannot ALTER a
        foreign key's ON DELETE clause without a full rename + recreate +
        copy + drop migration -- judged out of scope for this
        lab/portfolio project (see docs/DATABASE.md "Migrating an existing
        database"). The append-only TRIGGERS, unlike the FK clause, ARE
        independent schema objects and get added to an old database
        automatically by _init_schema()'s CREATE TRIGGER IF NOT EXISTS
        above, regardless of this method -- the important half of the
        Step-0 fix self-heals even on a pre-existing database file; this
        method only backfills the informational behavioral_* columns.
        """
        existing_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(events)").fetchall()}
        new_columns = {
            "behavioral_event_count_in_window": "INTEGER",
            "behavioral_escalating": "INTEGER",
            "behavioral_repeated_categories_json": "TEXT",
            "behavioral_explanation_json": "TEXT",
        }
        for col, coltype in new_columns.items():
            if col not in existing_cols:
                self._conn.execute(f"ALTER TABLE events ADD COLUMN {col} {coltype}")
        self._conn.commit()

    def insert_event(self, event: DLPEvent, behavior: Optional[BehavioralContext] = None) -> None:
        """
        Persist a fully enriched DLPEvent (events + its detections + its
        obfuscation rows, one transaction). Raises sqlite3.IntegrityError on
        a duplicate event_id rather than silently overwriting -- an audit
        trail should not allow silent overwrites of already-recorded
        events; a duplicate insert indicates a bug upstream, not something
        to paper over here. Callers in the live pipeline (run_pipeline_demo.py)
        catch this and log rather than crash the collector loop.

        `behavior`, when supplied, is the Phase 8
        correlation.behavior_tracker.BehavioralContext computed for this
        SAME event -- see run_pipeline_demo.py's analyze_event(), which
        already computes it to feed scoring.risk_engine.compute_risk()'s
        behavioral_adjustment parameter, and (as of this Step 0 fix) also
        passes the whole object here so the REASONING behind that integer
        survives in the audit trail. Optional and defaults to None for
        events scored before Phase 8 ever ran, or any other caller (e.g. a
        test) with no BehavioralContext to hand over -- the four
        behavioral_* columns simply stay NULL in that case.
        """
        if self.read_only:
            raise PermissionError(
                "This SQLiteAuditStore was opened with read_only=True (e.g. "
                "the dashboard process) -- refusing to write. If this is a "
                "legitimate write path, open a normal (read_only=False) "
                "store instead."
            )

        ai = event.ai_analysis
        risk = event.risk_assessment
        ai_is_sensitive = int(ai.is_sensitive) if (ai and ai.is_sensitive is not None) else None

        behavioral_event_count = behavior.event_count_in_window if behavior else None
        behavioral_escalating = int(behavior.escalating) if (behavior and behavior.escalating is not None) else None
        behavioral_repeated_categories_json = json.dumps(behavior.repeated_categories) if behavior else None
        behavioral_explanation_json = json.dumps(behavior.explanation) if behavior else None

        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO events (
                        event_id, schema_version, timestamp, host, user, source, event_type,
                        object_ref, size_bytes, content_excerpt, raw_metadata_json, any_match, needs_ai_review,
                        ai_status, ai_is_sensitive, ai_category, ai_confidence, ai_reasoning, ai_model, ai_duration_ms, ai_error,
                        risk_score, risk_base_score, risk_severity, risk_behavioral_adjustment,
                        risk_components_json, risk_explanation_json,
                        behavioral_event_count_in_window, behavioral_escalating,
                        behavioral_repeated_categories_json, behavioral_explanation_json,
                        inserted_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event.event_id, event.schema_version, event.timestamp, event.host, event.user,
                        event.source, event.event_type, event.object_ref, event.size_bytes, event.content_excerpt,
                        json.dumps(event.raw_metadata), int(event.any_match), int(needs_ai_review(event.detections)),
                        ai.status if ai else None, ai_is_sensitive, ai.category if ai else None,
                        ai.confidence if ai else None, ai.reasoning if ai else None, ai.model if ai else None,
                        ai.duration_ms if ai else None, ai.error if ai else None,
                        risk.score if risk else None, risk.base_score if risk else None,
                        risk.severity if risk else None, risk.behavioral_adjustment if risk else None,
                        json.dumps(risk.components) if risk else None,
                        json.dumps(risk.explanation) if risk else None,
                        behavioral_event_count, behavioral_escalating,
                        behavioral_repeated_categories_json, behavioral_explanation_json,
                        _utc_now_iso(),
                    ),
                )
                for d in event.detections:
                    if not d.matched:
                        continue  # a non-match carries no audit-worthy data; the detections
                                  # table is "what was found", not "every detector invoked"
                    self._conn.execute(
                        "INSERT INTO detections (event_id, detector, matched, category, confidence, matches_json, details_json) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (event.event_id, d.detector, int(d.matched), d.category, d.confidence,
                         json.dumps(d.matches), json.dumps(d.details)),
                    )
                for ob in event.obfuscation:
                    self._conn.execute(
                        "INSERT INTO obfuscation (event_id, technique, found, layers, decoded_excerpt, rescanned_detections_json) "
                        "VALUES (?,?,?,?,?,?)",
                        (event.event_id, ob.technique, int(ob.found), ob.layers, ob.decoded_excerpt,
                         json.dumps([r.to_dict() for r in ob.rescanned_detections])),
                    )
                self._conn.commit()
            except sqlite3.Error:
                self._conn.rollback()
                raise

    def get_event(self, event_id: str) -> Optional[dict[str, Any]]:
        """Full single-event reconstruction, JSON columns parsed back -- for a dashboard detail view."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["raw_metadata"] = json.loads(result.pop("raw_metadata_json"))
            result["risk_components"] = json.loads(result.pop("risk_components_json")) if result.get("risk_components_json") else None
            result["risk_explanation"] = json.loads(result.pop("risk_explanation_json")) if result.get("risk_explanation_json") else None
            result["behavioral_repeated_categories"] = json.loads(result.pop("behavioral_repeated_categories_json")) if result.get("behavioral_repeated_categories_json") else None
            result["behavioral_explanation"] = json.loads(result.pop("behavioral_explanation_json")) if result.get("behavioral_explanation_json") else None

            det_rows = self._conn.execute("SELECT * FROM detections WHERE event_id = ?", (event_id,)).fetchall()
            result["detections"] = [
                {**{k: v for k, v in dict(r).items() if k not in ("matches_json", "details_json")},
                 "matches": json.loads(r["matches_json"]), "details": json.loads(r["details_json"])}
                for r in det_rows
            ]
            ob_rows = self._conn.execute("SELECT * FROM obfuscation WHERE event_id = ?", (event_id,)).fetchall()
            result["obfuscation"] = [
                {**{k: v for k, v in dict(r).items() if k != "rescanned_detections_json"},
                 "rescanned_detections": json.loads(r["rescanned_detections_json"])}
                for r in ob_rows
            ]
            return result

    def query_events(
        self,
        user: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Summary listing (events table only, no child-row joins) -- for a dashboard table view."""
        clauses, params = [], []
        if user is not None:
            clauses.append("user = ?")
            params.append(user)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        if severity is not None:
            clauses.append("risk_severity = ?")
            params.append(severity)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
            return [dict(r) for r in rows]

    def count_events(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def severity_counts(self) -> dict[str, int]:
        """
        Count of audited events per risk_severity bucket -- e.g.
        {"critical": 3, "high": 5, "medium": 10, "low": 20}. Every row in
        `events` already has a non-NULL risk_severity (only events that
        crossed compute_risk() ever reach insert_event() in the current
        pipeline wiring), but this filters NULL out defensively rather than
        assuming that will always stay true.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT risk_severity, COUNT(*) as cnt FROM events GROUP BY risk_severity"
            ).fetchall()
        return {r["risk_severity"]: r["cnt"] for r in rows if r["risk_severity"] is not None}

    def verify_integrity(self) -> dict[str, Any]:
        """
        Self-check that the Phase 10 Step 0 append-only enforcement is
        ACTUALLY active in THIS on-disk database file -- not merely that
        schema.sql says it should be. This is what dashboard/api.py's
        /api/integrity route (and its "audit chain integrity" indicator)
        is built on.

        Runs on its OWN short-lived connection, independent of self._conn /
        whatever read_only mode this store was opened with, because the
        live-fire half of this check needs a writable handle to attempt a
        real UPDATE and DELETE and confirm both are rejected -- that is a
        materially stronger claim than "the trigger text exists in
        sqlite_master", since it also catches the trigger having been
        silently dropped or a database that predates Step 0 entirely (see
        _migrate_schema()'s docstring: this is the scenario where the
        static checks below would already report unhealthy). Every
        attempted write happens inside a transaction that is
        UNCONDITIONALLY rolled back before this method returns -- including
        if the live-fire probe were ever to unexpectedly "succeed" (i.e.
        the exact failure mode this check exists to catch) -- so calling
        this method can never itself leave the audit trail in a different
        state than it found it in.
        """
        result: dict[str, Any] = {
            "healthy": False,
            "missing_triggers": [],
            "tables_with_cascade_delete": [],
            "update_blocked": None,
            "delete_blocked": None,
            "checked_live_row": False,
            "error": None,
        }
        try:
            probe = sqlite3.connect(str(self.db_path), timeout=5.0)
            probe.row_factory = sqlite3.Row
            try:
                triggers = {r["name"] for r in probe.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                ).fetchall()}
                result["missing_triggers"] = sorted(_EXPECTED_IMMUTABILITY_TRIGGERS - triggers)

                cascade_tables = []
                for table in ("detections", "obfuscation"):
                    for r in probe.execute(f"PRAGMA foreign_key_list({table})").fetchall():
                        if (r["on_delete"] or "").upper() == "CASCADE":
                            cascade_tables.append(table)
                result["tables_with_cascade_delete"] = cascade_tables

                row = probe.execute("SELECT event_id FROM events LIMIT 1").fetchone()
                if row is not None:
                    result["checked_live_row"] = True
                    event_id = row["event_id"]
                    try:
                        probe.execute("BEGIN")
                        try:
                            probe.execute("UPDATE events SET risk_score = risk_score WHERE event_id = ?", (event_id,))
                            result["update_blocked"] = False
                        except sqlite3.Error:
                            result["update_blocked"] = True
                        try:
                            probe.execute("DELETE FROM events WHERE event_id = ?", (event_id,))
                            result["delete_blocked"] = False
                        except sqlite3.Error:
                            result["delete_blocked"] = True
                    finally:
                        probe.execute("ROLLBACK")
            finally:
                probe.close()
        except sqlite3.Error as exc:
            result["error"] = str(exc)
            return result

        result["healthy"] = (
            not result["missing_triggers"]
            and not result["tables_with_cascade_delete"]
            and result["update_blocked"] is not False
            and result["delete_blocked"] is not False
        )
        return result

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteAuditStore":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
