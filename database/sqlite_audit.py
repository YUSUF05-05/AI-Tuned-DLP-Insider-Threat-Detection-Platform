"""
database/sqlite_audit.py  (Phase 9)

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
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from common.event_schema import DLPEvent
from detectors.engine import needs_ai_review

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "database" / "audit_trail.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


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
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH, schema_path: str | Path = SCHEMA_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._init_schema(schema_path)

    def _init_schema(self, schema_path: str | Path) -> None:
        schema_sql = Path(schema_path).read_text(encoding="utf-8")
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def insert_event(self, event: DLPEvent) -> None:
        """
        Persist a fully enriched DLPEvent (events + its detections + its
        obfuscation rows, one transaction). Raises sqlite3.IntegrityError on
        a duplicate event_id rather than silently overwriting -- an audit
        trail should not allow silent overwrites of already-recorded
        events; a duplicate insert indicates a bug upstream, not something
        to paper over here. Callers in the live pipeline (run_pipeline_demo.py)
        catch this and log rather than crash the collector loop.
        """
        ai = event.ai_analysis
        risk = event.risk_assessment
        ai_is_sensitive = int(ai.is_sensitive) if (ai and ai.is_sensitive is not None) else None

        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO events (
                        event_id, schema_version, timestamp, host, user, source, event_type,
                        object_ref, size_bytes, content_excerpt, raw_metadata_json, any_match, needs_ai_review,
                        ai_status, ai_is_sensitive, ai_category, ai_confidence, ai_reasoning, ai_model, ai_duration_ms, ai_error,
                        risk_score, risk_base_score, risk_severity, risk_behavioral_adjustment,
                        risk_components_json, risk_explanation_json, inserted_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteAuditStore":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
