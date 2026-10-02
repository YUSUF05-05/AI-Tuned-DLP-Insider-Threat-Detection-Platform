"""
tests/test_database_behavioral_context.py

New tests for persisting the FULL Phase 8 BehavioralContext (not just the
single risk_behavioral_adjustment integer) via
SQLiteAuditStore.insert_event(event, behavior=...) and reading it back
through get_event(). Also tests the _migrate_schema() forward-compat shim
that backfills the new behavioral_* columns onto a database file created
before this Step 0 fix.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event, DetectionResult, RiskAssessment
from correlation.behavior_tracker import BehavioralContext
from database.sqlite_audit import SQLiteAuditStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteAuditStore(db_path=tmp_path / "audit_trail.db")
    yield s
    s.close()


def _flagged_event():
    event = build_event(source="http", event_type="http_request", object_ref="/upload", size_bytes=10,
                         content_excerpt="ssn 123-45-6789")
    event.detections = [DetectionResult(detector="keyword_detector", matched=True, category="customer_data",
                                         confidence=0.6, matches=["customer_data:social security number"])]
    event.risk_assessment = RiskAssessment(
        score=45, base_score=33, severity="medium", behavioral_adjustment=12,
        components={"deterministic": 0.6, "ai": 0.0, "context": 0.0, "destination": 1.0},
        weighted_contributions={"deterministic": 24.0, "ai": 0.0, "context": 0.0, "destination": 20.0},
        explanation=["deterministic: ...", "behavioral: +12 points from Phase 8 correlation"],
    )
    return event


def test_full_behavioral_context_round_trips(store):
    event = _flagged_event()
    behavior = BehavioralContext(
        adjustment=12,
        event_count_in_window=5,
        escalating=True,
        repeated_categories=["customer_data", "financial"],
        explanation=[
            "repeated activity: 5 flagged event(s) in window (>= 4) -> +12",
            "escalation: average base_score rose 20.0 -> 33.0 (+13.0) -> +10",
            "repeated category: customer_data, financial recur(s) across events in window -> +8",
        ],
    )
    store.insert_event(event, behavior=behavior)

    fetched = store.get_event(event.event_id)
    assert fetched["behavioral_event_count_in_window"] == 5
    assert fetched["behavioral_escalating"] == 1  # stored/returned as raw 0/1, same convention as ai_is_sensitive
    assert fetched["behavioral_repeated_categories"] == ["customer_data", "financial"]
    assert len(fetched["behavioral_explanation"]) == 3
    assert fetched["risk_behavioral_adjustment"] == 12  # unchanged existing column, still populated


def test_insert_event_without_behavior_leaves_new_columns_null(store):
    event = _flagged_event()
    store.insert_event(event, behavior=None)  # e.g. an event scored before Phase 8 ever ran

    fetched = store.get_event(event.event_id)
    assert fetched["behavioral_event_count_in_window"] is None
    assert fetched["behavioral_escalating"] is None
    assert fetched["behavioral_repeated_categories"] is None
    assert fetched["behavioral_explanation"] is None


def test_insert_event_backward_compatible_default(store):
    """behavior= is optional -- existing call sites that don't pass it must
    keep working exactly as before this change."""
    event = _flagged_event()
    store.insert_event(event)  # no behavior kwarg at all
    assert store.get_event(event.event_id) is not None


def test_behavioral_context_with_no_repeated_categories(store):
    event = _flagged_event()
    behavior = BehavioralContext(adjustment=5, event_count_in_window=2, escalating=False,
                                  repeated_categories=[], explanation=["repeated activity: 2 -> +5"])
    store.insert_event(event, behavior=behavior)
    fetched = store.get_event(event.event_id)
    assert fetched["behavioral_repeated_categories"] == []
    assert fetched["behavioral_escalating"] == 0


def test_migrate_schema_adds_missing_columns_to_a_pre_existing_db(tmp_path):
    """
    Simulates a database file created by an OLDER version of schema.sql
    (pre-Step-0, no behavioral_* columns) to confirm _migrate_schema()'s
    ALTER TABLE ADD COLUMN shim brings it up to date without data loss --
    see schema.sql / docs/DATABASE.md "Migrating an existing database".
    """
    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL, timestamp TEXT NOT NULL,
            host TEXT NOT NULL, user TEXT NOT NULL, source TEXT NOT NULL, event_type TEXT NOT NULL,
            object_ref TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, content_excerpt TEXT,
            raw_metadata_json TEXT NOT NULL DEFAULT '{}', any_match INTEGER NOT NULL DEFAULT 0,
            needs_ai_review INTEGER NOT NULL DEFAULT 0, ai_status TEXT, ai_is_sensitive INTEGER,
            ai_category TEXT, ai_confidence REAL, ai_reasoning TEXT, ai_model TEXT, ai_duration_ms INTEGER,
            ai_error TEXT, risk_score INTEGER, risk_base_score INTEGER, risk_severity TEXT,
            risk_behavioral_adjustment INTEGER, risk_components_json TEXT, risk_explanation_json TEXT,
            inserted_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "INSERT INTO events (event_id, schema_version, timestamp, host, user, source, event_type, "
        "object_ref, inserted_at) VALUES "
        "('legacy-1', '0.5.0', '2026-01-01T00:00:00.000Z', 'host', 'user', 'file', 'file_created', "
        "'/x', '2026-01-01T00:00:00.000Z')"
    )
    conn.commit()
    conn.close()

    store = SQLiteAuditStore(db_path=db_path)  # should ALTER TABLE the missing columns in, not fail

    raw = sqlite3.connect(str(db_path))
    raw.row_factory = sqlite3.Row
    cols = {r["name"] for r in raw.execute("PRAGMA table_info(events)").fetchall()}
    assert "behavioral_event_count_in_window" in cols
    assert "behavioral_escalating" in cols
    assert "behavioral_repeated_categories_json" in cols
    assert "behavioral_explanation_json" in cols
    # the pre-existing row must survive the migration untouched
    row = raw.execute("SELECT * FROM events WHERE event_id='legacy-1'").fetchone()
    assert row["behavioral_escalating"] is None
    assert row["user"] == "user"
    raw.close()

    # And the triggers must ALSO now be present -- the important half of the
    # Step 0 fix self-heals on an old database automatically (see
    # _migrate_schema()'s docstring).
    integrity = store.verify_integrity()
    assert integrity["missing_triggers"] == []
    store.close()
