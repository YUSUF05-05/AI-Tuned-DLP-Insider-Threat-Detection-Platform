import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import (  # noqa: E402
    build_event, DetectionResult, ObfuscationResult, AIAnalysisResult, RiskAssessment,
)
from database.sqlite_audit import SQLiteAuditStore  # noqa: E402


def _full_event(user="alice"):
    event = build_event(source="http", event_type="http_request", object_ref="/upload",
                         content_excerpt="card on file 4111111111111111")
    event.user = user
    event.detections = [
        DetectionResult(detector="card_detector", matched=True, category="payment_card",
                         confidence=1.0, matches=["visa:411111******1111"], details={"count": 1}),
    ]
    event.obfuscation = [
        ObfuscationResult(technique="base64", found=True, layers=1, decoded_excerpt="card 4111...",
                           rescanned_detections=[DetectionResult(detector="card_detector", matched=True, confidence=1.0)]),
    ]
    event.ai_analysis = AIAnalysisResult(status="ok", is_sensitive=True, category="payment_card",
                                          confidence=0.9, reasoning="looks like a card", model="llama3.2:latest", duration_ms=500)
    event.risk_assessment = RiskAssessment(score=72, base_score=72, severity="high", behavioral_adjustment=0,
                                            components={"deterministic": 1.0, "ai": 0.9, "context": 0.6, "destination": 1.0},
                                            explanation=["deterministic: ...", "final_score=72 -> HIGH"])
    return event


# --------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------

def test_schema_creates_all_tables_and_indexes(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    tables = {r[0] for r in store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"events", "detections", "obfuscation"}.issubset(tables)
    indexes = {r[0] for r in store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    assert "idx_events_user" in indexes
    assert "idx_events_severity" in indexes
    assert "idx_detections_event_id" in indexes
    store.close()


# --------------------------------------------------------------------
# Insert + retrieve, full round trip
# --------------------------------------------------------------------

def test_insert_and_get_full_event_round_trips_everything(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    event = _full_event()
    store.insert_event(event)

    row = store.get_event(event.event_id)
    assert row is not None
    assert row["event_id"] == event.event_id
    assert row["user"] == "alice"
    assert row["source"] == "http"
    assert row["content_excerpt"] == event.content_excerpt
    assert row["any_match"] == 1
    assert row["needs_ai_review"] == 1

    assert row["ai_status"] == "ok"
    assert row["ai_is_sensitive"] == 1
    assert row["ai_category"] == "payment_card"
    assert row["ai_confidence"] == 0.9
    assert row["ai_model"] == "llama3.2:latest"

    assert row["risk_score"] == 72
    assert row["risk_severity"] == "high"
    assert row["risk_components"] == {"deterministic": 1.0, "ai": 0.9, "context": 0.6, "destination": 1.0}
    assert "final_score=72 -> HIGH" in row["risk_explanation"]

    assert len(row["detections"]) == 1
    assert row["detections"][0]["detector"] == "card_detector"
    assert row["detections"][0]["matches"] == ["visa:411111******1111"]
    assert "4111111111111111" not in str(row["detections"][0]["matches"])  # masked evidence only, never raw

    assert len(row["obfuscation"]) == 1
    assert row["obfuscation"][0]["technique"] == "base64"
    assert len(row["obfuscation"][0]["rescanned_detections"]) == 1
    store.close()


def test_insert_event_with_no_ai_or_risk_stores_nulls_not_errors(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    event = build_event(source="file", event_type="file_created", object_ref="notes.txt")
    event.detections = [DetectionResult(detector="card_detector", matched=False)]
    store.insert_event(event)

    row = store.get_event(event.event_id)
    assert row["ai_status"] is None
    assert row["ai_is_sensitive"] is None
    assert row["risk_score"] is None
    assert row["risk_severity"] is None
    assert row["detections"] == []
    assert row["obfuscation"] == []
    store.close()


def test_get_nonexistent_event_returns_none(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    assert store.get_event("00000000-0000-0000-0000-000000000000") is None
    store.close()


def test_duplicate_event_id_raises_integrity_error(tmp_path):
    import sqlite3
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    event = _full_event()
    store.insert_event(event)
    with pytest.raises(sqlite3.IntegrityError):
        store.insert_event(event)  # same event_id again
    store.close()


# --------------------------------------------------------------------
# Querying
# --------------------------------------------------------------------

def test_query_events_filters_by_user(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    store.insert_event(_full_event(user="alice"))
    store.insert_event(_full_event(user="bob"))
    results = store.query_events(user="alice")
    assert len(results) == 1
    assert results[0]["user"] == "alice"
    store.close()


def test_query_events_filters_by_severity(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    high = _full_event(user="alice")
    store.insert_event(high)
    low_event = build_event(source="file", event_type="file_created", object_ref="x.txt")
    low_event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.3)]
    low_event.risk_assessment = RiskAssessment(score=10, base_score=10, severity="low")
    store.insert_event(low_event)

    results = store.query_events(severity="high")
    assert len(results) == 1
    assert results[0]["risk_severity"] == "high"
    store.close()


def test_query_events_respects_limit(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    for i in range(5):
        store.insert_event(_full_event(user=f"user{i}"))
    results = store.query_events(limit=3)
    assert len(results) == 3
    store.close()


def test_count_events(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "test.db")
    assert store.count_events() == 0
    store.insert_event(_full_event())
    assert store.count_events() == 1
    store.close()


# --------------------------------------------------------------------
# Persistence after restart
# --------------------------------------------------------------------

def test_persistence_after_restart(tmp_path):
    db_path = tmp_path / "persist_test.db"
    store1 = SQLiteAuditStore(db_path=db_path)
    event = _full_event()
    store1.insert_event(event)
    store1.close()

    store2 = SQLiteAuditStore(db_path=db_path)  # fresh instance, same file
    row = store2.get_event(event.event_id)
    assert row is not None
    assert row["risk_severity"] == "high"
    assert store2.count_events() == 1
    store2.close()


# --------------------------------------------------------------------
# Thread safety -- the actual requirement, stress-tested for real
# --------------------------------------------------------------------

def test_concurrent_inserts_from_many_threads_no_loss_no_crash(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "concurrent.db")
    thread_count = 20
    inserts_per_thread = 5
    errors: list[Exception] = []
    errors_lock = threading.Lock()

    def worker(thread_id: int):
        try:
            for i in range(inserts_per_thread):
                event = _full_event(user=f"thread{thread_id}")
                store.insert_event(event)
        except Exception as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not any(t.is_alive() for t in threads), "a thread hung"
    assert errors == [], f"concurrent inserts raised: {errors}"
    assert store.count_events() == thread_count * inserts_per_thread
    store.close()


def test_concurrent_reads_and_writes_do_not_corrupt_data(tmp_path):
    store = SQLiteAuditStore(db_path=tmp_path / "concurrent_rw.db")
    stop = threading.Event()
    read_errors: list[Exception] = []

    def writer():
        for i in range(30):
            store.insert_event(_full_event(user=f"writer{i}"))

    def reader():
        while not stop.is_set():
            try:
                store.query_events(limit=10)
                store.count_events()
            except Exception as exc:  # noqa: BLE001
                read_errors.append(exc)

    writer_thread = threading.Thread(target=writer)
    reader_threads = [threading.Thread(target=reader) for _ in range(5)]

    writer_thread.start()
    for r in reader_threads:
        r.start()
    writer_thread.join(timeout=30)
    stop.set()
    for r in reader_threads:
        r.join(timeout=5)

    assert read_errors == [], f"concurrent reads raised: {read_errors}"
    assert store.count_events() == 30
    store.close()
