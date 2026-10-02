"""
tests/test_dashboard_api.py

New tests for the Phase 10 dashboard's read-only JSON API
(dashboard/api.py), using Flask's test_client against a temp SQLite audit
trail populated via the real SQLiteAuditStore (read_only=False) so these
tests exercise the exact schema/queries the live dashboard uses.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event, DetectionResult, RiskAssessment
from correlation.behavior_tracker import BehavioralContext
from database.sqlite_audit import SQLiteAuditStore
from dashboard.api import create_dashboard_app


def _flagged_event(severity, score, source="clipboard"):
    event = build_event(source=source, event_type=f"{source}_event", object_ref="ref", size_bytes=1,
                         content_excerpt="card 4111111111111111")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0)]
    event.risk_assessment = RiskAssessment(score=score, base_score=score, severity=severity)
    return event


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "audit_trail.db"
    writer = SQLiteAuditStore(db_path=db_path)
    writer.insert_event(_flagged_event("critical", 90), behavior=BehavioralContext(
        adjustment=10, event_count_in_window=3, escalating=True,
        repeated_categories=["payment_card"], explanation=["repeated activity: 3 -> +10"]))
    writer.insert_event(_flagged_event("medium", 40, source="http"))
    writer.insert_event(_flagged_event("low", 10, source="file"))
    writer.close()

    app = create_dashboard_app(db_path=db_path)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_index_serves_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"<html" in resp.data.lower()


def test_summary_counts(client):
    resp = client.get("/api/summary")
    data = resp.get_json()
    assert data["total_events"] == 3
    assert data["critical_events"] == 1
    assert data["flagged_events"] == 2  # critical + medium; low excluded, see docs/DATABASE.md
    assert data["severity_counts"]["critical"] == 1
    assert data["severity_counts"]["low"] == 1


def test_integrity_endpoint(client):
    resp = client.get("/api/integrity")
    data = resp.get_json()
    assert data["healthy"] is True
    assert data["missing_triggers"] == []


def test_list_events_default(client):
    resp = client.get("/api/events")
    data = resp.get_json()
    assert data["count"] == 3
    # any_match/needs_ai_review/behavioral_escalating shaped to real booleans
    first = data["events"][0]
    assert isinstance(first["any_match"], bool)


def test_list_events_filtered_by_severity(client):
    resp = client.get("/api/events?severity=critical")
    data = resp.get_json()
    assert data["count"] == 1
    assert data["events"][0]["risk_severity"] == "critical"


def test_list_events_filtered_by_source(client):
    resp = client.get("/api/events?source=http")
    data = resp.get_json()
    assert data["count"] == 1
    assert data["events"][0]["source"] == "http"


def test_list_events_rejects_invalid_severity(client):
    resp = client.get("/api/events?severity=nonsense")
    assert resp.status_code == 400


def test_event_detail(client):
    listing = client.get("/api/events?severity=critical").get_json()
    event_id = listing["events"][0]["event_id"]
    resp = client.get("/api/events/" + event_id)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["behavioral_escalating"] == 1
    assert data["behavioral_repeated_categories"] == ["payment_card"]
    assert len(data["detections"]) == 1


def test_event_detail_not_found(client):
    resp = client.get("/api/events/does-not-exist")
    assert resp.status_code == 404
