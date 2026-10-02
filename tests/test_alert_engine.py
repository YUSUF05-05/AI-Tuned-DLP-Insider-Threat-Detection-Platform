"""
tests/test_alert_engine.py

New tests for the Phase 10 alert engine (alerts/alert_engine.py,
alerts/channels.py): threshold-based triggering, dispatch to every enabled
channel, and confirmation that webhook/email stay disabled and inert by
default (per config/alert_policy.yaml).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event, DetectionResult, RiskAssessment
from alerts.alert_engine import AlertEngine, _meets_threshold
from alerts.channels import ConsoleChannel, LogFileChannel, WebhookChannel, EmailChannel, AlertPayload


def _scored_event(severity: str, score: int = 50):
    event = build_event(source="clipboard", event_type="clipboard_change", object_ref="clipboard", size_bytes=5,
                         content_excerpt="card 4111111111111111")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0)]
    event.risk_assessment = RiskAssessment(score=score, base_score=score, severity=severity)
    return event


@pytest.fixture
def policy_path(tmp_path):
    path = tmp_path / "alert_policy.yaml"
    path.write_text(yaml.safe_dump({
        "trigger_severity_threshold": "medium",
        "channels": {
            "console": {"enabled": True},
            "log_file": {"enabled": True, "path": str(tmp_path / "alerts.log")},
            "webhook": {"enabled": False, "url": ""},
            "email": {"enabled": False, "smtp_host": "", "to_addresses": []},
        },
    }))
    return path


def test_meets_threshold_ordering():
    assert _meets_threshold("critical", "medium") is True
    assert _meets_threshold("medium", "medium") is True
    assert _meets_threshold("low", "medium") is False
    assert _meets_threshold("bogus", "medium") is False  # unrecognized severity never crashes, never over-alerts


def test_engine_does_not_alert_below_threshold(policy_path):
    engine = AlertEngine(policy_path=policy_path)
    results = engine.process(_scored_event("low", score=10))
    assert results == []


def test_engine_alerts_at_and_above_threshold(policy_path, capsys):
    engine = AlertEngine(policy_path=policy_path)
    results = engine.process(_scored_event("critical", score=90))
    assert len(results) == 2  # console + log_file enabled
    assert all(r.delivered for r in results)
    captured = capsys.readouterr()
    assert "CRITICAL" in captured.out


def test_engine_writes_log_file_channel(policy_path, tmp_path):
    engine = AlertEngine(policy_path=policy_path)
    event = _scored_event("high", score=65)
    engine.process(event)
    log_path = tmp_path / "alerts.log"
    assert log_path.exists()
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["event_id"] == event.event_id
    assert payload["severity"] == "high"


def test_disabled_channels_are_not_constructed(policy_path):
    engine = AlertEngine(policy_path=policy_path)
    channel_names = {c.name for c in engine.channels}
    assert channel_names == {"console", "log_file"}
    assert "webhook" not in channel_names
    assert "email" not in channel_names


def test_no_event_without_risk_assessment_never_alerts(policy_path):
    engine = AlertEngine(policy_path=policy_path)
    event = build_event(source="file", event_type="file_created", object_ref="/tmp/x", size_bytes=1)
    assert engine.should_alert(event) is False
    assert engine.process(event) == []


def test_console_channel_direct():
    channel = ConsoleChannel()
    payload = AlertPayload(event_id="e1", timestamp="t", user="u", host="h", source="file",
                            object_ref="/x", severity="critical", score=90, categories=["payment_card"])
    result = channel.send(payload)
    assert result.delivered is True
    assert result.channel == "console"


def test_log_file_channel_direct(tmp_path):
    channel = LogFileChannel(path=tmp_path / "out.log")
    payload = AlertPayload(event_id="e1", timestamp="t", user="u", host="h", source="file",
                            object_ref="/x", severity="high", score=60, categories=[])
    result = channel.send(payload)
    assert result.delivered is True
    assert (tmp_path / "out.log").exists()


def test_webhook_channel_without_url_is_inert():
    channel = WebhookChannel(url="")
    payload = AlertPayload(event_id="e1", timestamp="t", user="u", host="h", source="http",
                            object_ref="/upload", severity="critical", score=90, categories=[])
    result = channel.send(payload)
    assert result.delivered is False
    assert "no url" in (result.detail or "")


def test_email_channel_without_smtp_is_inert():
    channel = EmailChannel(smtp_host="", smtp_port=587, use_tls=True, from_address="", to_addresses=[])
    payload = AlertPayload(event_id="e1", timestamp="t", user="u", host="h", source="http",
                            object_ref="/upload", severity="critical", score=90, categories=[])
    result = channel.send(payload)
    assert result.delivered is False
