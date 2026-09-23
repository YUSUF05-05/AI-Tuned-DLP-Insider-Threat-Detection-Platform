"""
tests/test_pipeline_integration.py

Exercises analyze_event() from run_pipeline_demo.py -- the actual function
the live collectors call -- proving Phases 6, 7, and 8 work TOGETHER, not
just each in isolation. The AI call is mocked (no real Ollama needed to run
this in CI or this sandbox); the deterministic, scoring, and correlation
layers are all real code, not mocked.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event, AIAnalysisResult, JsonlEventLogger  # noqa: E402
from database.sqlite_audit import SQLiteAuditStore  # noqa: E402
import run_pipeline_demo  # noqa: E402


def _fake_ai_sensitive(*args, **kwargs):
    return AIAnalysisResult(status="ok", is_sensitive=True, category="payment_card", confidence=0.9, model="fake", duration_ms=100)


def test_full_chain_clean_event_gets_no_risk_assessment(tmp_path):
    event = build_event(source="file", event_type="file_created", object_ref="lunch_menu.txt",
                         content_excerpt="Team lunch is at noon on Friday.")
    run_pipeline_demo.analyze_event(event, flagged_log_path=tmp_path / "flagged.jsonl", use_ai=False)
    assert event.any_match is False
    assert event.risk_assessment is None  # analyze_event returns early for clean events
    assert event.ai_analysis is None


def test_full_chain_sensitive_event_gets_full_treatment(tmp_path):
    event = build_event(source="http", event_type="http_request", object_ref="/upload",
                         content_excerpt="card on file 4111111111111111")
    with patch("run_pipeline_demo.ollama_analyze", side_effect=_fake_ai_sensitive):
        run_pipeline_demo.analyze_event(event, flagged_log_path=tmp_path / "flagged.jsonl", use_ai=True)

    assert event.any_match is True
    assert event.ai_analysis is not None
    assert event.ai_analysis.status == "ok"
    assert event.risk_assessment is not None
    assert event.risk_assessment.score > 0
    assert event.risk_assessment.behavioral_adjustment == 0  # first event for this user, no history yet


def test_no_ai_flag_skips_phase_6_but_still_scores():
    event = build_event(source="file", event_type="file_created", object_ref="secret.pem",
                         content_excerpt="-----BEGIN RSA PRIVATE KEY-----\nfakekeymaterial")
    run_pipeline_demo.analyze_event(event, flagged_log_path=Path("/tmp/nonexistent_flagged.jsonl"), use_ai=False)
    assert event.ai_analysis is None
    assert event.risk_assessment is not None  # Phase 7 still runs on deterministic signal alone
    assert event.risk_assessment.components["ai"] == 0.0


def test_repeated_activity_across_real_events_raises_later_scores(tmp_path):
    """
    The actual proof Phase 8 is wired in: process four sensitive events for
    the SAME user through the real pipeline function, writing each to the
    flagged log exactly like the live collectors do, and confirm a later
    event scores higher than the first purely because of accumulated
    behavioral history -- nothing about the CONTENT changes between them.
    """
    flagged_log = tmp_path / "flagged.jsonl"
    from common.event_schema import JsonlEventLogger
    flagged_logger = JsonlEventLogger(flagged_log)

    scores = []
    for i in range(4):
        event = build_event(source="http", event_type="http_request", object_ref="/upload",
                             content_excerpt="card on file 4111111111111111")
        event.user = "alice_test_user"  # force same identity across all four
        with patch("run_pipeline_demo.ollama_analyze", side_effect=_fake_ai_sensitive):
            run_pipeline_demo.analyze_event(event, flagged_log_path=flagged_log, use_ai=True)
        flagged_logger.write(event)
        scores.append(event.risk_assessment.score)

    assert scores[0] < scores[-1], f"expected rising scores from behavioral correlation, got {scores}"
    assert scores[-1] - scores[0] >= 5  # at minimum, the 2-event repeated-activity tier should have kicked in


def test_full_chain_sensitive_event_persists_to_sqlite(tmp_path):
    """
    The Phase 9 proof: run a real sensitive event through the actual
    analyze_event() with a real SQLiteAuditStore attached, and confirm what
    landed in the database matches what's on the event object -- not a
    mock, a real .db file on disk.
    """
    db = SQLiteAuditStore(db_path=tmp_path / "phase9_integration.db")
    event = build_event(source="http", event_type="http_request", object_ref="/upload",
                         content_excerpt="card on file 4111111111111111")
    with patch("run_pipeline_demo.ollama_analyze", side_effect=_fake_ai_sensitive):
        run_pipeline_demo.analyze_event(event, flagged_log_path=tmp_path / "flagged.jsonl", use_ai=True, db=db)

    row = db.get_event(event.event_id)
    assert row is not None
    assert row["risk_score"] == event.risk_assessment.score
    assert row["risk_severity"] == event.risk_assessment.severity
    assert row["ai_category"] == "payment_card"
    assert len(row["detections"]) >= 1
    db.close()


def test_clean_event_is_not_persisted_to_sqlite(tmp_path):
    db = SQLiteAuditStore(db_path=tmp_path / "phase9_clean.db")
    event = build_event(source="file", event_type="file_created", object_ref="lunch.txt",
                         content_excerpt="Team lunch at noon.")
    run_pipeline_demo.analyze_event(event, flagged_log_path=tmp_path / "flagged.jsonl", use_ai=False, db=db)

    assert db.get_event(event.event_id) is None
    assert db.count_events() == 0
    db.close()


def test_db_none_skips_persistence_without_error():
    event = build_event(source="http", event_type="http_request", object_ref="/upload",
                         content_excerpt="card on file 4111111111111111")
    with patch("run_pipeline_demo.ollama_analyze", side_effect=_fake_ai_sensitive):
        # db=None (the --no-db path) must not raise
        run_pipeline_demo.analyze_event(event, flagged_log_path=Path("/tmp/no_such.jsonl"), use_ai=True, db=None)
    assert event.risk_assessment is not None  # scoring still ran; only persistence was skipped


def test_db_failure_is_logged_not_raised(tmp_path, caplog):
    """
    Safe-fallback proof: if insert_event() raises for any reason, the
    pipeline must keep running, matching Phase 6's AI-failure philosophy.
    """
    db = SQLiteAuditStore(db_path=tmp_path / "phase9_fail.db")
    event = build_event(source="http", event_type="http_request", object_ref="/upload",
                         content_excerpt="card on file 4111111111111111")

    with patch.object(db, "insert_event", side_effect=RuntimeError("simulated disk failure")):
        with patch("run_pipeline_demo.ollama_analyze", side_effect=_fake_ai_sensitive):
            # must not raise despite insert_event failing internally
            run_pipeline_demo.analyze_event(event, flagged_log_path=tmp_path / "flagged.jsonl", use_ai=True, db=db)

    assert event.risk_assessment is not None  # the rest of the pipeline completed normally
    db.close()
