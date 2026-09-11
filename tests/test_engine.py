import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event  # noqa: E402
from detectors.engine import run_all, needs_ai_review, enrich_event, summarize, AI_REVIEW_CONFIDENCE_THRESHOLD  # noqa: E402

VALID_VISA = "4111111111111111"


def test_run_all_returns_one_result_per_detector_without_filename():
    results = run_all("ordinary text with no sensitive data")
    detector_names = {r.detector for r in results}
    assert detector_names == {"card_detector", "swift_detector", "secret_detector", "keyword_detector"}


def test_run_all_includes_filetype_when_filename_given():
    results = run_all("text", filename="secret.pem", content_bytes=b"-----BEGIN RSA PRIVATE KEY-----")
    detector_names = {r.detector for r in results}
    assert "filetype_detector" in detector_names


def test_needs_ai_review_true_for_high_confidence_card_match():
    results = run_all(f"Card on file: {VALID_VISA}")
    assert needs_ai_review(results) is True


def test_needs_ai_review_false_for_clean_text():
    results = run_all("Team lunch is scheduled for noon on Friday.")
    assert needs_ai_review(results) is False


def test_enrich_event_attaches_detections_to_event():
    event = build_event(source="file", event_type="file_created", object_ref="C:/dlp-lab/monitored/notes.txt")
    enrich_event(event, f"contains card {VALID_VISA}")
    assert len(event.detections) > 0
    assert event.any_match is True


def test_summarize_reports_matched_detectors_and_categories():
    results = run_all(f"Wire the funds to card {VALID_VISA} and note the customer database export.")
    summary = summarize(results)
    assert summary["any_match"] is True
    assert "card_detector" in summary["matched_detectors"]
    assert "keyword_detector" in summary["matched_detectors"]
    assert summary["max_confidence"] >= AI_REVIEW_CONFIDENCE_THRESHOLD
    assert summary["needs_ai_review"] is True


def test_summarize_clean_text_reports_no_match():
    results = run_all("The office plants need watering.")
    summary = summarize(results)
    assert summary["any_match"] is False
    assert summary["matched_detectors"] == []
    assert summary["needs_ai_review"] is False
