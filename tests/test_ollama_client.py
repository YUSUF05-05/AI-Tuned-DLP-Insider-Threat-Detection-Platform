import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import DetectionResult  # noqa: E402
from ai.ollama_client import analyze, DEFAULT_MODEL  # noqa: E402


class FakeResponse:
    """Stand-in for requests.Response -- only what ollama_client.py touches."""

    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body")
        return self._json_data


# The exact, verbatim envelope the live curl call against llama3.2:latest produced.
REAL_ENVELOPE = {
    "model": "llama3.2:latest",
    "created_at": "2026-09-04T18:45:44.0332843Z",
    "message": {
        "role": "assistant",
        "content": (
            '{\n  "is_sensitive": false,\n  "category": "payment_card",\n  "confidence": 0.8,\n'
            '  "reasoning": "The note contains a string of digits, which is a common format for a '
            'credit card number. The length of the number (16 digits) is also consistent with a '
            'standard credit card number. However, without more context or information, it is not '
            'possible to confirm with certainty that the note is a valid credit card number."\n}'
        ),
    },
    "done": True, "done_reason": "stop",
    "total_duration": 11002378400, "load_duration": 9289414200,
    "prompt_eval_count": 40, "prompt_eval_cached_count": 0,
    "prompt_eval_duration": 430664000, "eval_count": 98, "eval_duration": 1275982000,
}


def test_successful_call_returns_validated_ok_result():
    def fake_post(url, json, timeout):
        return FakeResponse(200, REAL_ENVELOPE)

    result = analyze("card on file 4111111111111111", [], post_fn=fake_post)
    assert result.status == "ok"
    # This is the exact real response, which response_validator corrects --
    # proving analyze() actually routes through validate(), not just parses.
    assert result.is_sensitive is True
    assert result.confidence == 0.6
    assert result.model == "llama3.2:latest"
    assert result.duration_ms == 11002  # 11002378400 ns -> ms


def test_connection_error_returns_safe_fallback_not_raise():
    def fake_post(url, json, timeout):
        raise requests.exceptions.ConnectionError("refused")

    result = analyze("some content", [], post_fn=fake_post)
    assert result.status == "error"
    assert "could not connect" in result.error
    assert "ollama serve" in result.error


def test_timeout_returns_safe_fallback_with_configured_duration():
    def fake_post(url, json, timeout):
        raise requests.exceptions.Timeout()

    result = analyze("some content", [], timeout_seconds=30, post_fn=fake_post)
    assert result.status == "error"
    assert "timed out after 30" in result.error


def test_model_not_found_404_gives_actionable_error():
    def fake_post(url, json, timeout):
        return FakeResponse(404, text="model not found")

    result = analyze("x", [], model="nonexistent:model", post_fn=fake_post)
    assert result.status == "error"
    assert "not found" in result.error
    assert "ollama pull nonexistent:model" in result.error


def test_non_200_status_reported_with_body_excerpt():
    def fake_post(url, json, timeout):
        return FakeResponse(500, text="internal server error detail")

    result = analyze("x", [], post_fn=fake_post)
    assert result.status == "error"
    assert "500" in result.error
    assert "internal server error detail" in result.error


def test_invalid_json_envelope_handled_safely():
    def fake_post(url, json, timeout):
        return FakeResponse(200, json_data=None)  # .json() raises ValueError

    result = analyze("x", [], post_fn=fake_post)
    assert result.status == "error"
    assert "not valid JSON" in result.error


def test_missing_message_content_handled_safely():
    def fake_post(url, json, timeout):
        return FakeResponse(200, json_data={"model": "x", "message": {}})

    result = analyze("x", [], post_fn=fake_post)
    assert result.status == "error"
    assert "missing message.content" in result.error


def test_empty_content_short_circuits_without_network_call():
    calls = []

    def fake_post(url, json, timeout):
        calls.append(1)
        return FakeResponse(200, REAL_ENVELOPE)

    result = analyze("   ", [], post_fn=fake_post)
    assert result.status == "error"
    assert "empty content" in result.error
    assert calls == [], "must not make a network call for empty content"


def test_generic_request_exception_handled_safely():
    def fake_post(url, json, timeout):
        raise requests.exceptions.RequestException("dns failure")

    result = analyze("x", [], post_fn=fake_post)
    assert result.status == "error"
    assert "dns failure" in result.error


def test_deterministic_detections_passed_through_to_prompt():
    captured = {}

    def fake_post(url, json, timeout):
        captured["payload"] = json
        return FakeResponse(200, REAL_ENVELOPE)

    detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0)]
    analyze("card content", detections, post_fn=fake_post)
    user_msg = captured["payload"]["messages"][1]["content"]
    assert "card_detector" in user_msg
    assert "payment_card" in user_msg
