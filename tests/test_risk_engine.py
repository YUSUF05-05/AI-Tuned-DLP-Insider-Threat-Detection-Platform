import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import build_event, DetectionResult, ObfuscationResult, AIAnalysisResult  # noqa: E402
from scoring.risk_engine import (  # noqa: E402
    compute_risk, classify_severity, load_risk_policy, DEFAULT_POLICY_PATH,
)


def test_policy_loads_and_weights_sum_to_one():
    policy = load_risk_policy()
    assert abs(sum(policy["weights"].values()) - 1.0) < 1e-6


def test_policy_rejects_weights_not_summing_to_one(tmp_path):
    bad_policy = {
        "weights": {"deterministic": 0.5, "ai": 0.5, "context": 0.5, "destination": 0.5},
        "severity_thresholds": {"low": 0, "medium": 25, "high": 50, "critical": 75},
    }
    bad_path = tmp_path / "bad_risk_policy.yaml"
    bad_path.write_text(yaml.dump(bad_policy))
    with pytest.raises(ValueError, match="sum to 1.0"):
        load_risk_policy(bad_path)


# --------------------------------------------------------------------
# Severity boundaries -- exact edges, since off-by-one here silently
# misclassifies real alerts.
# --------------------------------------------------------------------

THRESHOLDS = {"low": 0, "medium": 25, "high": 50, "critical": 75}

@pytest.mark.parametrize("score,expected", [
    (0, "low"), (24, "low"),
    (25, "medium"), (49, "medium"),
    (50, "high"), (74, "high"),
    (75, "critical"), (100, "critical"),
])
def test_severity_boundaries(score, expected):
    assert classify_severity(score, THRESHOLDS) == expected


# --------------------------------------------------------------------
# Component-level behavior via full compute_risk() calls (integration-style,
# matches how this function is actually used in the pipeline)
# --------------------------------------------------------------------

def test_clean_event_scores_low():
    event = build_event(source="file", event_type="file_created", object_ref="notes.txt")
    event.detections = [DetectionResult(detector="card_detector", matched=False)]
    result = compute_risk(event)
    assert result.severity == "low"
    assert result.score < 25
    assert result.components["deterministic"] == 0.0
    assert result.components["ai"] == 0.0


def test_high_confidence_card_over_http_scores_high_or_critical():
    event = build_event(source="http", event_type="http_request", object_ref="/upload")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0)]
    result = compute_risk(event)
    assert result.components["deterministic"] == 1.0
    assert result.components["destination"] == 1.0  # http = 1.0 in the policy
    assert result.severity in ("high", "critical")


def test_multiple_detectors_add_corroboration_bonus_over_single_detector():
    single = build_event(source="file", event_type="file_created", object_ref="x.txt")
    single.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.7)]

    multiple = build_event(source="file", event_type="file_created", object_ref="x.txt")
    multiple.detections = [
        DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.7),
        DetectionResult(detector="keyword_detector", matched=True, category="financial", confidence=0.6),
    ]

    r_single = compute_risk(single)
    r_multiple = compute_risk(multiple)
    assert r_multiple.components["deterministic"] > r_single.components["deterministic"]


def test_obfuscation_layer_detections_count_toward_deterministic_score():
    event = build_event(source="file", event_type="file_created", object_ref="hidden.txt")
    event.detections = []  # nothing matched directly
    event.obfuscation = [
        ObfuscationResult(technique="base64", found=True, layers=1,
                           rescanned_detections=[DetectionResult(detector="card_detector", matched=True,
                                                                  category="payment_card", confidence=1.0)])
    ]
    result = compute_risk(event)
    assert result.components["deterministic"] == 1.0
    assert result.components["context"] > 0.0  # obfuscation bonus applies too


def test_ai_analysis_none_scores_zero_ai_component():
    event = build_event(source="file", event_type="file_created", object_ref="x.txt")
    event.ai_analysis = None
    result = compute_risk(event)
    assert result.components["ai"] == 0.0


def test_ai_analysis_error_status_scores_zero_not_crash():
    event = build_event(source="file", event_type="file_created", object_ref="x.txt")
    event.ai_analysis = AIAnalysisResult(status="error", error="timeout after 45s")
    result = compute_risk(event)
    assert result.components["ai"] == 0.0
    assert "unavailable" in result.explanation[1]


def test_ai_not_sensitive_scores_zero():
    event = build_event(source="file", event_type="file_created", object_ref="x.txt")
    event.ai_analysis = AIAnalysisResult(status="ok", is_sensitive=False, category="none", confidence=0.9)
    result = compute_risk(event)
    assert result.components["ai"] == 0.0


def test_ai_sensitive_contributes_its_confidence():
    event = build_event(source="file", event_type="file_created", object_ref="x.txt")
    event.ai_analysis = AIAnalysisResult(status="ok", is_sensitive=True, category="customer_data", confidence=0.85)
    result = compute_risk(event)
    assert result.components["ai"] == 0.85


def test_destination_scores_ordering_http_gt_clipboard_gt_file():
    def make(source):
        e = build_event(source=source, event_type="x", object_ref="x")
        e.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0)]
        return compute_risk(e)

    r_http = make("http")
    r_clip = make("clipboard")
    r_file = make("file")
    assert r_http.score > r_clip.score > r_file.score


# --------------------------------------------------------------------
# Behavioral adjustment -- the Phase 7/8 dependency resolution itself
# --------------------------------------------------------------------

def test_default_behavioral_adjustment_is_neutral_score_equals_base():
    event = build_event(source="file", event_type="x", object_ref="x")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.9)]
    result = compute_risk(event)  # no behavioral_adjustment passed
    assert result.behavioral_adjustment == 0
    assert result.score == result.base_score


def test_nonzero_behavioral_adjustment_increases_final_score_only():
    event = build_event(source="file", event_type="x", object_ref="x")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.5)]

    base = compute_risk(event, behavioral_adjustment=0)
    adjusted = compute_risk(event, behavioral_adjustment=15)

    assert adjusted.base_score == base.base_score  # base unaffected
    assert adjusted.score == base.base_score + 15
    assert adjusted.behavioral_adjustment == 15


def test_behavioral_adjustment_is_capped_by_policy():
    event = build_event(source="file", event_type="x", object_ref="x")
    result = compute_risk(event, behavioral_adjustment=9999)
    policy = load_risk_policy()
    assert result.behavioral_adjustment == policy["behavioral_adjustment_cap"]


def test_negative_behavioral_adjustment_clamped_to_zero():
    event = build_event(source="file", event_type="x", object_ref="x")
    result = compute_risk(event, behavioral_adjustment=-50)
    assert result.behavioral_adjustment == 0


def test_score_never_exceeds_100_even_with_max_everything():
    event = build_event(source="http", event_type="x", object_ref="x")
    event.detections = [
        DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=1.0),
        DetectionResult(detector="secret_detector", matched=True, category="credential_secret", confidence=1.0),
        DetectionResult(detector="keyword_detector", matched=True, category="financial", confidence=1.0),
    ]
    event.ai_analysis = AIAnalysisResult(status="ok", is_sensitive=True, category="payment_card", confidence=1.0)
    event.obfuscation = [ObfuscationResult(technique="base64", found=True, layers=1,
                                            rescanned_detections=[DetectionResult(detector="card_detector", matched=True, confidence=1.0)])]
    result = compute_risk(event, behavioral_adjustment=9999)
    assert result.score <= 100


def test_explanation_is_human_readable_and_nonempty():
    event = build_event(source="http", event_type="x", object_ref="x")
    event.detections = [DetectionResult(detector="card_detector", matched=True, category="payment_card", confidence=0.9)]
    result = compute_risk(event)
    assert len(result.explanation) >= 4
    assert any("final_score" in line for line in result.explanation)
