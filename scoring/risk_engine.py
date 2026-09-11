"""
scoring/risk_engine.py  (Phase 7)

Combines four signals available on a fully-enriched DLPEvent (after Phases
3-6 have all run) into a single explainable 0-100 risk score and severity
classification:

    deterministic  -- Phase 4/5 pattern-match confidence (event.detections, event.obfuscation)
    ai             -- Phase 6 local-LLM judgment (event.ai_analysis)
    context        -- circumstances around the finding (was it obfuscated to evade detection)
    destination    -- how close the observed activity is to data actually leaving (event.source)

ONE SCORING FUNCTION, TWO CALLERS (avoids the Phase 7/8 circular dependency):
Phase 7 runs before Phase 8 exists for a given event -- there is no
behavioral context yet at that point in the pipeline. compute_risk() takes
`behavioral_adjustment` as a parameter defaulting to 0 (neutral) specifically
so it can be called once with no behavioral input (producing base_score) and,
after Phase 8 has correlated the event against recent history, called AGAIN
with the real adjustment to produce the final score. The scoring logic
itself is never duplicated between the two phases -- Phase 8 computes an
adjustment value and hands it back to this same function.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DLPEvent, RiskAssessment

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "risk_policy.yaml"

REQUIRED_COMPONENTS = ("deterministic", "ai", "context", "destination")


def load_risk_policy(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    weights = policy.get("weights", {})
    missing = [c for c in REQUIRED_COMPONENTS if c not in weights]
    if missing:
        raise ValueError(f"risk_policy.yaml weights missing component(s): {missing}")
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"risk_policy.yaml weights must sum to 1.0, got {total}")

    return policy


def classify_severity(score: int, thresholds: dict[str, int]) -> str:
    """score is inclusive-lower-bound bucketed: >= critical -> critical, etc."""
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def _deterministic_component(event: DLPEvent, policy: dict[str, Any]) -> tuple[float, str]:
    """
    Highest confidence among every matched detector -- across BOTH direct
    detections and Phase 5's obfuscation-layer rescanned detections, since a
    hit found only after decoding is exactly as real as one found directly.
    A small, capped bonus is added when multiple distinct detectors agree.
    """
    matched_confidences: list[float] = []
    matched_detector_names: set[str] = set()

    for d in event.detections:
        if d.matched:
            matched_confidences.append(d.confidence)
            matched_detector_names.add(d.detector)
    for ob in event.obfuscation:
        for d in ob.rescanned_detections:
            if d.matched:
                matched_confidences.append(d.confidence)
                matched_detector_names.add(d.detector)

    if not matched_confidences:
        return 0.0, "deterministic: no detector matched"

    base = max(matched_confidences)
    cfg = policy.get("deterministic", {})
    per_extra = cfg.get("corroboration_bonus_per_extra_detector", 0.0)
    cap = cfg.get("corroboration_bonus_cap", 0.0)
    extra_detectors = max(0, len(matched_detector_names) - 1)
    bonus = min(cap, extra_detectors * per_extra)
    score = min(1.0, base + bonus)

    note = f"deterministic: max confidence {base:.2f} from {len(matched_detector_names)} detector(s)"
    if bonus > 0:
        note += f" (+{bonus:.2f} corroboration bonus)"
    return score, note


def _ai_component(event: DLPEvent) -> tuple[float, str]:
    if event.ai_analysis is None:
        return 0.0, "ai: not performed (content did not meet needs_ai_review threshold)"
    if event.ai_analysis.status == "error":
        return 0.0, f"ai: unavailable ({event.ai_analysis.error}) -- scored as 0, deterministic signal stands alone"
    if not event.ai_analysis.is_sensitive:
        return 0.0, "ai: assessed as not sensitive"
    return event.ai_analysis.confidence, f"ai: assessed sensitive at {event.ai_analysis.confidence:.2f} confidence ({event.ai_analysis.category})"


def _context_component(event: DLPEvent, policy: dict[str, Any]) -> tuple[float, str]:
    obfuscation_found = any(d.matched for ob in event.obfuscation for d in ob.rescanned_detections)
    if not obfuscation_found:
        return 0.0, "context: no evasion technique detected"
    bonus = policy.get("context", {}).get("obfuscation_bonus", 0.0)
    techniques = sorted({ob.technique for ob in event.obfuscation if any(d.matched for d in ob.rescanned_detections)})
    return bonus, f"context: content was obfuscated ({', '.join(techniques)}) to reach a detector -- evasion is itself a signal"


def _destination_component(event: DLPEvent, policy: dict[str, Any]) -> tuple[float, str]:
    scores = policy.get("destination_scores", {})
    score = scores.get(event.source, 0.5)
    return score, f"destination: source='{event.source}' scores {score:.2f}"


def compute_risk(
    event: DLPEvent,
    behavioral_adjustment: int = 0,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
) -> RiskAssessment:
    """
    Score a fully-enriched DLPEvent. Called with behavioral_adjustment=0 by
    Phase 7 alone (base_score); called again with a real value once Phase 8
    has computed one (final score). Safe to call repeatedly -- pure function,
    no side effects.
    """
    policy = load_risk_policy(policy_path)
    weights = policy["weights"]

    det_score, det_note = _deterministic_component(event, policy)
    ai_score, ai_note = _ai_component(event)
    ctx_score, ctx_note = _context_component(event, policy)
    dest_score, dest_note = _destination_component(event, policy)

    components = {"deterministic": det_score, "ai": ai_score, "context": ctx_score, "destination": dest_score}
    weighted_contributions = {name: round(components[name] * weights[name] * 100, 2) for name in components}

    base_score = round(sum(weighted_contributions.values()))
    behavioral_adjustment = max(0, min(behavioral_adjustment, policy.get("behavioral_adjustment_cap", 0)))
    final_score = max(0, min(100, base_score + behavioral_adjustment))

    severity = classify_severity(final_score, policy["severity_thresholds"])

    explanation = [det_note, ai_note, ctx_note, dest_note]
    if behavioral_adjustment:
        explanation.append(f"behavioral: +{behavioral_adjustment} points from Phase 8 correlation")
    explanation.append(f"base_score={base_score}, behavioral_adjustment={behavioral_adjustment}, final_score={final_score} -> {severity.upper()}")

    return RiskAssessment(
        score=final_score,
        base_score=base_score,
        severity=severity,
        behavioral_adjustment=behavioral_adjustment,
        components=components,
        weighted_contributions=weighted_contributions,
        explanation=explanation,
    )