"""
detectors/engine.py  (Phase 4 aggregator)

Runs every deterministic detector (card, SWIFT, secret, keyword, filetype)
against a piece of content and attaches the results to a DLPEvent.

This module is the seam where Phase 6 (AI/LLM analysis) will plug in later:
`run_all()` returns the deterministic verdicts; Phase 6 will take content
that scores above a "needs AI review" threshold (defined here, reused there)
and send ONLY that subset to the local LLM, rather than sending everything —
which is both a cost/latency optimization and a data-minimization choice
(least content leaves the deterministic layer necessary).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from common.event_schema import DetectionResult, DLPEvent
from detectors import card_detector, swift_detector, secret_detector, filetype_detector
from detectors.keyword_detector import KeywordDetector

# Any single deterministic detector at or above this confidence is enough to
# mark content as "needs AI review" once Phase 6 exists. Defined here so
# Phase 6/7 import ONE constant instead of redefining the threshold.
AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5

_keyword_detector_singleton: Optional[KeywordDetector] = None


def _get_keyword_detector() -> KeywordDetector:
    global _keyword_detector_singleton
    if _keyword_detector_singleton is None:
        _keyword_detector_singleton = KeywordDetector()
    return _keyword_detector_singleton


def run_all(
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> list[DetectionResult]:
    """
    Run every applicable deterministic detector against `text`
    (and `content_bytes`/`filename` for the filetype detector, which needs
    the raw bytes and name rather than decoded text).
    """
    results: list[DetectionResult] = [
        card_detector.detect(text),
        swift_detector.detect(text),
        secret_detector.detect(text),
        _get_keyword_detector().detect(text),
    ]
    if filename is not None:
        results.append(filetype_detector.detect(filename, content_bytes=content_bytes))
    return results


def needs_ai_review(results: list[DetectionResult]) -> bool:
    """True if any deterministic detector's confidence meets the AI-review bar."""
    return any(r.matched and r.confidence >= AI_REVIEW_CONFIDENCE_THRESHOLD for r in results)


def enrich_event(
    event: DLPEvent,
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> DLPEvent:
    """Run all detectors and attach their results to the given event in place."""
    event.detections = run_all(text, filename=filename, content_bytes=content_bytes)
    return event


def summarize(results: list[DetectionResult]) -> dict:
    """Compact summary used by logging/CLI output and, later, the dashboard."""
    matched = [r for r in results if r.matched]
    return {
        "any_match": len(matched) > 0,
        "matched_detectors": [r.detector for r in matched],
        "categories": sorted({r.category for r in matched if r.category}),
        "max_confidence": max((r.confidence for r in matched), default=0.0),
        "needs_ai_review": needs_ai_review(results),
    }
