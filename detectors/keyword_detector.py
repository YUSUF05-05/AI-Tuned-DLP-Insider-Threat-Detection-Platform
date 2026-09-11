"""
detectors/keyword_detector.py  (Phase 4.4)

Configurable, policy-driven keyword/category detector. Keyword lists live in
config/detection_policy.yaml (not hardcoded) so a security reviewer can tune
detection without touching code — this matters for a DLP tool specifically,
since keyword policy is expected to change per-organization in the real
world; hardcoding it would misrepresent how these tools are actually operated.

Matching rules:
  - Case-insensitive.
  - Whole-phrase matching with word boundaries, so "ssn" does not match
    inside an unrelated word like "assignment".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"


def load_policy(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _compile_category_patterns(categories: dict[str, Any]) -> dict[str, list[re.Pattern]]:
    compiled: dict[str, list[re.Pattern]] = {}
    for category, spec in categories.items():
        patterns = []
        for phrase in spec.get("keywords", []):
            # Escape the phrase, then allow flexible whitespace between words
            # (so "social security number" also matches "social  security number").
            escaped_words = [re.escape(w) for w in phrase.split()]
            pattern = r"\b" + r"\s+".join(escaped_words) + r"\b"
            compiled.setdefault(category, []).append(re.compile(pattern, re.IGNORECASE))
        compiled.setdefault(category, compiled.get(category, []))
    return compiled


class KeywordDetector:
    """
    Stateful wrapper so the YAML policy is parsed once (at construction) and
    reused across many detect() calls instead of re-reading/re-compiling
    regex on every event, which matters once this runs continuously against
    a live file/clipboard stream in Phase 3.
    """

    def __init__(self, policy_path: str | Path = DEFAULT_POLICY_PATH, exclude_categories: tuple[str, ...] = ("credentials_context",)):
        policy = load_policy(policy_path)
        categories = dict(policy.get("keyword_categories", {}))
        # credentials_context is intentionally excluded from standalone matching:
        # per the policy file's own description, it exists to raise confidence in
        # secret_detector matches, not to fire independently (it would otherwise
        # flag the word "password" appearing in ordinary IT documentation).
        for excluded in exclude_categories:
            categories.pop(excluded, None)
        self.categories = categories
        self._compiled = _compile_category_patterns(categories)

    def detect(self, text: str) -> DetectionResult:
        hits_by_category: dict[str, list[str]] = {}
        for category, patterns in self._compiled.items():
            for pattern in patterns:
                m = pattern.search(text)
                if m:
                    hits_by_category.setdefault(category, []).append(m.group(0).lower())

        matched = len(hits_by_category) > 0
        evidence = [f"{cat}:{phrase}" for cat, phrases in hits_by_category.items() for phrase in phrases]
        return DetectionResult(
            detector="keyword_detector",
            matched=matched,
            category=",".join(sorted(hits_by_category.keys())) if matched else None,
            confidence=0.6 if matched else 0.0,  # keywords alone are moderate-confidence, corroborating evidence
            matches=evidence,
            details={"categories_matched": sorted(hits_by_category.keys())},
        )
