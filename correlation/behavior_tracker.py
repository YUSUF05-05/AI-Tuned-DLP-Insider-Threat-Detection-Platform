"""
correlation/behavior_tracker.py  (Phase 8)

Builds a per-user behavioral adjustment by correlating a user's recent
FLAGGED events (any_match=True) within a rolling time window, then hands
that adjustment back to scoring.risk_engine.compute_risk() -- see that
module's docstring for the "one scoring function, two callers" design this
resolves the Phase 7/8 ordering with.

NO DATABASE DEPENDENCY (Phase 9 does not exist yet): this reads directly
from the JSONL event log Phase 3's collectors already write to
(logs/flagged_events.jsonl by default), via the existing
common.event_schema.JsonlEventLogger.read_all(). When Phase 9 lands, this
module's data-access layer can be swapped for a SQL query without touching
the correlation LOGIC below it -- that boundary is exactly why
load_recent_flagged_events() is a separate, small function.

WHAT COUNTS AS A "USER": DLPEvent.user, the OS username every collector
already populates via common.event_schema.current_user(). No new identity
concept is introduced.

THREE SIGNALS, EACH INDEPENDENTLY EXPLAINABLE:
  1. Repeated activity  -- how many flagged events this user produced in the window
  2. Escalation          -- is the average severity of those events trending up
                             (second half of the window scoring higher than the first)
  3. Repeated category   -- is the same category (e.g. payment_card) recurring,
                             suggesting targeted rather than incidental activity
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from common.event_schema import JsonlEventLogger

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "risk_policy.yaml"
DEFAULT_LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "flagged_events.jsonl"


@dataclass
class BehavioralContext:
    """Everything correlate() computed, for logging/debugging -- risk_engine
    only ever consumes `.adjustment`, but this keeps the full reasoning
    available rather than throwing it away after producing one integer."""
    adjustment: int
    event_count_in_window: int
    escalating: bool
    repeated_categories: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)


def _load_policy(policy_path: str | Path) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        full_policy = yaml.safe_load(f)
    return full_policy.get("behavioral_correlation", {})


def load_recent_flagged_events(
    user: str,
    current_time: datetime,
    log_path: str | Path = DEFAULT_LOG_PATH,
    window_hours: float = 24,
) -> list[dict[str, Any]]:
    """
    Read the JSONL flagged-event log and return this user's events whose
    timestamp falls within [current_time - window_hours, current_time).
    Malformed/unparseable timestamps are skipped, not fatal -- a single bad
    log line must never break correlation for every event after it.
    """
    logger = JsonlEventLogger(log_path)
    all_events = logger.read_all()
    window_start = current_time - timedelta(hours=window_hours)

    matches = []
    for ev in all_events:
        if ev.get("user") != user:
            continue
        ts_raw = ev.get("timestamp")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except (TypeError, ValueError):
            continue
        if window_start <= ts < current_time:
            matches.append(ev)
    return matches


def _extract_categories(event: dict[str, Any]) -> set[str]:
    categories = set()
    for d in event.get("detections", []):
        if d.get("matched") and d.get("category"):
            categories.add(d["category"])
    ai = event.get("ai_analysis")
    if ai and ai.get("status") == "ok" and ai.get("is_sensitive") and ai.get("category"):
        categories.add(ai["category"])
    return categories


def _extract_base_score(event: dict[str, Any]) -> int | None:
    risk = event.get("risk_assessment")
    if risk and "base_score" in risk:
        return risk["base_score"]
    return None


def _repeated_activity_bonus(count: int, policy: dict[str, Any]) -> tuple[int, str]:
    thresholds = sorted(policy.get("repeated_activity_thresholds", []), key=lambda t: -t["min_count"])
    for tier in thresholds:
        if count >= tier["min_count"]:
            return tier["bonus"], f"repeated activity: {count} flagged event(s) in window (>= {tier['min_count']}) -> +{tier['bonus']}"
    return 0, f"repeated activity: {count} flagged event(s) in window, below any threshold"


def _escalation_bonus(events: list[dict[str, Any]], policy: dict[str, Any]) -> tuple[int, bool, str]:
    scores = [(_extract_base_score(e), e.get("timestamp")) for e in events]
    scores = [(s, t) for s, t in scores if s is not None and t is not None]
    if len(scores) < 4:  # need enough points for a first-half/second-half comparison to mean anything
        return 0, False, "escalation: not enough scored events in window to assess a trend"

    scores.sort(key=lambda pair: pair[1])  # chronological
    mid = len(scores) // 2
    first_half = [s for s, _ in scores[:mid]]
    second_half = [s for s, _ in scores[mid:]]
    avg_first = sum(first_half) / len(first_half)
    avg_second = sum(second_half) / len(second_half)
    delta = avg_second - avg_first

    min_delta = policy.get("escalation_minimum_delta", 5)
    if delta >= min_delta:
        bonus = policy.get("escalation_bonus", 0)
        return bonus, True, f"escalation: average base_score rose {avg_first:.1f} -> {avg_second:.1f} (+{delta:.1f}) -> +{bonus}"
    return 0, False, f"escalation: average base_score {avg_first:.1f} -> {avg_second:.1f}, no significant rise"


def _repeated_category_bonus(events: list[dict[str, Any]], policy: dict[str, Any]) -> tuple[int, list[str], str]:
    category_counts: dict[str, int] = {}
    for ev in events:
        for cat in _extract_categories(ev):
            category_counts[cat] = category_counts.get(cat, 0) + 1

    repeated = sorted([cat for cat, count in category_counts.items() if count >= 2])
    if not repeated:
        return 0, [], "repeated category: no category recurs across events in window"

    bonus = policy.get("repeated_category_bonus", 0)
    return bonus, repeated, f"repeated category: {', '.join(repeated)} recur(s) across events in window -> +{bonus}"


def correlate(
    user: str,
    current_time: datetime,
    log_path: str | Path = DEFAULT_LOG_PATH,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
) -> BehavioralContext:
    """
    Compute this user's behavioral adjustment for the event being scored
    right now. `current_time` is passed explicitly (not read internally via
    datetime.now()) so this is deterministic and testable without mocking
    the clock.
    """
    policy = _load_policy(policy_path)
    window_hours = policy.get("time_window_hours", 24)

    events = load_recent_flagged_events(user, current_time, log_path, window_hours)

    activity_bonus, activity_note = _repeated_activity_bonus(len(events), policy)
    escalation_bonus_val, escalating, escalation_note = _escalation_bonus(events, policy)
    category_bonus, repeated_categories, category_note = _repeated_category_bonus(events, policy)

    total = activity_bonus + escalation_bonus_val + category_bonus

    return BehavioralContext(
        adjustment=total,
        event_count_in_window=len(events),
        escalating=escalating,
        repeated_categories=repeated_categories,
        explanation=[activity_note, escalation_note, category_note],
    )
