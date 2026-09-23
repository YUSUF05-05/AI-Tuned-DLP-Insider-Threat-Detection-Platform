import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from correlation.behavior_tracker import (  # noqa: E402
    correlate, load_recent_flagged_events, _repeated_activity_bonus,
    _escalation_bonus, _repeated_category_bonus,
)

NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


def _write_events(path: Path, events: list[dict]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _fake_event(user, hours_ago, base_score=None, category="payment_card", ts=NOW):
    ev = {
        "user": user,
        "timestamp": (ts - timedelta(hours=hours_ago)).isoformat(),
        "detections": [{"detector": "card_detector", "matched": True, "category": category, "confidence": 1.0}],
        "ai_analysis": None,
    }
    if base_score is not None:
        ev["risk_assessment"] = {"base_score": base_score}
    return ev


def _policy_path(tmp_path, **overrides):
    policy = {
        "weights": {"deterministic": 0.4, "ai": 0.3, "context": 0.1, "destination": 0.2},
        "severity_thresholds": {"low": 0, "medium": 25, "high": 50, "critical": 75},
        "behavioral_adjustment_cap": 25,
        "behavioral_correlation": {
            "time_window_hours": 24,
            "repeated_activity_thresholds": [
                {"min_count": 7, "bonus": 20}, {"min_count": 4, "bonus": 12}, {"min_count": 2, "bonus": 5},
            ],
            "escalation_bonus": 10, "escalation_minimum_delta": 5,
            "repeated_category_bonus": 8,
        },
    }
    policy["behavioral_correlation"].update(overrides)
    p = tmp_path / "risk_policy.yaml"
    p.write_text(yaml.dump(policy))
    return p


# --------------------------------------------------------------------
# load_recent_flagged_events
# --------------------------------------------------------------------

def test_filters_by_user(tmp_path):
    log = tmp_path / "flagged.jsonl"
    _write_events(log, [_fake_event("alice", 1), _fake_event("bob", 1)])
    result = load_recent_flagged_events("alice", NOW, log, window_hours=24)
    assert len(result) == 1
    assert result[0]["user"] == "alice"


def test_filters_by_time_window(tmp_path):
    log = tmp_path / "flagged.jsonl"
    _write_events(log, [_fake_event("alice", hours_ago=1), _fake_event("alice", hours_ago=48)])
    result = load_recent_flagged_events("alice", NOW, log, window_hours=24)
    assert len(result) == 1


def test_malformed_timestamp_is_skipped_not_fatal(tmp_path):
    log = tmp_path / "flagged.jsonl"
    _write_events(log, [{"user": "alice", "timestamp": "not-a-real-timestamp"}, _fake_event("alice", 1)])
    result = load_recent_flagged_events("alice", NOW, log, window_hours=24)
    assert len(result) == 1  # the malformed one is skipped, the good one still counts


def test_missing_log_file_returns_empty_list(tmp_path):
    result = load_recent_flagged_events("alice", NOW, tmp_path / "does_not_exist.jsonl", window_hours=24)
    assert result == []


# --------------------------------------------------------------------
# Repeated activity tiers -- exact thresholds
# --------------------------------------------------------------------

POLICY = {
    "repeated_activity_thresholds": [
        {"min_count": 7, "bonus": 20}, {"min_count": 4, "bonus": 12}, {"min_count": 2, "bonus": 5},
    ],
}

def test_below_lowest_threshold_no_bonus():
    bonus, _ = _repeated_activity_bonus(1, POLICY)
    assert bonus == 0


def test_exactly_at_first_tier():
    bonus, _ = _repeated_activity_bonus(2, POLICY)
    assert bonus == 5


def test_exactly_at_second_tier():
    bonus, _ = _repeated_activity_bonus(4, POLICY)
    assert bonus == 12


def test_exactly_at_third_tier():
    bonus, _ = _repeated_activity_bonus(7, POLICY)
    assert bonus == 20


def test_above_third_tier_still_caps_at_top_bonus():
    bonus, _ = _repeated_activity_bonus(50, POLICY)
    assert bonus == 20


# --------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------

ESC_POLICY = {"escalation_bonus": 10, "escalation_minimum_delta": 5}

def test_escalation_detected_on_rising_trend():
    events = [
        _fake_event("alice", hours_ago=20, base_score=10),
        _fake_event("alice", hours_ago=15, base_score=15),
        _fake_event("alice", hours_ago=5, base_score=40),
        _fake_event("alice", hours_ago=1, base_score=50),
    ]
    bonus, escalating, note = _escalation_bonus(events, ESC_POLICY)
    assert escalating is True
    assert bonus == 10
    assert "rose" in note


def test_no_escalation_on_flat_trend():
    events = [
        _fake_event("alice", hours_ago=20, base_score=20),
        _fake_event("alice", hours_ago=15, base_score=22),
        _fake_event("alice", hours_ago=5, base_score=21),
        _fake_event("alice", hours_ago=1, base_score=19),
    ]
    bonus, escalating, note = _escalation_bonus(events, ESC_POLICY)
    assert escalating is False
    assert bonus == 0


def test_insufficient_events_no_escalation_claim():
    events = [_fake_event("alice", hours_ago=1, base_score=90)]
    bonus, escalating, note = _escalation_bonus(events, ESC_POLICY)
    assert escalating is False
    assert bonus == 0
    assert "not enough" in note


def test_events_without_risk_assessment_are_ignored_not_fatal():
    events = [_fake_event("alice", hours_ago=h) for h in [20, 15, 5, 1]]  # no base_score at all
    bonus, escalating, note = _escalation_bonus(events, ESC_POLICY)
    assert escalating is False
    assert bonus == 0  # can't assess trend with no scores, must not crash


# --------------------------------------------------------------------
# Repeated category
# --------------------------------------------------------------------

CAT_POLICY = {"repeated_category_bonus": 8}

def test_repeated_category_detected():
    events = [_fake_event("alice", 1, category="payment_card"), _fake_event("alice", 2, category="payment_card")]
    bonus, repeated, note = _repeated_category_bonus(events, CAT_POLICY)
    assert bonus == 8
    assert repeated == ["payment_card"]


def test_no_repeat_when_categories_differ():
    events = [_fake_event("alice", 1, category="payment_card"), _fake_event("alice", 2, category="credential_secret")]
    bonus, repeated, note = _repeated_category_bonus(events, CAT_POLICY)
    assert bonus == 0
    assert repeated == []


# --------------------------------------------------------------------
# Full correlate() integration
# --------------------------------------------------------------------

def test_correlate_combines_all_three_signals(tmp_path):
    log = tmp_path / "flagged.jsonl"
    policy_path = _policy_path(tmp_path)
    # 4 events (>= tier 4 -> +12), same category repeated (+8), rising scores (+10)
    _write_events(log, [
        _fake_event("alice", hours_ago=20, base_score=10, category="payment_card"),
        _fake_event("alice", hours_ago=15, base_score=15, category="payment_card"),
        _fake_event("alice", hours_ago=5, base_score=40, category="payment_card"),
        _fake_event("alice", hours_ago=1, base_score=50, category="payment_card"),
    ])
    ctx = correlate("alice", NOW, log, policy_path)
    assert ctx.event_count_in_window == 4
    assert ctx.escalating is True
    assert ctx.repeated_categories == ["payment_card"]
    assert ctx.adjustment == 12 + 10 + 8  # 30, will get capped later by risk_engine, not here


def test_correlate_different_users_do_not_interfere(tmp_path):
    log = tmp_path / "flagged.jsonl"
    policy_path = _policy_path(tmp_path)
    _write_events(log, [_fake_event("alice", 1, base_score=90, category="payment_card") for _ in range(10)])
    ctx_bob = correlate("bob", NOW, log, policy_path)
    assert ctx_bob.event_count_in_window == 0
    assert ctx_bob.adjustment == 0


def test_correlate_no_history_returns_zero_adjustment(tmp_path):
    log = tmp_path / "flagged.jsonl"
    policy_path = _policy_path(tmp_path)
    ctx = correlate("nobody_yet", NOW, log, policy_path)
    assert ctx.adjustment == 0
    assert ctx.event_count_in_window == 0
