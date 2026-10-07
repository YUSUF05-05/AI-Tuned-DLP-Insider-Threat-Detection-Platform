"""
tests/test_scenarios.py  (Phase 11.5)

Puts the Phase 11 scenario catalog under pytest so it runs with the rest of
the suite (python -m pytest tests/ -v).

Four groups:
  1. Contract tests       -- simulations/scenarios.py rejects malformed scenarios.
  2. Scenario expectations -- one test per catalog entry. Scenarios with a
                              known_gap are STRICT xfails: while the gap exists
                              the test is an expected failure; the day it is
                              fixed the test XPASSes and strict mode fails the
                              suite until the known_gap marker is removed.
  3. Pipeline invariants   -- every flagged event is persisted and logged. These
                              are deliberately NOT xfail-able: a known detection
                              gap must never be allowed to hide a persistence bug.
  4. Determinism           -- two full runs produce an identical report.

The whole catalog is executed ONCE per module (module-scoped fixture); each
parametrized test only inspects the stored outcome.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from simulations.scenario_catalog import CATALOG  # noqa: E402
from simulations.scenario_runner import (  # noqa: E402
    DEFAULT_ALERT_POLICY, DecisionOnlyAlertEngine, build_report, run_catalog,
)
from simulations.scenarios import Expect, Scenario, Step, validate_catalog  # noqa: E402


@pytest.fixture(scope="module")
def outcomes(tmp_path_factory):
    work_root = tmp_path_factory.mktemp("scenarios")
    return {o.scenario_id: o for o in run_catalog(CATALOG, work_root)}


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------
def _ok_step(**overrides):
    kwargs = dict(source="clipboard", payload="x", at_minutes=0, expect=Expect(flagged=True))
    kwargs.update(overrides)
    return Step(**kwargs)


def _scenario(**overrides):
    kwargs = dict(id="s1_demo", threat="S1", kind="attack", title="t", rationale="r", steps=(_ok_step(),))
    kwargs.update(overrides)
    return Scenario(**kwargs)


def test_catalog_satisfies_its_own_coverage_rules():
    validate_catalog(CATALOG)


def test_catalog_has_both_attacks_and_benign_controls_for_every_threat():
    for threat in ("S1", "S2", "S3", "S4", "S5", "S6"):
        kinds = {s.kind for s in CATALOG if s.threat == threat}
        assert "benign_control" in kinds, f"{threat} has no benign control"
        assert kinds & {"attack", "evasion"}, f"{threat} has no attack/evasion"


@pytest.mark.parametrize("bad", [
    lambda: Expect(min_severity="hgih"),
    lambda: Expect(min_severity="high", max_severity="low"),
    lambda: Expect(min_layers=0),
    lambda: Expect(categories_include=["payment_card"]),          # list, not tuple
    lambda: _ok_step(source="usb"),
    lambda: _ok_step(payload=""),
    lambda: _ok_step(at_minutes=-1),
    lambda: _ok_step(source="file"),                              # file step without filename
    lambda: _ok_step(filename="a.txt"),                           # filename on a non-file step
    lambda: _ok_step(source="file", filename="sub/dir.txt"),      # directories not allowed
    lambda: _scenario(id="BadId"),
    lambda: _scenario(id="s2_wrong_prefix"),                      # prefix must match threat S1
    lambda: _scenario(kind="malware"),
    lambda: _scenario(steps=()),
    lambda: _scenario(steps=(_ok_step(expect=None),)),            # asserts nothing
    lambda: _scenario(steps=(_ok_step(at_minutes=5), _ok_step(payload="y", at_minutes=5))),   # not strictly increasing
    lambda: _scenario(steps=(_ok_step(at_minutes=0), _ok_step(at_minutes=1))),                # same clipboard payload twice
    lambda: _scenario(start="not-a-timestamp"),
])
def test_malformed_definitions_are_rejected_at_construction(bad):
    with pytest.raises(ValueError):
        bad()


def test_duplicate_ids_are_rejected_by_catalog_validation():
    with pytest.raises(ValueError, match="duplicate"):
        validate_catalog(tuple(CATALOG) + (CATALOG[0],))


def test_missing_benign_control_is_rejected_by_catalog_validation():
    attacks_only = tuple(s for s in CATALOG if s.kind != "benign_control")
    with pytest.raises(ValueError, match="benign_control"):
        validate_catalog(attacks_only)


def test_decision_only_alert_engine_has_no_delivery_channels():
    assert DecisionOnlyAlertEngine(policy_path=DEFAULT_ALERT_POLICY).channels == []


# ---------------------------------------------------------------------------
# 2. Scenario expectations (strict xfail for documented gaps)
# ---------------------------------------------------------------------------
def _scenario_param(sc: Scenario):
    marks = [pytest.mark.xfail(strict=True, reason=sc.known_gap)] if sc.known_gap else []
    return pytest.param(sc, id=sc.id, marks=marks)


@pytest.mark.parametrize("scenario", [_scenario_param(s) for s in CATALOG])
def test_scenario_meets_its_requirement(scenario, outcomes):
    outcome = outcomes[scenario.id]
    assert not outcome.step_failures, "\n".join(outcome.step_failures)


# ---------------------------------------------------------------------------
# 3. Pipeline invariants (never xfail)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scenario", [pytest.param(s, id=s.id) for s in CATALOG])
def test_every_flagged_event_is_persisted_and_logged(scenario, outcomes):
    assert not outcomes[scenario.id].invariant_failures, "\n".join(outcomes[scenario.id].invariant_failures)


# ---------------------------------------------------------------------------
# 4. Determinism
# ---------------------------------------------------------------------------
def test_two_full_runs_produce_identical_reports(outcomes, tmp_path):
    threshold = DecisionOnlyAlertEngine(policy_path=DEFAULT_ALERT_POLICY).threshold
    first = build_report(list(outcomes.values()), threshold)
    second = build_report(run_catalog(CATALOG, tmp_path / "again"), threshold)
    assert first == second
