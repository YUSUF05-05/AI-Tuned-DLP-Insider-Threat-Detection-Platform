"""
simulations/scenarios.py  (Phase 11.1 -- scenario contract)

Defines WHAT a detection scenario is, with no pipeline imports at all: no
detectors, no collectors, no database. That separation is deliberate. The
catalog (simulations/scenario_catalog.py) and the runner
(simulations/scenario_runner.py) both depend on this module, but this module
depends on neither, so the vocabulary of a scenario can be reviewed, and
unit-tested, without running a single detector.

WHY FROZEN DATACLASSES VALIDATED IN __post_init__ (lighter alternative
considered: plain dicts, which is what simulations/http_exfil_simulator.py's
SYNTHETIC_SCENARIOS uses): a typo such as min_severity="hgih" in a dict is
silently never matched and the scenario "passes" while asserting nothing.
Here the same typo raises ValueError when the catalog is imported, so a bad
scenario can never reach a run. The cost is ~100 lines of validation; the
benefit is that a green run actually means something.

EXPECTATIONS COME FROM REQUIREMENTS, NOT FROM OUTPUT. Every Expect in the
catalog is derived from docs/THREAT_MODEL.md (S1-S6, DR1-DR9). If you tune an
expectation until it matches what the pipeline currently prints, you have
built a snapshot test, which can only ever say "nothing changed". A scenario
that fails today is information. Record it in `known_gap` (see below) rather
than loosening the assertion.

KNOWN GAPS. `Scenario.known_gap` marks a scenario whose expectations are
KNOWN to fail against the current implementation, with a sentence saying why
and where it gets fixed. tests/test_scenarios.py turns that into a strict
xfail: while the gap exists the test is "expected failure"; the day someone
fixes it, the test XPASSes and strict mode FAILS the suite until the
known_gap marker is removed. Gap documentation cannot silently rot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

SEVERITIES = ("low", "medium", "high", "critical")   # ascending, matches risk_policy.yaml
SOURCES = ("file", "clipboard", "http")              # matches DLPEvent.source
KINDS = ("attack", "evasion", "benign_control")
THREAT_IDS = ("S1", "S2", "S3", "S4", "S5", "S6")    # docs/THREAT_MODEL.md scenario table

# A fixed anchor (a Monday, 09:00 UTC) instead of "now": simulated time makes
# every run byte-for-byte reproducible, and correlate() already takes time as
# an explicit parameter, so nothing needs mocking.
DEFAULT_START = "2026-03-02T09:00:00Z"

_ID_RE = re.compile(r"^s[1-6]_[a-z0-9_]+$")


def _check_severity(value: Optional[str], field_name: str) -> None:
    if value is not None and value not in SEVERITIES:
        raise ValueError(f"{field_name}={value!r} is not one of {SEVERITIES}")


@dataclass(frozen=True)
class Expect:
    """
    What must be true of ONE emitted event. Every field defaults to None /
    empty, meaning "not asserted", so a scenario states only what its
    requirement actually says.
    """
    flagged: Optional[bool] = None                    # event.any_match
    min_severity: Optional[str] = None                # final severity must be >= this (unflagged fails)
    max_severity: Optional[str] = None                # final severity must be <= this (unflagged passes)
    categories_include: tuple[str, ...] = ()          # detector categories seen directly OR after decoding
    obfuscation_include: tuple[str, ...] = ()         # normalizer techniques whose rescan produced a match
    min_layers: Optional[int] = None                  # nested-encoding depth
    min_behavioral_adjustment: Optional[int] = None
    max_behavioral_adjustment: Optional[int] = None
    would_alert: Optional[bool] = None                # AlertEngine.should_alert() under config/alert_policy.yaml

    def __post_init__(self) -> None:
        _check_severity(self.min_severity, "min_severity")
        _check_severity(self.max_severity, "max_severity")
        if self.min_severity and self.max_severity:
            if SEVERITIES.index(self.min_severity) > SEVERITIES.index(self.max_severity):
                raise ValueError("min_severity is above max_severity")
        if (self.min_behavioral_adjustment is not None and self.max_behavioral_adjustment is not None
                and self.min_behavioral_adjustment > self.max_behavioral_adjustment):
            raise ValueError("min_behavioral_adjustment is above max_behavioral_adjustment")
        if self.min_layers is not None and self.min_layers < 1:
            raise ValueError("min_layers must be >= 1")
        for name in ("categories_include", "obfuscation_include"):
            if not isinstance(getattr(self, name), tuple):
                raise ValueError(f"{name} must be a tuple (got a list? use parentheses)")


@dataclass(frozen=True)
class Step:
    """One observable action by one user at one simulated moment."""
    source: str                                       # file | clipboard | http
    payload: Union[str, bytes]
    at_minutes: int                                   # minutes after Scenario.start
    user: str = "insider"
    filename: Optional[str] = None                    # file steps only: bare file name, no directories
    expect: Optional[Expect] = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ValueError(f"source={self.source!r} is not one of {SOURCES}")
        if not isinstance(self.at_minutes, int) or self.at_minutes < 0:
            raise ValueError("at_minutes must be a non-negative int")
        if not self.payload:
            raise ValueError("payload must not be empty")
        if self.source == "file":
            if not self.filename or "/" in self.filename or "\\" in self.filename:
                raise ValueError("file steps need a bare filename (no path separators)")
        else:
            if self.filename is not None:
                raise ValueError(f"filename is only valid for file steps (source={self.source!r})")
            if not isinstance(self.payload, str):
                raise ValueError(f"{self.source} payloads must be str (clipboard text / HTTP body encoded as UTF-8)")


@dataclass(frozen=True)
class Scenario:
    id: str                                           # s<threat digit>_<snake_case>
    threat: str                                       # S1..S6
    kind: str                                         # attack | evasion | benign_control
    title: str
    rationale: str                                    # which requirement this exercises, and why it matters
    steps: tuple[Step, ...]
    known_gap: Optional[str] = None                   # why this is expected to fail today, and where it gets fixed
    start: str = DEFAULT_START

    def __post_init__(self) -> None:
        if not _ID_RE.match(self.id):
            raise ValueError(f"scenario id {self.id!r} must match {_ID_RE.pattern}")
        if self.threat not in THREAT_IDS:
            raise ValueError(f"{self.id}: threat={self.threat!r} is not one of {THREAT_IDS}")
        if not self.id.startswith(self.threat.lower() + "_"):
            raise ValueError(f"{self.id}: id prefix must match threat {self.threat}")
        if self.kind not in KINDS:
            raise ValueError(f"{self.id}: kind={self.kind!r} is not one of {KINDS}")
        if not isinstance(self.steps, tuple) or not self.steps:
            raise ValueError(f"{self.id}: steps must be a non-empty tuple")
        if not any(s.expect is not None for s in self.steps):
            raise ValueError(f"{self.id}: no step has an Expect -- a scenario that asserts nothing cannot fail")

        previous_minute = -1
        previous_clip: Optional[str] = None
        for i, step in enumerate(self.steps, start=1):
            # correlate() only counts prior events with ts < current ts (strict),
            # so two steps at the same minute would silently not see each other.
            if step.at_minutes <= previous_minute:
                raise ValueError(f"{self.id}: step {i} at_minutes must be strictly increasing")
            previous_minute = step.at_minutes
            # ClipboardCollector only emits when the clipboard CHANGES. Two identical
            # consecutive pastes would produce one event and a confusing "missing" step.
            if step.source == "clipboard":
                if step.payload == previous_clip:
                    raise ValueError(f"{self.id}: step {i} repeats the previous clipboard payload (no change event would fire)")
                previous_clip = step.payload  # type: ignore[assignment]
        try:
            self.start_dt()
        except ValueError as exc:
            raise ValueError(f"{self.id}: bad start timestamp {self.start!r}: {exc}") from exc

    def start_dt(self) -> datetime:
        return datetime.fromisoformat(self.start.replace("Z", "+00:00")).astimezone(timezone.utc)

    def timestamp_for(self, step: Step) -> str:
        """Same format as common.event_schema.utc_now_iso(): ISO-8601, milliseconds, 'Z' suffix."""
        moment = self.start_dt() + timedelta(minutes=step.at_minutes)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def validate_catalog(catalog: tuple[Scenario, ...] | list[Scenario]) -> None:
    """
    Catalog-level rules that no single Scenario can check about itself:
      - ids are unique;
      - every threat S1..S6 has at least one attack/evasion scenario AND at
        least one benign control. Attack-only coverage proves the detector
        fires; it says nothing about whether it fires on everything.
    Raises ValueError listing every problem at once.
    """
    problems: list[str] = []
    seen: set[str] = set()
    for sc in catalog:
        if sc.id in seen:
            problems.append(f"duplicate scenario id {sc.id}")
        seen.add(sc.id)
    for threat in THREAT_IDS:
        mine = [s for s in catalog if s.threat == threat]
        if not any(s.kind in ("attack", "evasion") for s in mine):
            problems.append(f"{threat}: no attack/evasion scenario")
        if not any(s.kind == "benign_control" for s in mine):
            problems.append(f"{threat}: no benign_control scenario")
    if problems:
        raise ValueError("scenario catalog invalid:\n  - " + "\n  - ".join(problems))
