"""
simulations/scenario_runner.py  (Phase 11.2)

Runs the scenario catalog through the REAL pipeline and reports, per step,
what the system actually did next to what the requirement said it should do.

HOW IT STAYS HONEST
  - It drives the project's own collectors through their own test seams:
        file       -> DLPFileEventHandler.on_created(FileCreatedEvent(...))
        clipboard  -> ClipboardCollector(read_fn=<fake>).poll_once()
        http       -> create_app(...).test_client().post("/upload")
    so file-reading, excerpt capping, UTF-8/latin-1 fallback, clipboard change
    detection and HTTP body decoding are all exercised, not bypassed. No sleeps
    and no watchdog thread timing, so runs are deterministic.
  - It reuses run_pipeline_demo.build_on_event(), the exact callback the live
    pipeline uses (detect -> normalize -> score -> correlate -> re-score ->
    SQLite -> flagged-log). Copying that chain here would let scenarios and
    production drift apart. (Extracting a shared pipeline module is a refactor
    that belongs in Phase 16, not here.)
  - AI review is OFF. LLM output is non-deterministic and slow; Phase 12 measures
    it separately.

HOW IT STAYS SAFE
  - Every scenario gets a fresh, private working directory (default
    logs/_scenarios/<scenario_id>/): its own flagged log, SQLite file and
    collector logs. Behavioral correlation therefore never sees your live
    logs/flagged_events.jsonl, and the live audit database is never touched.
  - Alerts are DECIDED (AlertEngine.should_alert) but never DELIVERED: the engine
    used here has no channels, so process() cannot print, write alerts.log, or
    reach a webhook even by accident.
  - Identity and time are simulated: each step's user and timestamp are applied
    to the event before analysis (collectors otherwise stamp the OS user and the
    wall clock).

Usage (from the project root, venv active):
    python simulations/scenario_runner.py
    python simulations/scenario_runner.py --scenario s1_bulk_customer_export
    python simulations/scenario_runner.py --list
    python simulations/scenario_runner.py --json logs/phase11_results.json

Exit code: 0 when every scenario PASSes or is a documented KNOWN_GAP; 1 when
any scenario FAILs (unexpected) or XPASSes (a known gap that no longer fails --
remove its known_gap marker).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from watchdog.events import FileCreatedEvent  # noqa: E402

from alerts.alert_engine import AlertEngine  # noqa: E402
from collectors.clipboard_collector import ClipboardCollector  # noqa: E402
from collectors.file_collector import DLPFileEventHandler  # noqa: E402
from collectors.http_collector import create_app  # noqa: E402
from common.event_schema import DLPEvent, JsonlEventLogger  # noqa: E402
from database.sqlite_audit import SQLiteAuditStore  # noqa: E402
from run_pipeline_demo import build_on_event  # noqa: E402
from simulations.scenario_catalog import CATALOG  # noqa: E402
from simulations.scenarios import SEVERITIES, Expect, Scenario, Step  # noqa: E402

# Importing run_pipeline_demo calls logging.basicConfig(level=INFO); the pipeline logs one
# INFO line per clean event, which would drown the results table.
logging.getLogger().setLevel(logging.WARNING)

DEFAULT_WORK_ROOT = ROOT / "logs" / "_scenarios"
DEFAULT_ALERT_POLICY = ROOT / "config" / "alert_policy.yaml"
REPORT_VERSION = 1

_SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}


class DecisionOnlyAlertEngine(AlertEngine):
    """The real AlertEngine's threshold logic (should_alert) with zero delivery channels."""

    def _build_channels(self) -> list:
        return []


@dataclass
class StepOutcome:
    index: int
    source: str
    user: str
    timestamp: str
    emitted: bool = False
    flagged: bool = False
    severity: Optional[str] = None
    score: Optional[int] = None
    base_score: Optional[int] = None
    behavioral_adjustment: Optional[int] = None
    categories: list[str] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    layers: int = 0
    would_alert: bool = False
    components: dict[str, float] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


@dataclass
class ScenarioOutcome:
    scenario_id: str
    threat: str
    kind: str
    title: str
    known_gap: Optional[str]
    steps: list[StepOutcome]
    invariant_failures: list[str] = field(default_factory=list)

    @property
    def step_failures(self) -> list[str]:
        return [f"step {s.index}: {msg}" for s in self.steps for msg in s.failures]

    @property
    def status(self) -> str:
        if self.invariant_failures:
            return "FAIL"          # pipeline-integrity problems are never excusable as a known gap
        if self.step_failures:
            return "KNOWN_GAP" if self.known_gap else "FAIL"
        return "XPASS" if self.known_gap else "PASS"

    def to_report(self) -> dict:
        return {
            "id": self.scenario_id, "threat": self.threat, "kind": self.kind, "title": self.title,
            "status": self.status, "known_gap": self.known_gap,
            "step_failures": self.step_failures, "invariant_failures": self.invariant_failures,
            "steps": [asdict(s) for s in self.steps],
        }


# --------------------------------------------------------------------------
# Expectation checking
# --------------------------------------------------------------------------
def check_expectation(exp: Expect, o: StepOutcome) -> list[str]:
    problems: list[str] = []
    if exp.flagged is not None and o.flagged != exp.flagged:
        problems.append(f"flagged: expected {exp.flagged}, got {o.flagged}")
    if exp.min_severity is not None:
        if o.severity is None or _SEV_RANK[o.severity] < _SEV_RANK[exp.min_severity]:
            problems.append(f"severity: expected >= {exp.min_severity}, got {o.severity or 'unflagged'}"
                            f" (score {o.score}, base {o.base_score}, behavioral +{o.behavioral_adjustment or 0})")
    if exp.max_severity is not None and o.severity is not None and _SEV_RANK[o.severity] > _SEV_RANK[exp.max_severity]:
        problems.append(f"severity: expected <= {exp.max_severity}, got {o.severity}"
                        f" (score {o.score}, base {o.base_score}, behavioral +{o.behavioral_adjustment or 0})")
    missing = [c for c in exp.categories_include if c not in o.categories]
    if missing:
        problems.append(f"categories: missing {missing}; saw {o.categories or 'none'}")
    missing = [t for t in exp.obfuscation_include if t not in o.obfuscation]
    if missing:
        problems.append(f"obfuscation: missing {missing}; saw {o.obfuscation or 'none'}")
    if exp.min_layers is not None and o.layers < exp.min_layers:
        problems.append(f"layers: expected >= {exp.min_layers}, got {o.layers}")
    adjustment = o.behavioral_adjustment or 0
    if exp.min_behavioral_adjustment is not None and adjustment < exp.min_behavioral_adjustment:
        problems.append(f"behavioral adjustment: expected >= {exp.min_behavioral_adjustment}, got {adjustment}")
    if exp.max_behavioral_adjustment is not None and adjustment > exp.max_behavioral_adjustment:
        problems.append(f"behavioral adjustment: expected <= {exp.max_behavioral_adjustment}, got {adjustment}")
    if exp.would_alert is not None and o.would_alert != exp.would_alert:
        problems.append(f"would_alert: expected {exp.would_alert}, got {o.would_alert}")
    return problems


def _observe(event: DLPEvent, outcome: StepOutcome, alert_engine: AlertEngine) -> None:
    """Copy what the pipeline concluded about `event` into `outcome`."""
    outcome.emitted = True
    outcome.flagged = event.any_match
    categories: set[str] = set()
    for det in event.detections:
        if det.matched and det.category:
            categories.update(part for part in det.category.split(",") if part)
    techniques: list[str] = []
    for ob in event.obfuscation:
        matched = [d for d in ob.rescanned_detections if d.matched]
        if matched:
            techniques.append(ob.technique)
            outcome.layers = max(outcome.layers, ob.layers)
            for det in matched:
                if det.category:
                    categories.update(part for part in det.category.split(",") if part)
    outcome.categories = sorted(categories)
    outcome.obfuscation = sorted(set(techniques))
    ra = event.risk_assessment
    if ra is not None:
        outcome.severity, outcome.score, outcome.base_score = ra.severity, ra.score, ra.base_score
        outcome.behavioral_adjustment = ra.behavioral_adjustment
        outcome.components = dict(ra.components)
    outcome.would_alert = alert_engine.should_alert(event)


# --------------------------------------------------------------------------
# Scenario execution
# --------------------------------------------------------------------------
def run_scenario(scenario: Scenario, work_root: Path, alert_engine: AlertEngine) -> ScenarioOutcome:
    workdir = Path(work_root) / scenario.id
    shutil.rmtree(workdir, ignore_errors=True)
    (workdir / "monitored").mkdir(parents=True)

    flagged_logger = JsonlEventLogger(workdir / "flagged_events.jsonl")
    db = SQLiteAuditStore(db_path=workdir / "audit_trail.db")
    pipeline = build_on_event(flagged_logger, use_ai=False, db=db, alert_engine=None)

    ctx: dict = {"step": None, "event": None}

    def hook(event: DLPEvent) -> None:
        step: Step = ctx["step"]
        event.user = step.user                              # collectors stamp the OS user / wall clock;
        event.timestamp = scenario.timestamp_for(step)      # scenarios supply simulated identity and time
        with contextlib.redirect_stdout(io.StringIO()):     # analyze_event prints a console block per flagged event
            pipeline(event)
        ctx["event"] = event

    file_handler = DLPFileEventHandler(JsonlEventLogger(workdir / "file_events.jsonl"), on_event=hook)
    clipboard = {"value": ""}
    clipboard_collector = ClipboardCollector(
        JsonlEventLogger(workdir / "clipboard_events.jsonl"), read_fn=lambda: clipboard["value"], on_event=hook,
    )
    clipboard_collector.poll_once()                        # first poll is a baseline and never emits
    http_client = create_app(JsonlEventLogger(workdir / "http_events.jsonl"), on_event=hook).test_client()

    outcomes: list[StepOutcome] = []
    try:
        for index, step in enumerate(scenario.steps, start=1):
            outcome = StepOutcome(index=index, source=step.source, user=step.user,
                                  timestamp=scenario.timestamp_for(step))
            ctx["step"], ctx["event"] = step, None
            try:
                if step.source == "file":
                    path = workdir / "monitored" / step.filename
                    data = step.payload if isinstance(step.payload, bytes) else step.payload.encode("utf-8")
                    path.write_bytes(data)                 # bytes, not write_text: no Windows \n -> \r\n rewrite
                    file_handler.on_created(FileCreatedEvent(str(path)))
                elif step.source == "clipboard":
                    clipboard["value"] = step.payload
                    clipboard_collector.poll_once()
                else:
                    http_client.post(
                        "/upload", data=step.payload.encode("utf-8"),
                        headers={"Content-Type": "text/plain", "X-DLP-Simulated-User": step.user},
                    )
            except Exception as exc:  # noqa: BLE001 -- a crashing pipeline is a result, not a runner crash
                outcome.failures.append(f"pipeline raised {type(exc).__name__}: {exc}")

            if ctx["event"] is None:
                if not outcome.failures:
                    outcome.failures.append("no event was emitted by the collector")
            else:
                _observe(ctx["event"], outcome, alert_engine)
                if step.expect is not None:
                    outcome.failures.extend(check_expectation(step.expect, outcome))
            outcomes.append(outcome)

        # Pipeline-integrity invariants: true for EVERY scenario, independent of its expectations.
        flagged_steps = sum(1 for o in outcomes if o.flagged)
        invariants: list[str] = []
        persisted = db.count_events()
        if persisted != flagged_steps:
            invariants.append(f"persistence: {flagged_steps} flagged event(s) but {persisted} row(s) in the audit database")
        logged = len(flagged_logger.read_all())
        if logged != flagged_steps:
            invariants.append(f"flagged log: {flagged_steps} flagged event(s) but {logged} line(s) in flagged_events.jsonl")
    finally:
        db.close()

    return ScenarioOutcome(
        scenario_id=scenario.id, threat=scenario.threat, kind=scenario.kind, title=scenario.title,
        known_gap=scenario.known_gap, steps=outcomes, invariant_failures=invariants,
    )


def run_catalog(
    catalog=CATALOG,
    work_root: Path = DEFAULT_WORK_ROOT,
    only: Optional[list[str]] = None,
    alert_policy_path: Path = DEFAULT_ALERT_POLICY,
) -> list[ScenarioOutcome]:
    alert_engine = DecisionOnlyAlertEngine(policy_path=alert_policy_path)
    selected = [s for s in catalog if not only or s.id in only]
    unknown = sorted(set(only or []) - {s.id for s in catalog})
    if unknown:
        raise SystemExit(f"unknown scenario id(s): {unknown}. Use --list to see valid ids.")
    return [run_scenario(sc, Path(work_root), alert_engine) for sc in selected]


def build_report(outcomes: list[ScenarioOutcome], alert_threshold: str) -> dict:
    """Deterministic by construction: no event ids, no absolute paths, no wall-clock times."""
    return {
        "report_version": REPORT_VERSION,
        "alert_threshold": alert_threshold,
        "scenarios": [o.to_report() for o in outcomes],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _final_cell(o: ScenarioOutcome) -> str:
    last = o.steps[-1]
    if last.severity is None:
        return "clean" if last.emitted else "no event"
    return f"{last.severity}/{last.score}"


def print_results(outcomes: list[ScenarioOutcome]) -> None:
    print(f"\n{'SCENARIO':<34} {'THR':<4} {'KIND':<15} {'STATUS':<10} FINAL")
    print("-" * 78)
    for o in outcomes:
        print(f"{o.scenario_id:<34} {o.threat:<4} {o.kind:<15} {o.status:<10} {_final_cell(o)}")
    for o in outcomes:
        if o.status == "PASS":
            continue
        print(f"\n[{o.status}] {o.scenario_id} -- {o.title}")
        if o.known_gap:
            print(f"    known gap: {o.known_gap}")
        for line in o.step_failures:
            print(f"    - {line}")
        for line in o.invariant_failures:
            print(f"    ! INVARIANT {line}")
        if o.status == "XPASS":
            print("    This scenario now meets its expectations: remove its known_gap marker.")
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    print("\nSummary: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) + f" (of {len(outcomes)})")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Phase 11 detection scenarios through the real pipeline")
    parser.add_argument("--scenario", action="append", help="scenario id (repeatable); default: all")
    parser.add_argument("--list", action="store_true", help="list scenario ids and exit")
    parser.add_argument("--json", metavar="PATH", help="also write a deterministic JSON report (input to Phase 12)")
    parser.add_argument("--work-dir", default=str(DEFAULT_WORK_ROOT), help="scratch directory (recreated per scenario)")
    parser.add_argument("--alert-policy-path", default=str(DEFAULT_ALERT_POLICY))
    args = parser.parse_args(argv)

    if args.list:
        for sc in CATALOG:
            print(f"{sc.id:<34} {sc.threat}  {sc.kind:<15} {sc.title}")
        return 0

    outcomes = run_catalog(CATALOG, Path(args.work_dir), args.scenario, Path(args.alert_policy_path))
    print_results(outcomes)

    if args.json:
        threshold = DecisionOnlyAlertEngine(policy_path=args.alert_policy_path).threshold
        out_path = Path(args.json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(build_report(outcomes, threshold), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"JSON report written to {out_path}")

    return 1 if any(o.status in ("FAIL", "XPASS") for o in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
