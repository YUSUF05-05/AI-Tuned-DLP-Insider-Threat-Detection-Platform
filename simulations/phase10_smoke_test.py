"""
simulations/phase10_smoke_test.py

Reusable end-to-end verification script for Phase 9 (Step 0 fixes) and
Phase 10 (dashboard + alerts). Not part of the automated pytest suite --
this is a narrative demo script in the same spirit as
simulations/http_exfil_simulator.py, meant to be run manually and read.

Exercises the full chain on synthetic data only (see docs/THREAT_MODEL.md
A2): detection -> risk scoring -> behavioral correlation -> SQLite
persistence (with full behavioral context) -> alert engine -> a real,
separately-started dashboard process queried over HTTP -> a raw SQL tamper
attempt against the finished database to prove the append-only triggers
actually reject it.

Usage:
    python simulations/phase10_smoke_test.py
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import time
import urllib.request
import json as jsonlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.event_schema import build_event
from detectors.engine import run_all, summarize
from normalization.normalizer import normalize_and_rescan
from scoring.risk_engine import compute_risk
from correlation.behavior_tracker import correlate, BehavioralContext
from database.sqlite_audit import SQLiteAuditStore
from alerts.alert_engine import AlertEngine

WORKDIR = ROOT / "logs" / "_phase10_smoke"


def line(msg=""):
    print(msg)


def step(title):
    line()
    line("=" * 78)
    line(title)
    line("=" * 78)


def main():
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    WORKDIR.mkdir(parents=True)
    db_path = WORKDIR / "audit_trail.db"
    flagged_log = WORKDIR / "flagged_events.jsonl"
    alert_log = WORKDIR / "alerts.log"

    step("1. Build a synthetic flagged event (Phase 4/5)")
    event = build_event(
        source="clipboard",
        event_type="clipboard_change",
        object_ref="clipboard",
        content_excerpt="exporting customer list: card 4111111111111111 ssn 123-45-6789",
    )
    event.user = "demo_analyst"
    event.detections = run_all(event.content_excerpt, filename=None)
    event.obfuscation = normalize_and_rescan(event.content_excerpt, run_all)
    summary = summarize(event.detections)
    line(f"any_match={event.any_match}  matched_detectors={summary['matched_detectors']}  needs_ai_review={summary['needs_ai_review']}")
    assert event.any_match, "smoke fixture should have matched -- fix the fixture, not this assertion"

    step("2. Risk scoring (Phase 7) + behavioral correlation (Phase 8)")
    event.risk_assessment = compute_risk(event, behavioral_adjustment=0)
    behavior = correlate("demo_analyst", datetime.now(timezone.utc), log_path=flagged_log)
    event.risk_assessment = compute_risk(event, behavioral_adjustment=behavior.adjustment)
    ra = event.risk_assessment
    line(f"severity={ra.severity.upper()}  score={ra.score}  (base={ra.base_score}, behavioral=+{ra.behavioral_adjustment})")
    line(f"behavioral: event_count_in_window={behavior.event_count_in_window} escalating={behavior.escalating} repeated_categories={behavior.repeated_categories}")

    step("3. Persist to SQLite audit trail (Phase 9), including FULL behavioral context")
    db = SQLiteAuditStore(db_path=db_path)
    db.insert_event(event, behavior=behavior)
    line(f"inserted event_id={event.event_id}")
    fetched = db.get_event(event.event_id)
    line(f"read back: behavioral_event_count_in_window={fetched['behavioral_event_count_in_window']} "
         f"behavioral_escalating={fetched['behavioral_escalating']} "
         f"behavioral_repeated_categories={fetched['behavioral_repeated_categories']}")
    assert fetched["behavioral_event_count_in_window"] == behavior.event_count_in_window, \
        "full behavioral context did not round-trip through insert_event()/get_event()"

    step("4. Alert engine (Phase 10) -- policy threshold is 'medium'; this event should fire")
    alert_engine = AlertEngine(policy_path=ROOT / "config" / "alert_policy.yaml")
    # Point the log_file channel at our scratch dir for this run, mirroring
    # the real policy's shape but without touching the repo's own logs/alerts.log.
    for ch in alert_engine.channels:
        if ch.name == "log_file":
            ch.path = alert_log
            ch.path.parent.mkdir(parents=True, exist_ok=True)
    results = alert_engine.process(event)
    for r in results:
        line(f"channel={r.channel} delivered={r.delivered} detail={r.detail}")
    assert results, "expected the alert engine to fire for a flagged event above the threshold"
    assert all(r.delivered for r in results), "expected every enabled channel to report delivered=True"
    if alert_log.exists():
        line(f"alerts.log content: {alert_log.read_text().strip()}")

    step("5. Immutability -- attempt a RAW SQL UPDATE and DELETE directly against the finished database")
    raw = sqlite3.connect(str(db_path))
    try:
        raw.execute("UPDATE events SET risk_score = 0 WHERE event_id = ?", (event.event_id,))
        line("UPDATE: SUCCEEDED (this would be a FAILURE of the Step 0 fix)")
        update_ok = False
    except sqlite3.DatabaseError as exc:
        line(f"UPDATE: REJECTED as expected -> {exc}")
        update_ok = True
    try:
        raw.execute("DELETE FROM events WHERE event_id = ?", (event.event_id,))
        line("DELETE: SUCCEEDED (this would be a FAILURE of the Step 0 fix)")
        delete_ok = False
    except sqlite3.DatabaseError as exc:
        line(f"DELETE: REJECTED as expected -> {exc}")
        delete_ok = True
    raw.close()
    assert update_ok and delete_ok, "append-only enforcement did not hold -- see schema.sql triggers"

    step("6. verify_integrity() -- the same check the dashboard's /api/integrity route exposes")
    integrity = db.verify_integrity()
    line(jsonlib.dumps(integrity, indent=2))
    assert integrity["healthy"] is True

    db.close()

    step("7. Start the dashboard as a REAL separate process and hit it over HTTP")
    import subprocess
    port = 18766
    proc = subprocess.Popen(
        [sys.executable, "-m", "dashboard.run_dashboard", "--port", str(port), "--db-path", str(db_path)],
        cwd=str(ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 10
        last_err = None
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
                break
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.3)
        else:
            raise RuntimeError(f"dashboard did not come up in time: {last_err}")

        for path in ("/healthz", "/api/summary", "/api/integrity", f"/api/events?severity={event.risk_assessment.severity}", f"/api/events/{event.event_id}"):
            with urllib.request.urlopen(base + path, timeout=3) as resp:
                body = resp.read().decode()
            line(f"GET {path} -> HTTP {resp.status}")
            line(f"  {body[:400]}{'...' if len(body) > 400 else ''}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    step("SMOKE TEST PASSED")
    line("Every assertion above held: detection -> scoring -> correlation -> append-only")
    line("persistence with full behavioral context -> alert dispatch -> a real dashboard")
    line("process serving the data read-only over HTTP -> raw SQL UPDATE/DELETE rejected.")


if __name__ == "__main__":
    main()
