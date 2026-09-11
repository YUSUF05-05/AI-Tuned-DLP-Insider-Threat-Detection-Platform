"""
run_pipeline_demo.py

End-to-end demonstration wiring the full pipeline built so far:

    Phase 3 collectors -> Phase 4 detection -> Phase 5 normalization
        -> Phase 6 AI review -> Phase 7 risk scoring -> Phase 8 behavioral
        correlation -> Phase 7 risk scoring again (final)

This is a DEMO / verification harness, not "the product": Phase 9 will add
SQLite persistence (this still logs to logs/*.jsonl) and Phase 10 will add a
real dashboard (this still just prints to the console). Nothing here is the
final alerting UI.

WHY compute_risk() RUNS TWICE (see scoring/risk_engine.py's docstring for the
full reasoning): Phase 7 has no behavioral context for an event until Phase 8
has correlated it against the user's recent history, and Phase 8 needs the
event's OWN base score already computed before it can log a usable
base_score for FUTURE correlation to read. So: score once with
behavioral_adjustment=0 (base_score), correlate, then score again with the
real adjustment (final score). Same function both times -- no duplicated
scoring logic.

Usage (Windows, from the project root, with the venv active):
    python run_pipeline_demo.py
    python run_pipeline_demo.py --watch-dir C:\\dlp-lab\\monitored --http-port 8765
    python run_pipeline_demo.py --no-http           (file monitoring only)
    python run_pipeline_demo.py --no-ai             (skip Phase 6, e.g. Ollama not running)
"""

from __future__ import annotations

import argparse
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from common.event_schema import JsonlEventLogger, DLPEvent
from detectors.engine import run_all, summarize
from normalization.normalizer import normalize_and_rescan
from collectors.file_collector import start_file_collector
from collectors.http_collector import create_app
from ai.ollama_client import analyze as ollama_analyze
from scoring.risk_engine import compute_risk
from correlation.behavior_tracker import correlate

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "45"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("pipeline")


def analyze_event(event: DLPEvent, flagged_log_path: Path, use_ai: bool) -> None:
    """
    Runs the full analysis chain (Phases 4-8) and attaches every result to
    the event in place. Prints a console alert with severity/score on any
    match. This is the seam Phase 9 will extend with SQLite persistence.
    """
    text = event.content_excerpt or ""
    filename = event.object_ref if event.source == "file" else None

    event.detections = run_all(text, filename=filename)
    event.obfuscation = normalize_and_rescan(text, run_all) if text else []
    summary = summarize(event.detections)

    if not event.any_match:
        logger.info("clean: %s:%s -> %s", event.source, event.event_type, event.object_ref)
        return

    # Phase 6: AI review -- only for content that crossed the deterministic
    # review threshold AND actually has text to show the model.
    if use_ai and summary["needs_ai_review"] and text:
        event.ai_analysis = ollama_analyze(
            text, event.detections, host=OLLAMA_HOST, model=OLLAMA_MODEL, timeout_seconds=OLLAMA_TIMEOUT_SECONDS,
        )
        if event.ai_analysis.status == "error":
            logger.warning("AI review unavailable (%s) -- continuing on deterministic signal alone", event.ai_analysis.error)

    # Phase 7 (pass 1): base score, no behavioral context yet.
    event.risk_assessment = compute_risk(event, behavioral_adjustment=0)

    # Phase 8: correlate against this user's recent flagged history.
    try:
        current_time = datetime.fromisoformat(event.timestamp)
    except (TypeError, ValueError):
        current_time = datetime.now(timezone.utc)
    behavior = correlate(event.user, current_time, log_path=flagged_log_path)

    # Phase 7 (pass 2): final score, now with the real behavioral adjustment.
    event.risk_assessment = compute_risk(event, behavioral_adjustment=behavior.adjustment)

    categories = summary["categories"] or []
    obf_techniques = [ob.technique for ob in event.obfuscation if any(d.matched for d in ob.rescanned_detections)]
    if obf_techniques:
        categories = categories + [f"obfuscated:{t}" for t in obf_techniques]

    ra = event.risk_assessment
    print(f"\n[ALERT] {event.source}:{event.event_type} -> {event.object_ref}")
    print(f"        categories={categories}")
    print(f"        severity={ra.severity.upper()} score={ra.score} (base={ra.base_score}, behavioral=+{ra.behavioral_adjustment})")
    if event.ai_analysis and event.ai_analysis.status == "ok":
        print(f"        ai: is_sensitive={event.ai_analysis.is_sensitive} category={event.ai_analysis.category} confidence={event.ai_analysis.confidence:.2f}")
    if behavior.event_count_in_window:
        print(f"        behavioral: {behavior.event_count_in_window} prior flagged event(s) for {event.user} in window, escalating={behavior.escalating}")


def build_on_event(flagged_logger: JsonlEventLogger, use_ai: bool):
    def on_event(event: DLPEvent):
        analyze_event(event, flagged_log_path=Path(flagged_logger.log_path), use_ai=use_ai)
        if event.any_match:
            flagged_logger.write(event)

    return on_event


def main():
    parser = argparse.ArgumentParser(description="Full Phase 3-8 pipeline integration demo")
    parser.add_argument("--watch-dir", default=str(ROOT / "simulations" / "monitored"))
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--no-http", action="store_true", help="Disable the HTTP collector/destination")
    parser.add_argument("--no-ai", action="store_true", help="Skip Phase 6 AI review (e.g. Ollama not running)")
    args = parser.parse_args()

    Path(args.watch_dir).mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)

    flagged_logger = JsonlEventLogger(ROOT / "logs" / "flagged_events.jsonl")
    on_event = build_on_event(flagged_logger, use_ai=not args.no_ai)

    file_event_logger = JsonlEventLogger(ROOT / "logs" / "file_events.jsonl")
    observer = start_file_collector(args.watch_dir, file_event_logger, on_event=on_event)
    logger.info("File collector running. Watching: %s", args.watch_dir)

    if not args.no_http:
        http_event_logger = JsonlEventLogger(ROOT / "logs" / "http_events.jsonl")
        app = create_app(http_event_logger, on_event=on_event)
        http_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=args.http_port, use_reloader=False),
            daemon=True,
        )
        http_thread.start()
        logger.info("HTTP collector running on http://127.0.0.1:%d/upload (loopback only)", args.http_port)

    if not args.no_ai:
        logger.info("AI review enabled: %s @ %s (timeout %.0fs)", OLLAMA_MODEL, OLLAMA_HOST, OLLAMA_TIMEOUT_SECONDS)

    logger.info("Pipeline running. Drop files into %s or POST to /upload. Ctrl+C to stop.", args.watch_dir)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
