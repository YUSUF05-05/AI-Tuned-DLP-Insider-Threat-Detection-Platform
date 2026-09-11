"""
collectors/http_collector.py  (Phase 3.3 — Outbound HTTP Activity Monitoring)

This module is BOTH halves of the lab's HTTP telemetry, deliberately kept
together because they are two views of the same request:

  1. The "controlled HTTP destination" — a local Flask app standing in for
     an external exfiltration endpoint (e.g. a personal cloud-storage
     upload, a paste site, a webhook). The synthetic test client in
     simulations/http_exfil_simulator.py sends traffic here instead of to
     any real external service — see Rule 3 in the project's ethical
     constraints (no real exfiltration, ever).
  2. The collector — every request that hits the destination is captured as
     a DLPEvent (method, path, size, content-type, simulated user/process
     context, and — subject to the same capture thresholds as the other
     collectors — a content excerpt for detection).

SECURITY NOTE: this server MUST bind to 127.0.0.1 only (see run_server()
below and docs/TELEMETRY.md "Network Exposure"). Binding to 0.0.0.0 would
turn a lab fixture into a real endpoint reachable from the network, which is
both a needless risk and outside this project's defensive-only scope.

"User/process context where possible": a real endpoint DLP agent can read
this from the OS (which process opened the socket, which user owns that
process). A local Flask server only sees an HTTP request, so the synthetic
test client tags requests with `X-DLP-Simulated-User` / `X-DLP-Simulated-Process`
headers to stand in for that OS-level context during lab testing; production
deployment would replace this with a real host-side hook (out of scope here).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional

import yaml
from flask import Flask, request, jsonify

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("http_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


def create_app(
    event_logger: JsonlEventLogger,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
) -> Flask:
    """
    Factory so tests can build an app around a temp-directory event logger
    without needing a real network port (Flask's test_client() drives the
    WSGI app in-process).
    """
    app = Flask(__name__)
    max_bytes, excerpt_max_chars = _load_capture_thresholds(policy_path)

    @app.route("/upload", methods=["POST"])
    def upload():
        body = request.get_data() or b""
        size_bytes = len(body)

        excerpt = None
        if 0 < size_bytes <= max_bytes:
            try:
                excerpt = body.decode("utf-8")[:excerpt_max_chars]
            except UnicodeDecodeError:
                excerpt = body.decode("latin-1", errors="replace")[:excerpt_max_chars]

        dlp_event = build_event(
            source="http",
            event_type="http_request",
            object_ref=request.path,
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={
                "method": request.method,
                "content_type": request.headers.get("Content-Type", ""),
                "remote_addr": request.remote_addr,
                "simulated_user": request.headers.get("X-DLP-Simulated-User", "unknown"),
                "simulated_process": request.headers.get("X-DLP-Simulated-Process", "unknown"),
            },
        )
        event_logger.write(dlp_event)
        logger.info(
            "http_request: %s %s (%d bytes, user=%s)",
            request.method, request.path, size_bytes,
            dlp_event.raw_metadata["simulated_user"],
        )
        if on_event:
            on_event(dlp_event)

        return jsonify({"status": "received", "event_id": dlp_event.event_id, "bytes": size_bytes}), 200

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return jsonify({"status": "ok"}), 200

    return app


def run_server(
    event_logger: JsonlEventLogger,
    host: str = "127.0.0.1",
    port: int = 8765,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
):
    """
    Run the collector as a real server. host defaults to loopback-only —
    do not change this to 0.0.0.0 (see module docstring "SECURITY NOTE").
    """
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            "Refusing to bind the lab HTTP collector to a non-loopback address. "
            "This is a deliberate guardrail, not a bug — see docs/TELEMETRY.md."
        )
    app = create_app(event_logger, on_event=on_event)
    app.run(host=host, port=port)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    elogger = JsonlEventLogger("./logs/http_events.jsonl")
    run_server(elogger)
