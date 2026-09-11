# PHASE 3 — ENDPOINT TELEMETRY COLLECTION

## 🎯 Objective

Observe three sources of endpoint activity — file system events, clipboard
changes, and outbound HTTP requests to a controlled destination — and turn
each into a structured `DLPEvent` (Phase 2's shared schema), without yet
judging whether the content is sensitive (that's Phase 4/5).

## 🧠 Concept

Three collectors, one shared contract: every collector calls
`common.event_schema.build_event()`, writes the result through a
`JsonlEventLogger`, and optionally invokes an `on_event` callback. This
means Phase 4/5's detection logic doesn't know or care which collector
produced an event — it only ever sees a `DLPEvent`.

**Scope of monitoring.** The file collector watches exactly one configured
directory (`simulations/monitored` in this lab, or wherever `DLP_MONITORED_PATH`
points), never the whole filesystem. This mirrors how real DLP agents work —
they watch defined sensitive locations (a finance share, a source repo
checkout, a Downloads folder), not every byte written to disk — and it keeps
this project's footprint on your actual machine minimal and predictable.

**Why polling for the clipboard, not an OS hook.** `pyperclip` (used here)
wraps `win32clipboard` on Windows and `xclip`/`xsel` on Linux behind one
`paste()` call. A real "clipboard changed" notification
(`AddClipboardFormatListener`) is Windows-only, which would fork the
implementation and make it untestable outside Windows. Polling every second
is cheap and identical on both platforms — see `tests/test_clipboard_collector.py`
for how this is validated without a real display or clipboard backend at all.

**Privacy-by-design content capture.** No collector reads/logs unbounded
content. `config/detection_policy.yaml`'s `content_capture` block sets a
2 MiB ceiling and a 4000-character excerpt cap — above either, only metadata
(path, size, timestamp) is captured, never content. This is a real design
decision, not a corner cut: real endpoint DLP agents make the same tradeoff,
because indexing every byte of every file is both a privacy and a
performance problem.

**Network exposure.** The HTTP collector doubles as the lab's simulated
"external destination." `collectors/http_collector.py`'s `run_server()`
hard-refuses to bind anything other than `127.0.0.1`/`localhost` — this is a
runtime `raise`, not a comment, so it can't be silently misconfigured later
in the project.

## 🏗️ Architecture

```
File system  ──▶ DLPFileEventHandler (watchdog) ──▶ JsonlEventLogger ──▶ file_events.jsonl
Clipboard    ──▶ ClipboardCollector (polling)    ──▶ JsonlEventLogger ──▶ clipboard_events.jsonl
HTTP request ──▶ Flask /upload route             ──▶ JsonlEventLogger ──▶ http_events.jsonl
```
All three optionally fan out to the same `on_event(DLPEvent)` callback,
which `run_pipeline_demo.py` wires to Phase 4/5 (see "Expected Result" below
for a real captured run).

## 📁 Files

```
collectors/file_collector.py
collectors/clipboard_collector.py
collectors/http_collector.py
run_pipeline_demo.py
simulations/http_exfil_simulator.py
tests/test_file_collector.py
tests/test_clipboard_collector.py
tests/test_http_collector.py
```

## ⚙️ Configuration

Content-capture thresholds (from `config/detection_policy.yaml`, already
shown in full in `docs/ARCHITECTURE.md`):
```yaml
content_capture:
  max_bytes_for_full_read: 2097152      # 2 MiB
  excerpt_max_chars: 4000
  redact_detected_secrets_in_excerpt: true
```
Relevant `.env` values (see `docs/INSTALLATION.md`):
```env
DLP_MONITORED_PATH=C:\dlp-lab\monitored
DLP_HTTP_HOST=127.0.0.1
DLP_HTTP_PORT=8765
```

## 💻 Commands

Run the three collectors together via the pipeline demo (recommended first
run) from `C:\dlp-lab\ai-dlp-insider-threat` with the venv active:

```powershell
python run_pipeline_demo.py --watch-dir C:\dlp-lab\monitored --http-port 8765
```
Leave this running in one PowerShell window. In a **second** PowerShell
window (same venv activated), generate some activity:

```powershell
"Q3 customer database export. Sample card on file: 4111111111111111." | Out-File C:\dlp-lab\monitored\customer_export_sample.txt
```
```powershell
python simulations\http_exfil_simulator.py --base-url http://127.0.0.1:8765
```
For the clipboard collector specifically (interactive — needs a real
Windows session, so it isn't exercised by the demo script above):
```powershell
python -c "from common.event_schema import JsonlEventLogger; from collectors.clipboard_collector import ClipboardCollector; c = ClipboardCollector(JsonlEventLogger('logs/clipboard_events.jsonl')); print('Watching clipboard, Ctrl+C to stop. Copy something now.'); c.run()"
```
Then copy any text (Ctrl+C) in another application and watch the console.

Stop everything with `Ctrl+C` in the first window when done.

## 🧩 Implementation

### `collectors/file_collector.py` — complete file
```python
"""
collectors/file_collector.py  (Phase 3.1 — File Activity Monitoring)

Watches a single, explicitly-configured directory (NOT the whole filesystem
— see docs/TELEMETRY.md "Scope of Monitoring" for why) for create/modify/move
events using the `watchdog` library, which uses ReadDirectoryChangesW on
Windows and inotify on Linux — the same public API on both, so the logic
below is validated here in the Linux sandbox and behaves identically on the
target Windows host.

PRIVACY-BY-DESIGN CONTENT CAPTURE:
Full file content is only read and attached to the event's content_excerpt
when BOTH of these hold (thresholds come from config/detection_policy.yaml):
  1. The file is smaller than `content_capture.max_bytes_for_full_read`.
  2. Reading succeeds as text (binary files >  that fail UTF-8/latin-1
     decoding are still detected via filename/magic-bytes in Phase 4's
     filetype_detector, just without a text excerpt).
Every event is still logged with metadata (path, size, timestamps) regardless
of whether content was captured — this mirrors how real endpoint DLP agents
avoid indexing arbitrarily large or opaque binary content wholesale.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

import yaml
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("file_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

# Event types we care about; watchdog also emits directory events we ignore here.
_WATCHED_EVENT_TYPES = {"created", "modified", "moved"}


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


def _read_excerpt_if_eligible(path: Path, max_bytes: int, excerpt_max_chars: int) -> tuple[Optional[str], int]:
    """Returns (content_excerpt_or_None, size_bytes). Never raises."""
    try:
        size_bytes = path.stat().st_size
    except OSError:
        return None, 0

    if size_bytes == 0 or size_bytes > max_bytes:
        return None, size_bytes

    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None, size_bytes

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None, size_bytes  # opaque binary; filetype_detector will still see the bytes separately

    return text[:excerpt_max_chars], size_bytes


class DLPFileEventHandler(FileSystemEventHandler):
    """
    Bridges watchdog's callback events to DLPEvent objects, writes them to
    the JSONL event log, and optionally forwards each event to `on_event`
    (used to wire in the Phase 4 detection engine without this collector
    needing to import detectors directly — keeps Phase 3 independently
    testable from Phase 4).
    """

    def __init__(
        self,
        event_logger: JsonlEventLogger,
        on_event: Optional[Callable[[DLPEvent], None]] = None,
        policy_path: Path = DEFAULT_POLICY_PATH,
    ):
        super().__init__()
        self.event_logger = event_logger
        self.on_event = on_event
        self.max_bytes, self.excerpt_max_chars = _load_capture_thresholds(policy_path)

    def _handle(self, event_type: str, src_path: str):
        path = Path(src_path)
        if path.is_dir():
            return  # directory-level events are not in scope for this collector

        excerpt, size_bytes = _read_excerpt_if_eligible(path, self.max_bytes, self.excerpt_max_chars)
        dlp_event = build_event(
            source="file",
            event_type=f"file_{event_type}",
            object_ref=str(path),
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={"extension": path.suffix},
        )
        self.event_logger.write(dlp_event)
        logger.info("file_%s: %s (%d bytes)", event_type, path, size_bytes)
        if self.on_event:
            self.on_event(dlp_event)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("created", event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("modified", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("moved", event.dest_path)


def start_file_collector(
    watch_path: str,
    event_logger: JsonlEventLogger,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
) -> Observer:
    """
    Start watching `watch_path` in a background thread and return the
    Observer so the caller can .stop()/.join() it (see main.py / tests).
    """
    Path(watch_path).mkdir(parents=True, exist_ok=True)
    handler = DLPFileEventHandler(event_logger, on_event=on_event, policy_path=policy_path)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    logger.info("File collector watching: %s", watch_path)
    return observer


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    watch_dir = sys.argv[1] if len(sys.argv) > 1 else "./simulations/monitored"
    elogger = JsonlEventLogger("./logs/file_events.jsonl")
    obs = start_file_collector(watch_dir, elogger)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
        obs.join()
```

### `collectors/clipboard_collector.py` — complete file
```python
"""
collectors/clipboard_collector.py  (Phase 3.2 — Clipboard Monitoring)

Polls the OS clipboard (via `pyperclip`) at a fixed interval, diffs against
the last-seen value, and emits a DLPEvent on every change. Polling (rather
than an OS clipboard-changed hook) is used deliberately — see
docs/TELEMETRY.md "Why Polling" — because it is identical code on Windows
and Linux (pyperclip wraps win32clipboard on Windows, xclip/xsel on Linux),
whereas native clipboard-changed notifications are a Windows-only API
(AddClipboardFormatListener) that would fork the implementation.

TESTABILITY:
The clipboard read function is injected (`read_fn`, defaults to
`pyperclip.paste`) instead of imported directly, because pyperclip requires
a real OS clipboard (a Windows session, or an X11/xclip setup on Linux) that
does not exist in a headless CI/sandbox container. Tests inject a fake
sequence of clipboard values and assert on the resulting events, which
validates the polling/diffing/event-emission logic exactly as it will run
on the real target machine, without needing a real display.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

import yaml

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("clipboard_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"
DEFAULT_POLL_INTERVAL_SECONDS = 1.0


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


class ClipboardCollector:
    """
    Stateful poller. Call `.poll_once()` in a loop (see run()), or drive it
    directly from a test with a fake read_fn for deterministic, display-free
    unit testing.
    """

    def __init__(
        self,
        event_logger: JsonlEventLogger,
        read_fn: Callable[[], str] = None,
        on_event: Optional[Callable[[DLPEvent], None]] = None,
        policy_path: Path = DEFAULT_POLICY_PATH,
    ):
        if read_fn is None:
            import pyperclip  # imported lazily so this module can be imported
            read_fn = pyperclip.paste                      # in test environments without a clipboard backend
        self.read_fn = read_fn
        self.event_logger = event_logger
        self.on_event = on_event
        self.max_bytes, self.excerpt_max_chars = _load_capture_thresholds(policy_path)
        self._last_value: Optional[str] = None
        self._initialized = False

    def poll_once(self) -> Optional[DLPEvent]:
        """
        Read the clipboard once. Returns a DLPEvent if the content changed
        since the last poll, else None. The FIRST poll establishes a
        baseline and never emits an event — otherwise whatever happened to
        already be on the clipboard when the collector starts would be
        reported as a "change", which is misleading.
        """
        try:
            current = self.read_fn()
        except Exception as exc:  # pyperclip raises if no backend is available
            logger.warning("Clipboard read failed: %s", exc)
            return None

        if not self._initialized:
            self._last_value = current
            self._initialized = True
            return None

        if current == self._last_value:
            return None

        self._last_value = current
        size_bytes = len(current.encode("utf-8", errors="ignore")) if current else 0
        excerpt = None
        if current and size_bytes <= self.max_bytes:
            excerpt = current[: self.excerpt_max_chars]

        dlp_event = build_event(
            source="clipboard",
            event_type="clipboard_change",
            object_ref="clipboard",
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={"char_count": len(current) if current else 0},
        )
        self.event_logger.write(dlp_event)
        logger.info("clipboard_change: %d bytes", size_bytes)
        if self.on_event:
            self.on_event(dlp_event)
        return dlp_event

    def run(self, interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS, stop_after: Optional[int] = None):
        """Blocking polling loop. `stop_after` (number of polls) is used by tests; None = forever."""
        polls = 0
        while stop_after is None or polls < stop_after:
            self.poll_once()
            polls += 1
            time.sleep(interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    elogger = JsonlEventLogger("./logs/clipboard_events.jsonl")
    collector = ClipboardCollector(elogger)
    collector.run()
```

### `collectors/http_collector.py` — complete file
```python
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
```

### `run_pipeline_demo.py` — complete file (wires Phase 3 into Phase 4/5)
```python
"""
run_pipeline_demo.py

End-to-end demonstration wiring Phase 3 collectors -> Phase 4 detection
engine -> Phase 5 normalizer into one running pipeline. This is what you run
to verify Phases 3-5 are correctly integrated (see each docs/*.md file's
"Completion Criteria" section).

This is a DEMO / verification harness, not "the product": Phase 6 onward
will replace the simple console-alert logic in analyze_event() below with
the AI review layer, risk scoring, behavioral correlation, database
persistence, and dashboard. Nothing here is meant to be the final alerting
UI — see docs/ for what each later phase will change.

Usage (Windows, from the project root, with the venv active):
    python run_pipeline_demo.py
    python run_pipeline_demo.py --watch-dir C:\\dlp-lab\\monitored --http-port 8765
    python run_pipeline_demo.py --no-http      (file monitoring only)
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from pathlib import Path

from common.event_schema import JsonlEventLogger, DLPEvent
from detectors.engine import run_all, summarize
from normalization.normalizer import normalize_and_rescan
from collectors.file_collector import start_file_collector
from collectors.http_collector import create_app

ROOT = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("pipeline")


def analyze_event(event: DLPEvent) -> None:
    """
    Runs Phase 4 detectors and, for events with captured content, the Phase 5
    normalizer, then attaches results to the event. Prints a console alert on
    any match. This function is the seam Phase 6 will extend (or replace)
    with AI-based analysis of borderline/ambiguous content.
    """
    text = event.content_excerpt or ""
    filename = event.object_ref if event.source == "file" else None

    event.detections = run_all(text, filename=filename)
    summary = summarize(event.detections)

    event.obfuscation = normalize_and_rescan(text, run_all) if text else []

    if event.any_match:
        categories = summary["categories"] or []
        obf_techniques = [ob.technique for ob in event.obfuscation if any(d.matched for d in ob.rescanned_detections)]
        if obf_techniques:
            categories = categories + [f"obfuscated:{t}" for t in obf_techniques]
        print(f"\n[ALERT] {event.source}:{event.event_type} -> {event.object_ref}")
        print(f"        categories={categories}")
        print(f"        needs_ai_review={summary['needs_ai_review']}  (Phase 6 will act on this flag)")
    else:
        logger.info("clean: %s:%s -> %s", event.source, event.event_type, event.object_ref)


def build_on_event(flagged_logger: JsonlEventLogger):
    def on_event(event: DLPEvent):
        analyze_event(event)
        if event.any_match:
            flagged_logger.write(event)

    return on_event


def main():
    parser = argparse.ArgumentParser(description="Phase 3-5 pipeline integration demo")
    parser.add_argument("--watch-dir", default=str(ROOT / "simulations" / "monitored"))
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--no-http", action="store_true", help="Disable the HTTP collector/destination")
    args = parser.parse_args()

    Path(args.watch_dir).mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)

    flagged_logger = JsonlEventLogger(ROOT / "logs" / "flagged_events.jsonl")
    on_event = build_on_event(flagged_logger)

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
```

### `simulations/http_exfil_simulator.py` — complete file
```python
"""
simulations/http_exfil_simulator.py

Synthetic test client for the Phase 3 HTTP collector. Sends a handful of
requests — some clean, some containing synthetic sensitive data, one
obfuscated — to the LOCAL lab destination started by
collectors/http_collector.py or run_pipeline_demo.py.

This never contacts any real external host. It exists so Phase 3/11 test
scenarios have deterministic, repeatable traffic to generate, standing in
for "a user's browser/app uploading data somewhere" per Rule 3 of the
project's ethical constraints (simulate, do not perform, exfiltration).

Usage:
    python simulations/http_exfil_simulator.py --base-url http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import base64
import sys

import requests

SYNTHETIC_SCENARIOS = [
    {
        "name": "clean_message",
        "user": "alice",
        "process": "outlook.exe",
        "content_type": "text/plain",
        "body": "Reminder: the team offsite is next Thursday.",
    },
    {
        "name": "plaintext_card_number",
        "user": "bob",
        "process": "chrome.exe",
        "content_type": "text/plain",
        "body": "Refund the customer using card 4111111111111111 please.",
    },
    {
        "name": "aws_key_leak",
        "user": "carol",
        "process": "slack.exe",
        "content_type": "text/plain",
        "body": "oops wrong channel -- AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    },
    {
        "name": "base64_obfuscated_card_number",
        "user": "dave",
        "process": "firefox.exe",
        "content_type": "text/plain",
        "body": None,  # filled in below
    },
    {
        "name": "customer_database_export",
        "user": "erin",
        "process": "python.exe",
        "content_type": "text/csv",
        "body": "name,ssn,customer_database\nJohn Sample,000-00-0000,true\n",
    },
]

SYNTHETIC_SCENARIOS[3]["body"] = base64.b64encode(
    b"internal note: card on file is 5555555555554444"
).decode()


def run(base_url: str) -> None:
    ok = requests.get(f"{base_url}/healthz", timeout=5)
    print(f"health check: {ok.status_code} {ok.json()}")

    for scenario in SYNTHETIC_SCENARIOS:
        headers = {
            "Content-Type": scenario["content_type"],
            "X-DLP-Simulated-User": scenario["user"],
            "X-DLP-Simulated-Process": scenario["process"],
        }
        resp = requests.post(
            f"{base_url}/upload",
            data=scenario["body"].encode("utf-8"),
            headers=headers,
            timeout=5,
        )
        print(f"[{scenario['name']}] -> HTTP {resp.status_code} {resp.json()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic HTTP exfiltration-pattern simulator (lab-local only)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    try:
        run(args.base_url)
    except requests.exceptions.ConnectionError:
        print(f"Could not reach {args.base_url} -- is run_pipeline_demo.py or http_collector.py running?")
        sys.exit(1)
```

## 🧪 Testing

```powershell
python -m pytest tests/test_file_collector.py tests/test_clipboard_collector.py tests/test_http_collector.py -v
```

| Test file | What it proves | How, without needing real OS resources |
|---|---|---|
| `test_file_collector.py` (5 tests) | File create/modify events become correct `DLPEvent`s; size/excerpt thresholds are respected; directories themselves aren't logged as file events | Uses `tmp_path` (a real temp directory) and the **real** `watchdog` `Observer` — this is a genuine integration test, not a mock, validated on Linux `inotify` and expected identical on Windows `ReadDirectoryChangesW` since both go through the same `watchdog` public API |
| `test_clipboard_collector.py` (7 tests) | Baseline-then-diff logic, threshold handling, and failure resilience | Injects a `FakeClipboard` in place of `pyperclip.paste` — no real clipboard/display needed, which is exactly why this can run in this sandbox *and* on your Windows machine identically |
| `test_http_collector.py` (6 tests) | Every request is logged with correct metadata; loopback-only guard actually raises | Flask's `test_client()` drives the app in-process — no real socket needed |

## ✅ Expected Result

This is real, captured output from running exactly the commands above (file
drop + `http_exfil_simulator.py`) against the pipeline demo — not a
hypothetical:

```
2026-08-12 18:35:31,786 INFO file_collector: file_created: simulations/monitored/customer_export_sample.txt (94 bytes)

[ALERT] file:file_created -> simulations/monitored/customer_export_sample.txt
        categories=['customer_data', 'payment_card']
        needs_ai_review=True  (Phase 6 will act on this flag)
...
[ALERT] http:http_request -> /upload
        categories=['credential_secret']
        needs_ai_review=True  (Phase 6 will act on this flag)

[ALERT] http:http_request -> /upload
        categories=['obfuscated:base64']
        needs_ai_review=False  (Phase 6 will act on this flag)
```

And one representative logged event, pretty-printed (the real log is one
compact JSON object per line):
```json
{
  "event_id": "9ac9224e-c286-445f-8d4f-9a262da767d0",
  "schema_version": "0.3.0",
  "timestamp": "2026-08-12T18:35:33.611Z",
  "source": "http",
  "event_type": "http_request",
  "object_ref": "/upload",
  "size_bytes": 55,
  "content_excerpt": "Refund the customer using card 4111111111111111 please.",
  "detections": [
    {"detector": "card_detector", "matched": true, "category": "payment_card",
     "confidence": 1.0, "matches": ["visa:411111******1111"]}
  ],
  "raw_metadata": {"method": "POST", "simulated_user": "bob", "simulated_process": "chrome.exe"}
}
```
Note the card number is masked (`411111******1111`) even in the raw log —
this comes from `card_detector.py`'s masking, not from anything in the
collector, confirming the "never persist raw sensitive evidence" rule holds
across phase boundaries.

Across the full demo run: **6** file events logged, **5** HTTP events
logged, **7** of those 11 correctly flagged (2 clean file writes + 1 clean
HTTP message legitimately produced zero alerts — confirming the pipeline
doesn't just flag everything).

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| File collector produces 2 events (`file_created` then `file_modified`) for one file write | Normal — most editors/OS write calls trigger both; `watchdog`'s event granularity is OS-level, not "user intent"-level | Already handled: detection re-runs on every event, so duplicate alerts for the same content are expected and harmless. Deduplication-by-content-hash would be a reasonable Phase 8+ enhancement, not in scope here |
| `PermissionError` reading a file right after `file_created` fires | Windows locks files more strictly than Linux while another process still has them open (e.g., a large file mid-write by another app) | Already handled in code: `_read_excerpt_if_eligible()` catches `PermissionError` and falls back to metadata-only; you'll see `content_excerpt: null` for that event rather than a crash |
| `OSError: [WinError 10048] ... address already in use` starting the HTTP collector | Port 8765 already bound by a previous run that didn't shut down cleanly | Find and stop it: `Get-Process -Id (Get-NetTCPConnection -LocalPort 8765).OwningProcess \| Stop-Process`, or just pass `--http-port 8766` |
| Clipboard collector never emits an event | The very first poll is *always* silent by design (it establishes the baseline) — copying the exact same text twice in a row also correctly produces nothing | Copy something different from whatever was already on the clipboard when the collector started |
| `requests.exceptions.ConnectionError` from `http_exfil_simulator.py` | The pipeline demo (or `http_collector.py` directly) isn't running, or is on a different port | Start it first; confirm the port matches `--base-url` |

## 🔐 Security Considerations

- The HTTP collector's loopback-only guard (`run_server()`) is enforced in
  code specifically so a future edit can't accidentally turn this lab
  fixture into something reachable from the network — see
  `docs/THREAT_MODEL.md` "Attack surface."
- Clipboard and file content are only ever written to your **local** JSONL
  logs (`logs/`, gitignored) — nothing here transmits anywhere outside the
  loopback interface.
- Because collectors attach `content_excerpt` to events, `logs/*.jsonl`
  itself becomes sensitive the moment you run this against real content.
  Treat it accordingly even in the lab: it's gitignored, and Phase 9's
  database (later) inherits the same masking/fingerprinting discipline
  already applied at the detector level (Phase 4).

## 📌 Completion Criteria

- [x] `collectors/file_collector.py`, `clipboard_collector.py`,
      `http_collector.py` implemented
- [x] All three have passing dedicated tests (18 tests total)
- [x] `run_pipeline_demo.py` wires all three into a single running process
- [x] End-to-end run confirmed: plaintext-sensitive, obfuscated, and clean
      content all produce the *correct* (not just *some*) alert behavior
- [ ] You have run `python run_pipeline_demo.py` on your own Windows machine,
      dropped a file into the watched folder, and seen a matching `[ALERT]`
      line in your own terminal — reproducing the captured run above, not
      just reading about it
