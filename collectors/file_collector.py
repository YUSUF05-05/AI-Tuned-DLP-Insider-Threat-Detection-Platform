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
