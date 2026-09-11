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
