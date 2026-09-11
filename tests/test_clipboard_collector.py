import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import JsonlEventLogger  # noqa: E402
from collectors.clipboard_collector import ClipboardCollector  # noqa: E402


class FakeClipboard:
    """Injected in place of pyperclip.paste so tests don't need a real OS clipboard."""

    def __init__(self, sequence: list[str]):
        self._sequence = sequence
        self._index = 0

    def __call__(self) -> str:
        value = self._sequence[min(self._index, len(self._sequence) - 1)]
        self._index += 1
        return value


def test_first_poll_establishes_baseline_and_emits_nothing(tmp_path):
    fake = FakeClipboard(["initial clipboard content"])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)

    event = collector.poll_once()
    assert event is None
    assert logger.read_all() == []


def test_unchanged_value_emits_no_event(tmp_path):
    fake = FakeClipboard(["same value", "same value", "same value"])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)

    collector.poll_once()  # baseline
    ev2 = collector.poll_once()
    ev3 = collector.poll_once()
    assert ev2 is None
    assert ev3 is None
    assert logger.read_all() == []


def test_changed_value_emits_event_with_content(tmp_path):
    fake = FakeClipboard(["first value", "SECOND VALUE with card 4111111111111111"])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)

    collector.poll_once()  # baseline, no event
    event = collector.poll_once()

    assert event is not None
    assert event.source == "clipboard"
    assert event.event_type == "clipboard_change"
    assert "4111111111111111" in event.content_excerpt
    logged = logger.read_all()
    assert len(logged) == 1


def test_multiple_changes_produce_multiple_events(tmp_path):
    fake = FakeClipboard(["v1", "v2", "v3", "v4"])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)

    collector.poll_once()  # baseline = v1
    collector.poll_once()  # v1 -> v2, event
    collector.poll_once()  # v2 -> v3, event
    collector.poll_once()  # v3 -> v4, event

    logged = logger.read_all()
    assert len(logged) == 3


def test_content_over_threshold_is_logged_without_excerpt(tmp_path):
    big_value = "x" * 1000
    fake = FakeClipboard(["baseline", big_value])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)
    # override threshold to something small for the test
    collector.max_bytes = 100

    collector.poll_once()  # baseline
    event = collector.poll_once()

    assert event is not None
    assert event.content_excerpt is None
    assert event.size_bytes == 1000  # metadata still captured even without content


def test_read_failure_does_not_crash_collector(tmp_path):
    def broken_read():
        raise RuntimeError("no clipboard backend available in this environment")

    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=broken_read)

    event = collector.poll_once()  # must not raise
    assert event is None


def test_run_stop_after_limits_number_of_polls(tmp_path):
    fake = FakeClipboard(["a", "b", "c", "d", "e"])
    logger = JsonlEventLogger(tmp_path / "clip.jsonl")
    collector = ClipboardCollector(logger, read_fn=fake)

    collector.run(interval_seconds=0, stop_after=5)
    # baseline "a", then b,c,d,e each differ from previous -> 4 events
    assert len(logger.read_all()) == 4
