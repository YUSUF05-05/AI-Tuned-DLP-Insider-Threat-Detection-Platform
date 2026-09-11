import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import JsonlEventLogger  # noqa: E402
from collectors.file_collector import (  # noqa: E402
    start_file_collector,
    _read_excerpt_if_eligible,
)


def _wait_for_events(log_path: Path, min_count: int, timeout: float = 5.0) -> list[dict]:
    """Poll the JSONL log until at least min_count events appear or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log_path.exists():
            lines = [l for l in log_path.read_text().splitlines() if l.strip()]
            if len(lines) >= min_count:
                return [json.loads(l) for l in lines]
        time.sleep(0.1)
    if log_path.exists():
        return [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    return []


def test_read_excerpt_respects_size_threshold(tmp_path):
    small_file = tmp_path / "small.txt"
    small_file.write_text("hello world")
    excerpt, size = _read_excerpt_if_eligible(small_file, max_bytes=1024, excerpt_max_chars=4000)
    assert excerpt == "hello world"
    assert size == len("hello world")


def test_read_excerpt_skips_files_over_threshold(tmp_path):
    big_file = tmp_path / "big.txt"
    big_file.write_text("x" * 2000)
    excerpt, size = _read_excerpt_if_eligible(big_file, max_bytes=1000, excerpt_max_chars=4000)
    assert excerpt is None
    assert size == 2000  # size is still reported even though content wasn't captured


def test_read_excerpt_truncates_to_max_chars(tmp_path):
    f = tmp_path / "long.txt"
    f.write_text("a" * 500)
    excerpt, size = _read_excerpt_if_eligible(f, max_bytes=10_000, excerpt_max_chars=50)
    assert len(excerpt) == 50


def test_end_to_end_file_created_event_is_logged(tmp_path):
    watch_dir = tmp_path / "monitored"
    log_path = tmp_path / "file_events.jsonl"
    elogger = JsonlEventLogger(log_path)

    observer = start_file_collector(str(watch_dir), elogger)
    try:
        time.sleep(0.3)  # let the observer fully start before writing
        (watch_dir / "notes.txt").write_text("card number 4111111111111111")
        events = _wait_for_events(log_path, min_count=1)
    finally:
        observer.stop()
        observer.join(timeout=5)

    assert len(events) >= 1
    created_events = [e for e in events if e["event_type"] == "file_created"]
    assert len(created_events) >= 1
    ev = created_events[0]
    assert ev["source"] == "file"
    assert "notes.txt" in ev["object_ref"]
    assert ev["content_excerpt"] is not None
    assert "4111111111111111" in ev["content_excerpt"]
    assert ev["size_bytes"] > 0


def test_directory_creation_is_not_logged_as_file_event(tmp_path):
    watch_dir = tmp_path / "monitored"
    log_path = tmp_path / "file_events.jsonl"
    elogger = JsonlEventLogger(log_path)

    observer = start_file_collector(str(watch_dir), elogger)
    try:
        time.sleep(0.3)
        (watch_dir / "a_subdirectory").mkdir()
        (watch_dir / "real_file.txt").write_text("trigger at least one real event")
        events = _wait_for_events(log_path, min_count=1)
    finally:
        observer.stop()
        observer.join(timeout=5)

    for e in events:
        assert "a_subdirectory" not in e["object_ref"] or not e["object_ref"].endswith("a_subdirectory")
