import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.event_schema import JsonlEventLogger  # noqa: E402
from collectors.http_collector import create_app, run_server  # noqa: E402


def test_healthz_endpoint(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    app = create_app(logger)
    client = app.test_client()

    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_upload_logs_event_with_content(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    app = create_app(logger)
    client = app.test_client()

    resp = client.post(
        "/upload",
        data=b"card number 4111111111111111",
        content_type="text/plain",
        headers={"X-DLP-Simulated-User": "alice", "X-DLP-Simulated-Process": "chrome.exe"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "received"
    assert body["bytes"] == len(b"card number 4111111111111111")

    events = logger.read_all()
    assert len(events) == 1
    ev = events[0]
    assert ev["source"] == "http"
    assert ev["event_type"] == "http_request"
    assert ev["object_ref"] == "/upload"
    assert "4111111111111111" in ev["content_excerpt"]
    assert ev["raw_metadata"]["simulated_user"] == "alice"
    assert ev["raw_metadata"]["simulated_process"] == "chrome.exe"


def test_upload_without_simulated_headers_defaults_to_unknown(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    app = create_app(logger)
    client = app.test_client()

    client.post("/upload", data=b"no headers here", content_type="text/plain")
    events = logger.read_all()
    assert events[0]["raw_metadata"]["simulated_user"] == "unknown"


def test_on_event_callback_is_invoked(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    received = []
    app = create_app(logger, on_event=lambda ev: received.append(ev))
    client = app.test_client()

    client.post("/upload", data=b"test payload", content_type="text/plain")
    assert len(received) == 1
    assert received[0].source == "http"


def test_multiple_requests_each_logged_separately(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    app = create_app(logger)
    client = app.test_client()

    client.post("/upload", data=b"first", content_type="text/plain")
    client.post("/upload", data=b"second", content_type="text/plain")
    client.post("/upload", data=b"third", content_type="text/plain")

    events = logger.read_all()
    assert len(events) == 3


def test_run_server_refuses_non_loopback_bind(tmp_path):
    logger = JsonlEventLogger(tmp_path / "http.jsonl")
    with pytest.raises(ValueError, match="loopback"):
        run_server(logger, host="0.0.0.0")
