"""
ai/ollama_client.py  (Phase 6)

The only module in this project that makes a real network call (to Ollama's
local REST API, loopback only -- see docs/TELEMETRY.md's loopback-only
guardrail on the HTTP collector; the same principle applies here: this talks
to 127.0.0.1, never anywhere else). Wraps prompt_builder + response_validator
into one analyze() call, and is where "timeout handling", "model-unavailable
handling", and "safe fallback" actually get enforced: every failure mode
returns AIAnalysisResult(status="error", ...) rather than raising, so a
broken, slow, or absent Ollama never crashes a pipeline that was working
fine without it through Phases 3-5.

TESTABILITY: the actual HTTP call is dependency-injected (`post_fn`,
defaults to requests.post) for the same reason
collectors/clipboard_collector.py injects its clipboard reader -- it lets
every failure mode (timeout, connection refused, HTTP error status,
malformed envelope) be exercised deterministically without a real Ollama
instance. The live, real-network path is exactly what a caller gets by not
overriding the default.

DEFAULT_TIMEOUT_SECONDS justification: a live test against llama3.2:latest
on real hardware measured load_duration alone at ~9.3s (cold model load,
Ollama's default keep_alive unloads after ~5 min idle so this recurs in any
low-traffic dev loop) plus ~1.3s generation for a short structured response.
45s leaves comfortable margin for slower hardware or a larger model without
being so long a genuinely dead Ollama hangs the pipeline for a long time.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

import requests

from common.event_schema import AIAnalysisResult, DetectionResult
from ai.prompt_builder import build_request
from ai.response_validator import validate

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:latest"
DEFAULT_TIMEOUT_SECONDS = 45.0


def analyze(
    content: str,
    detections: list[DetectionResult],
    host: str = DEFAULT_HOST,
    model: str = DEFAULT_MODEL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    post_fn: Callable[..., "requests.Response"] = requests.post,
) -> AIAnalysisResult:
    """
    Send `content` (with Phase 4 `detections` as context) to Ollama for
    structured review. Never raises -- every failure path returns
    AIAnalysisResult(status="error", error=<specific, actionable reason>).
    """
    if not content or not content.strip():
        return AIAnalysisResult(status="error", error="empty content, nothing to analyze", model=model)

    payload = build_request(content, detections, model=model)
    url = f"{host.rstrip('/')}/api/chat"
    start = time.monotonic()

    try:
        response = post_fn(url, json=payload, timeout=timeout_seconds)
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return AIAnalysisResult(status="error", error=f"timed out after {timeout_seconds}s waiting for {host}",
                                 model=model, duration_ms=elapsed_ms)
    except requests.exceptions.ConnectionError:
        return AIAnalysisResult(status="error",
                                 error=f"could not connect to Ollama at {host} -- is it running? (ollama serve)",
                                 model=model)
    except requests.exceptions.RequestException as exc:
        return AIAnalysisResult(status="error", error=f"request failed: {exc}", model=model)

    elapsed_ms = int((time.monotonic() - start) * 1000)

    if response.status_code == 404:
        return AIAnalysisResult(
            status="error",
            error=f"model '{model}' not found on {host} -- pull it first: ollama pull {model}",
            model=model, duration_ms=elapsed_ms,
        )
    if response.status_code != 200:
        return AIAnalysisResult(
            status="error",
            error=f"Ollama returned HTTP {response.status_code}: {response.text[:200]}",
            model=model, duration_ms=elapsed_ms,
        )

    try:
        envelope = response.json()
    except ValueError:
        return AIAnalysisResult(status="error", error="Ollama response was not valid JSON",
                                 model=model, duration_ms=elapsed_ms)

    message = envelope.get("message") or {}
    raw_content = message.get("content")
    if raw_content is None:
        return AIAnalysisResult(status="error", error="Ollama response missing message.content",
                                 model=model, duration_ms=elapsed_ms)

    actual_model = envelope.get("model", model)
    # Ollama's own total_duration is nanoseconds and more accurate than our
    # wall-clock elapsed_ms (excludes our own request-building overhead);
    # prefer it when present, fall back to elapsed_ms otherwise.
    total_duration_ns = envelope.get("total_duration")
    ollama_duration_ms = int(total_duration_ns / 1_000_000) if total_duration_ns else elapsed_ms

    return validate(raw_content, model=actual_model, duration_ms=ollama_duration_ms)
