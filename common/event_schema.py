"""
common/event_schema.py

Shared event data model used by every collector (Phase 3), the deterministic
detection engine (Phase 4), and the normalization layer (Phase 5).

WHY THIS MODULE EXISTS (architectural decision, documented in docs/ARCHITECTURE.md):
The original project structure did not include a shared "common/" package.
It was added deliberately because collectors, detectors, and the normalizer
all need to produce and pass around the same event shape. Without a shared
schema, each module would invent its own dict keys, and Phase 9 (database
ingestion) would need brittle, module-specific parsing for each source.
Centralizing it here means:
  - One canonical field set for the whole pipeline.
  - Phase 4/5 can enrich an event produced by Phase 3 without guessing keys.
  - Phase 9's database schema can map 1:1 onto this dataclass later.

SCHEMA EVOLUTION NOTE:
This is the Phase 3-5 subset of the event schema. Fields that depend on later
phases (ai_analysis, risk_score, correlation_id, pci_dss_relevant, etc.) are
intentionally NOT included yet — they will be added when Phases 6-9 are
implemented, so as not to fabricate data this stage of the pipeline cannot
actually produce. Every event emitted in Phases 3-5 is valid, forward-compatible
JSON that later phases can extend.
"""

from __future__ import annotations

import getpass
import json
import os
import socket
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


SCHEMA_VERSION = "0.5.0"  # bumped when fields change shape; 0.4.0 = Phase 6 adds ai_analysis, 0.5.0 = Phase 7 adds risk_assessment


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_event_id() -> str:
    """Generate a unique event ID (UUID4)."""
    return str(uuid.uuid4())


def current_user() -> str:
    """
    Best-effort current OS username.
    getpass.getuser() works on both Windows and Linux; it is wrapped because
    it can raise on some minimal/headless environments (used here for the
    Linux test sandbox as well as the target Windows host).
    """
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def current_host() -> str:
    """Best-effort local hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


@dataclass
class DetectionResult:
    """
    One deterministic detector's verdict on a piece of content (Phase 4).
    A single event can carry multiple DetectionResults (one per detector run).
    """
    detector: str                     # e.g. "card_detector", "swift_detector"
    matched: bool
    category: Optional[str] = None    # e.g. "payment_card", "secret", "keyword:financial"
    confidence: float = 0.0           # 0.0 - 1.0, deterministic detectors use 1.0 or 0.0 mostly
    matches: list[str] = field(default_factory=list)   # redacted/partial match evidence
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ObfuscationResult:
    """
    Result of the Phase 5 normalization/obfuscation pass on a piece of content.
    """
    technique: str                    # "base64" | "url_encoding" | "json_embedded" | "gzip" | "zip" | "none"
    found: bool
    layers: int = 0                   # how many nested encodings were unwrapped
    decoded_excerpt: Optional[str] = None  # short, redacted excerpt of decoded content
    rescanned_detections: list[DetectionResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["rescanned_detections"] = [r.to_dict() if isinstance(r, DetectionResult) else r
                                      for r in self.rescanned_detections]
        return d


@dataclass
class AIAnalysisResult:
    """
    Result of Phase 6's local-LLM review of content the deterministic layer
    already flagged as ambiguous (detectors.engine.needs_ai_review() == True).
    Unlike DetectionResult (one verdict per pattern), this is a single
    holistic judgment from the model.

    This object only ever exists when AI review was actually attempted --
    DLPEvent.ai_analysis stays None for the large majority of events that
    never crossed the needs_ai_review() threshold, the same way
    content_excerpt stays None for content that was never captured.
    """
    status: str                        # "ok" | "error"
    is_sensitive: Optional[bool] = None
    category: Optional[str] = None
    confidence: float = 0.0
    reasoning: Optional[str] = None
    model: Optional[str] = None        # which model actually answered, from Ollama's own response
    duration_ms: Optional[int] = None  # Ollama's total_duration, converted to ms
    error: Optional[str] = None        # populated only when status == "error"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    """
    Result of Phase 7's hybrid risk scoring, optionally adjusted by Phase 8's
    behavioral correlation. Two callers, one scoring function
    (scoring.risk_engine.compute_risk) -- see that module's docstring for
    why: Phase 7 runs before Phase 8 exists yet for a given event, computing
    a base_score with behavioral_adjustment=0 (neutral); once Phase 8 has
    correlated the event against recent history, compute_risk is called
    again with the real adjustment to produce the final `score`. This
    dataclass holds both, plus a full breakdown so the number is never a
    black box.
    """
    score: int                     # 0-100, final (base_score + behavioral_adjustment, clamped)
    base_score: int                # 0-100, before any behavioral adjustment
    severity: str                  # "low" | "medium" | "high" | "critical"
    behavioral_adjustment: int = 0
    components: dict[str, float] = field(default_factory=dict)            # raw 0.0-1.0 per signal
    weighted_contributions: dict[str, float] = field(default_factory=dict)  # points (0-100) per signal
    explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DLPEvent:
    """
    Canonical event shape produced by every Phase 3 collector and enriched by
    Phase 4/5. This is what eventually gets written to the JSONL event log
    and, in Phase 9, inserted into the SQLite audit database.
    """
    event_id: str
    schema_version: str
    timestamp: str
    host: str
    user: str
    source: str                # "file" | "clipboard" | "http"
    event_type: str            # e.g. "file_created", "clipboard_change", "http_request"
    object_ref: str            # file path / "clipboard" / destination URL
    size_bytes: int = 0
    content_excerpt: Optional[str] = None   # only populated when detection needs it (privacy by design)
    detections: list[DetectionResult] = field(default_factory=list)
    obfuscation: list[ObfuscationResult] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    ai_analysis: Optional[AIAnalysisResult] = None
    risk_assessment: Optional[RiskAssessment] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detections"] = [x.to_dict() if isinstance(x, DetectionResult) else x for x in self.detections]
        d["obfuscation"] = [x.to_dict() if isinstance(x, ObfuscationResult) else x for x in self.obfuscation]
        d["ai_analysis"] = self.ai_analysis.to_dict() if isinstance(self.ai_analysis, AIAnalysisResult) else self.ai_analysis
        d["risk_assessment"] = self.risk_assessment.to_dict() if isinstance(self.risk_assessment, RiskAssessment) else self.risk_assessment
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @property
    def any_match(self) -> bool:
        """True if any deterministic detector matched on this event or any obfuscation layer."""
        if any(d.matched for d in self.detections):
            return True
        for ob in self.obfuscation:
            if any(d.matched for d in ob.rescanned_detections):
                return True
        return False


def build_event(
    source: str,
    event_type: str,
    object_ref: str,
    size_bytes: int = 0,
    content_excerpt: Optional[str] = None,
    raw_metadata: Optional[dict[str, Any]] = None,
) -> DLPEvent:
    """Factory used by all collectors so every event is built the same way."""
    return DLPEvent(
        event_id=new_event_id(),
        schema_version=SCHEMA_VERSION,
        timestamp=utc_now_iso(),
        host=current_host(),
        user=current_user(),
        source=source,
        event_type=event_type,
        object_ref=object_ref,
        size_bytes=size_bytes,
        content_excerpt=content_excerpt,
        raw_metadata=raw_metadata or {},
    )


class JsonlEventLogger:
    """
    Append-only JSONL event log. This is the Phase 3-5 durability layer:
    every collector writes here. Phase 9 will read this file (or replace it
    with direct DB writes) to populate the SQLite audit trail.

    One JSON object per line -> trivially greppable, diffable, and streamable,
    and avoids partial-write corruption that a single large JSON array risks.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: DLPEvent) -> None:
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        events = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
