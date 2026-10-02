"""
alerts/channels.py  (Phase 10)

Pluggable alert-delivery channels behind one small interface (`AlertChannel`),
so alerts/alert_engine.py can dispatch to every ENABLED channel identically
regardless of where the alert actually goes. Two channels are fully
implemented and enabled by default (console, log_file); webhook and email
are wired against the SAME interface -- fully participating in dispatch --
but disabled by default in config/alert_policy.yaml because they need
operator-supplied config (a real webhook URL, real SMTP credentials) this
lab-portfolio project does not fabricate (see docs/THREAT_MODEL.md A2 -- no
real-looking-but-fake secrets are invented here either).

Every channel's send() takes the same AlertPayload and returns an
AlertDeliveryResult -- never raises. A channel failing to deliver (e.g. a
webhook endpoint down) must never crash the pipeline thread that found the
underlying DLP event; this mirrors ai/ollama_client.py's and
database/sqlite_audit.py's existing "safe fallback, log don't raise"
philosophy exactly.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("alert_channels")


@dataclass
class AlertPayload:
    """Everything a channel needs to render an alert, independent of transport."""
    event_id: str
    timestamp: str
    user: str
    host: str
    source: str
    object_ref: str
    severity: str
    score: int
    categories: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AlertDeliveryResult:
    channel: str
    delivered: bool
    detail: Optional[str] = None


class AlertChannel(ABC):
    """One delivery mechanism. Subclasses implement send(); `name` identifies
    the channel in config/alert_policy.yaml and in delivery results/logs."""

    name: str = "base"

    @abstractmethod
    def send(self, payload: AlertPayload) -> AlertDeliveryResult:
        raise NotImplementedError


class ConsoleChannel(AlertChannel):
    """Prints a one-line alert to stdout. Always available, no config needed."""
    name = "console"

    def send(self, payload: AlertPayload) -> AlertDeliveryResult:
        print(
            f"[ALERT/{payload.severity.upper()}] {payload.timestamp} user={payload.user} "
            f"source={payload.source} score={payload.score} categories={payload.categories} "
            f"-> {payload.object_ref}"
        )
        return AlertDeliveryResult(channel=self.name, delivered=True)


class LogFileChannel(AlertChannel):
    """
    Appends one JSON line per alert to a log file -- same JSONL-per-line
    philosophy as common.event_schema.JsonlEventLogger (greppable,
    diffable, streamable, no partial-write corruption from a single huge
    JSON array), but intentionally a SEPARATE file/class rather than
    reusing JsonlEventLogger directly: that class's write() is typed to
    DLPEvent specifically, and an alert is a different, smaller shape
    (AlertPayload) with a different lifecycle (alerts/*.log is meant for a
    human or an external alerting tool to tail, not to be re-ingested by
    the detection pipeline the way logs/flagged_events.jsonl is).
    """
    name = "log_file"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, payload: AlertPayload) -> AlertDeliveryResult:
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload.to_dict(), ensure_ascii=False) + "\n")
            return AlertDeliveryResult(channel=self.name, delivered=True, detail=str(self.path))
        except OSError as exc:
            logger.error("log_file channel failed to write %s: %s", self.path, exc)
            return AlertDeliveryResult(channel=self.name, delivered=False, detail=str(exc))


class WebhookChannel(AlertChannel):
    """
    Disabled by default (config/alert_policy.yaml channels.webhook.enabled:
    false). Wired against the same interface as every other channel so
    enabling it later is a CONFIG change, not a code change: set
    `enabled: true` and a real `url`, and this will POST
    payload.to_dict() as JSON via `requests` (already a project dependency
    -- see ai/ollama_client.py) with the configured timeout. Not exercised
    by default because this lab project does not fabricate a real external
    endpoint to send to (see docs/THREAT_MODEL.md A3 -- no traffic leaves
    loopback / no real external destination is modeled anywhere in this
    project).
    """
    name = "webhook"

    def __init__(self, url: str, timeout_seconds: float = 5.0):
        self.url = url
        self.timeout_seconds = timeout_seconds

    def send(self, payload: AlertPayload) -> AlertDeliveryResult:
        if not self.url:
            return AlertDeliveryResult(channel=self.name, delivered=False, detail="no url configured")
        try:
            import requests  # local import: only needed if this channel is actually enabled
            resp = requests.post(self.url, json=payload.to_dict(), timeout=self.timeout_seconds)
            ok = 200 <= resp.status_code < 300
            return AlertDeliveryResult(channel=self.name, delivered=ok, detail=f"HTTP {resp.status_code}")
        except Exception as exc:  # noqa: BLE001 -- a webhook failure must never crash the pipeline
            logger.error("webhook channel failed: %s", exc)
            return AlertDeliveryResult(channel=self.name, delivered=False, detail=str(exc))


class EmailChannel(AlertChannel):
    """
    Disabled by default (config/alert_policy.yaml channels.email.enabled:
    false). Wired against the same interface using only the standard
    library (smtplib / email.message -- no new dependency), so enabling it
    is a config change (real SMTP host/creds) not a code change. Not
    exercised by default for the same reason as WebhookChannel: no real
    credentials or destination exist in this lab.
    """
    name = "email"

    def __init__(self, smtp_host: str, smtp_port: int, use_tls: bool, from_address: str, to_addresses: list[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.from_address = from_address
        self.to_addresses = to_addresses

    def send(self, payload: AlertPayload) -> AlertDeliveryResult:
        if not self.smtp_host or not self.to_addresses:
            return AlertDeliveryResult(channel=self.name, delivered=False, detail="smtp not configured")
        try:
            import smtplib
            from email.message import EmailMessage

            msg = EmailMessage()
            msg["Subject"] = f"[DLP ALERT][{payload.severity.upper()}] {payload.object_ref}"
            msg["From"] = self.from_address
            msg["To"] = ", ".join(self.to_addresses)
            msg.set_content(json.dumps(payload.to_dict(), indent=2, ensure_ascii=False))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                server.send_message(msg)
            return AlertDeliveryResult(channel=self.name, delivered=True)
        except Exception as exc:  # noqa: BLE001 -- see WebhookChannel
            logger.error("email channel failed: %s", exc)
            return AlertDeliveryResult(channel=self.name, delivered=False, detail=str(exc))


CHANNEL_REGISTRY: dict[str, type[AlertChannel]] = {
    "console": ConsoleChannel,
    "log_file": LogFileChannel,
    "webhook": WebhookChannel,
    "email": EmailChannel,
}
