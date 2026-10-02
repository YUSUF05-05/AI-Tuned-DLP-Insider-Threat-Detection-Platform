"""Policy-driven dispatch to the configured alert channels."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .channels import (
    AlertDeliveryResult,
    AlertPayload,
    CHANNEL_REGISTRY,
)

SEVERITY_ORDER = {
    "clean": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _meets_threshold(severity: str, threshold: str) -> bool:
    """Return whether a known severity reaches the configured threshold."""
    level = SEVERITY_ORDER.get(str(severity).lower())
    floor = SEVERITY_ORDER.get(str(threshold).lower())
    return level is not None and floor is not None and level >= floor


class AlertEngine:
    def __init__(self, policy_path: str | Path | None = None):
        if policy_path is None:
            policy_path = Path(__file__).resolve().parents[1] / "config" / "alert_policy.yaml"
        self.policy_path = Path(policy_path)
        self.policy = yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}
        self.threshold = str(
            self.policy.get("trigger_severity_threshold", self.policy.get("severity_threshold", "medium"))
        ).lower()
        self.channels = self._build_channels()

    def _build_channels(self) -> list[Any]:
        configured = self.policy.get("channels") or {}
        channels = []
        for name, channel_type in CHANNEL_REGISTRY.items():
            settings = configured.get(name) or {}
            if not settings.get("enabled", False):
                continue
            if name == "console":
                channels.append(channel_type())
            elif name == "log_file":
                channels.append(channel_type(settings.get("path", "logs/alerts.log")))
            elif name == "webhook":
                channels.append(channel_type(
                    url=str(settings.get("url", "")),
                    timeout_seconds=float(settings.get("timeout_seconds", 5)),
                ))
            elif name == "email":
                channels.append(channel_type(
                    smtp_host=str(settings.get("smtp_host", "")),
                    smtp_port=int(settings.get("smtp_port", 587)),
                    use_tls=bool(settings.get("use_tls", True)),
                    from_address=str(settings.get("from_address", "")),
                    to_addresses=list(settings.get("to_addresses", [])),
                ))
        return channels

    @staticmethod
    def _event_dict(event: Any) -> dict[str, Any]:
        if hasattr(event, "to_dict"):
            return event.to_dict()
        return dict(event)

    def _risk(self, event: Any) -> dict[str, Any]:
        plain = self._event_dict(event)
        risk = plain.get("risk_assessment") or plain.get("risk") or {}
        return risk.to_dict() if hasattr(risk, "to_dict") else (risk if isinstance(risk, dict) else {})

    def should_alert(self, event: Any) -> bool:
        risk = self._risk(event)
        severity = risk.get("severity", "clean")
        return _meets_threshold(str(severity), self.threshold)

    def build_alert(self, event: Any) -> AlertPayload:
        plain = self._event_dict(event)
        risk = self._risk(event)
        detections = plain.get("detections") or []
        categories = sorted({
            str(d.get("category"))
            for d in detections
            if isinstance(d, dict) and d.get("matched") and d.get("category")
        })
        score = risk.get("score", risk.get("final_score", risk.get("risk_score", 0)))
        try:
            score = int(score or 0)
        except (TypeError, ValueError):
            score = 0
        return AlertPayload(
            event_id=str(plain.get("event_id", "")),
            timestamp=str(plain.get("timestamp", "")),
            user=str(plain.get("user", "")),
            host=str(plain.get("host", "")),
            source=str(plain.get("source", "")),
            object_ref=str(plain.get("object_ref", "")),
            severity=str(risk.get("severity", "clean")).lower(),
            score=score,
            categories=categories,
            summary=f"{plain.get('event_type', 'event')} matched {', '.join(categories) or 'a detector'}",
        )

    def process(self, event: Any) -> list[AlertDeliveryResult]:
        if not self.should_alert(event):
            return []
        payload = self.build_alert(event)
        results = []
        for channel in self.channels:
            try:
                results.append(channel.send(payload))
            except Exception as exc:  # keep a channel failure from stopping collection
                results.append(AlertDeliveryResult(channel=channel.name, delivered=False, detail=str(exc)))
        return results
