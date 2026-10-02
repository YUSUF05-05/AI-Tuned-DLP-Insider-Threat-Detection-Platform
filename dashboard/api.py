"""Standalone read-only Flask dashboard for the Phase 9 SQLite audit trail."""
from __future__ import annotations

import argparse
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from database.sqlite_audit import DEFAULT_DB_PATH, SQLiteAuditStore

ROOT = Path(__file__).resolve().parents[1]
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_SOURCES = {"file", "clipboard", "http"}


def _bool_query(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> Flask:
    app = Flask(__name__, template_folder=str(ROOT / "dashboard" / "templates"))
    store = SQLiteAuditStore(db_path=db_path, read_only=True)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        integrity = store.verify_integrity()
        return jsonify({"status": "ok", "read_only": True, "integrity": integrity})

    # Keep the Phase 10 route names used by the dashboard UI and its callers.
    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.get("/api/integrity")
    def integrity():
        return jsonify(store.verify_integrity())

    @app.get("/api/summary")
    def summary():
        severity_counts = store.severity_counts()
        return jsonify({
            "total_events": store.count_events(),
            "flagged_events": sum(severity_counts.get(level, 0) for level in ("critical", "high", "medium")),
            "critical_events": severity_counts.get("critical", 0),
            "severity_counts": severity_counts,
        })

    @app.get("/api/events")
    def events():
        user = request.args.get("user") or None
        source = request.args.get("source") or None
        severity = request.args.get("severity") or None
        try:
            limit = int(request.args.get("limit", "50"))
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400
        limit = max(1, min(limit, 500))
        if source is not None and source not in VALID_SOURCES:
            return jsonify({"error": f"invalid source '{source}'"}), 400
        if severity is not None and severity not in VALID_SEVERITIES:
            return jsonify({"error": f"invalid severity '{severity}'"}), 400
        data = [_shape_summary_row(row) for row in store.query_events(
            user=user, source=source, severity=severity, limit=limit,
        )]
        return jsonify({"events": data, "count": len(data)})

    @app.get("/api/events/<event_id>")
    def event_detail(event_id: str):
        event = store.get_event(event_id)
        if event is None:
            return jsonify({"error": "event not found"}), 404
        return jsonify(event)

    return app


# The Phase 10 launcher and tests use this descriptive factory name.
create_dashboard_app = create_app


def _shape_summary_row(row: dict) -> dict:
    """Shape SQLite summary rows for JSON consumers and the dashboard table."""
    shaped = dict(row)
    for bool_col in ("any_match", "needs_ai_review", "behavioral_escalating", "ai_is_sensitive"):
        if bool_col in shaped and shaped[bool_col] is not None:
            shaped[bool_col] = bool(shaped[bool_col])
    for drop_col in (
        "raw_metadata_json", "risk_components_json", "risk_explanation_json",
        "behavioral_repeated_categories_json", "behavioral_explanation_json",
    ):
        shaped.pop(drop_col, None)
    return shaped


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the read-only DLP audit dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    args = parser.parse_args()

    app = create_app(args.db)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
