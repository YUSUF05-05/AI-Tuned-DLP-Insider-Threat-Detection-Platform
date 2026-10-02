"""
dashboard/run_dashboard.py  (Phase 10)

Standalone entry point for the analyst dashboard -- a SEPARATE process from
run_pipeline_demo.py, on its own port, so an analyst can have the dashboard
open continuously while the collector pipeline runs (or restarts, or
crashes) independently. Talks to database/audit_trail.db read-only
(dashboard.api.create_dashboard_app opens SQLiteAuditStore(read_only=True))
-- see that module's docstring and docs/DATABASE.md "Read-only dashboard
design" for why this process never writes to the audit trail.

Usage (Windows, from the project root, venv active):
    python -m dashboard.run_dashboard
    python -m dashboard.run_dashboard --port 8080 --db-path C:\\dlp-lab\\ai-dlp-insider-threat\\database\\audit_trail.db
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

from dashboard.api import create_dashboard_app, DEFAULT_DB_PATH

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("dashboard")

# Deliberately different from run_pipeline_demo.py's --http-port default
# (8765) since the two processes run side by side.
DEFAULT_PORT = int(os.getenv("DASHBOARD_PORT", "8766"))
DEFAULT_DB_PATH_ENV = os.getenv("DLP_DATABASE_PATH", str(DEFAULT_DB_PATH))


def main():
    parser = argparse.ArgumentParser(description="Phase 10 analyst dashboard (read-only)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH_ENV)
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            "Refusing to bind the dashboard to a non-loopback address by default -- "
            "this mirrors collectors/http_collector.py's guardrail. If you need "
            "remote analyst access, put a real reverse proxy + auth in front of "
            "this (Trust Boundary C in docs/THREAT_MODEL.md is explicitly flagged "
            "as unimplemented access control -- this phase still does not add "
            "authentication; see docs/DATABASE.md 'Known limitations')."
        )

    app = create_dashboard_app(db_path=args.db_path)
    logger.info("Dashboard running on http://%s:%d (read-only, db=%s)", args.host, args.port, args.db_path)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
