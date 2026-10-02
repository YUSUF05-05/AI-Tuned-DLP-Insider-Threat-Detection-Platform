# Phase 10 Delivery Manifest

## Added

| Path | Purpose |
|---|---|
| `alerts/__init__.py` | Exposes the alert engine as a package. |
| `alerts/alert_engine.py` | Applies the configured severity threshold and dispatches alerts. |
| `alerts/channels.py` | Console, JSONL log, webhook, and email channel implementations. |
| `config/alert_policy.yaml` | Default alert threshold and enabled channels. |
| `dashboard/__init__.py` | Dashboard package marker. |
| `dashboard/api.py` | Read-only Flask dashboard API and application factory. |
| `dashboard/run_dashboard.py` | Separate dashboard process entry point. |
| `dashboard/templates/index.html` | Analyst dashboard UI. |
| `database/__init__.py` | Exposes the SQLite audit store. |
| `docs/DATABASE.md` | Audit database schema, integrity, and read-only design. |
| `simulations/phase10_smoke_test.py` | Exercises persistence, alerting, integrity, and dashboard HTTP routes. |
| `tests/test_alert_engine.py` | Alert threshold and channel tests. |
| `tests/test_dashboard_api.py` | Dashboard route and response tests. |
| `tests/test_database_behavioral_context.py` | Full behavior-context persistence and schema migration tests. |

## Updated

| Path | Change |
|---|---|
| `database/schema.sql` | Adds behavioral context columns, removes cascading deletes, and enforces append-only audit tables. |
| `database/sqlite_audit.py` | Adds full behavior persistence, read-only access, migrations, and integrity checks. |
| `docs/ARCHITECTURE.md` | Documents the implemented database, alert, and dashboard flow. |
| `run_pipeline_demo.py` | Persists enriched events and dispatches alerts from the live pipeline. |
| `simulations/http_exfil_simulator.py` | Allows enough time for synchronous AI review to finish. |
| `tests/test_file_collector.py` | Waits for content capture across Windows create/modify notifications. |

The dashboard runs independently from the pipeline and opens the SQLite audit
database in read-only mode. Start the pipeline before the dashboard so the
database file exists.
