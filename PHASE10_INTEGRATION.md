# Phase 10 Integration

Phase 10 adds policy-driven alert delivery and a read-only analyst dashboard
to the existing event pipeline. The pipeline and dashboard run as separate
processes.

## Run the pipeline

From the project root with the virtual environment active:

```bash
python run_pipeline_demo.py --watch-dir simulations/monitored --http-port 8765
```

The pipeline enriches each detected event, persists it to the SQLite audit
database, and dispatches alerts according to `config/alert_policy.yaml`.
Ollama AI review is enabled by default; pass `--no-ai` to run without it.

## Run the dashboard

In a second terminal:

```bash
python -m dashboard.run_dashboard --host 127.0.0.1 --port 8766
```

Open `http://127.0.0.1:8766` for the UI. Port 8765 belongs to the HTTP
collector: `/healthz` is its health check and `/upload` accepts POST requests.
The dashboard opens the same audit database in read-only mode and never
starts from the pipeline process.

## Exercise the live collectors

Use a third terminal for the synthetic HTTP scenarios:

```bash
python simulations/http_exfil_simulator.py --base-url http://127.0.0.1:8765 --timeout 60
```

For the file collector, place a synthetic text file in the watch directory.
The generated event should appear in the dashboard and alert log according
to its risk severity.

## Smoke verification

```bash
python simulations/phase10_smoke_test.py
```

This creates a disposable database under `logs/_phase10_smoke`, verifies
behavior-context persistence and append-only triggers, exercises alert
channels, and starts a separate dashboard process to check its HTTP routes.
