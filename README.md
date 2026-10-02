# AI-Tuned DLP & Insider Threat Detection Platform

A defensive, lab-scale Data Loss Prevention and insider-threat detection
pipeline: endpoint telemetry (file/clipboard/HTTP) → obfuscation-aware
normalization → a deterministic detection engine (payment cards, SWIFT
codes, credentials, sensitive keywords, sensitive file types) → local-LLM
review, hybrid risk scoring, behavioral correlation, a SQLite audit
trail, and an analyst dashboard.

**Status: Phases 0-10 implemented.** The pipeline includes local AI review,
risk scoring, behavioral correlation, an append-only SQLite audit trail,
alert routing, and a separate read-only analyst dashboard. Phases 11-18 in
the project roadmap cover expanded scenarios, evaluation, hardening, and
portfolio documentation.

Built as a portfolio project. Uses synthetic/publicly-documented test data
exclusively; performs no real data exfiltration (the "external destination"
in Phase 3 is a local server that refuses to bind off-loopback). See
`docs/THREAT_MODEL.md` for full scope and ethical constraints.

## Quick start (Windows)

Full walkthrough: `docs/INSTALLATION.md`. Short version:

```powershell
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
# extract this project to C:\dlp-lab\ai-dlp-insider-threat, then:
cd C:\dlp-lab\ai-dlp-insider-threat
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m pytest tests/ -v          # run the project test suite
python run_pipeline_demo.py         # starts file + HTTP collectors together
```

The pipeline also starts the Phase 10 alert engine and writes to the SQLite
audit trail. To run the analyst dashboard separately, open another terminal:

```powershell
python -m dashboard.run_dashboard --port 8766
```

Then open `http://127.0.0.1:8766`. The dashboard reads the audit database in
read-only mode. Start the pipeline first so the database exists.

## Documentation

| Phase | Doc | Covers |
|---|---|---|
| 0 | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, actors, scenarios, requirements, assumptions, limitations |
| 1 | [docs/INSTALLATION.md](docs/INSTALLATION.md) | Native Windows environment setup, every command, verification |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Directory structure, shared event schema, config |
| 3 | [docs/TELEMETRY.md](docs/TELEMETRY.md) | File/clipboard/HTTP collectors |
| 4 | [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | Card/SWIFT/secret/keyword/filetype detectors + known limitations |
| 5 | [docs/NORMALIZATION.md](docs/NORMALIZATION.md) | Base64/URL/JSON/gzip obfuscation detection |
| 9/10 | [docs/DATABASE.md](docs/DATABASE.md) | Append-only SQLite audit trail and read-only dashboard access |

Or read `IMPLEMENTATION_GUIDE_PHASE_0-5.md` in the project root for all six
combined into one sequential walkthrough with phase-to-phase checkpoints.

## Project layout

```
common/          shared event schema + JSONL logger      (Phase 2)
config/          detection_policy.yaml                   (Phase 2/4)
collectors/      file, clipboard, HTTP telemetry          (Phase 3)
detectors/       card, SWIFT, secret, keyword, filetype    (Phase 4)
normalization/   base64/URL/JSON/gzip obfuscation detect   (Phase 5)
ai/              local LLM review                          (Phase 6)
scoring/         hybrid risk scoring                        (Phase 7)
correlation/     behavioral pattern detection                (Phase 8)
database/        append-only SQLite audit trail              (Phase 9)
alerts/          policy-driven alert routing                 (Phase 10)
dashboard/       read-only analyst UI                       (Phase 10)
tests/           automated module and integration tests
simulations/     synthetic fixtures + HTTP exfil-pattern simulator
```

## Try it

```powershell
python run_pipeline_demo.py --watch-dir C:\dlp-lab\monitored --http-port 8765
```
In a second terminal:
```powershell
"card 4111111111111111" | Out-File C:\dlp-lab\monitored\test.txt
python simulations\http_exfil_simulator.py
python simulations\verify_fixtures.py
```

## License / provenance note

All "sensitive" values anywhere in this repository (tests, fixtures, docs)
are either fabricated or drawn from values publishers explicitly designate
as safe test data (e.g. AWS's own SDK-documentation example access key,
the payment industry's standard test card numbers). None of it is real.
