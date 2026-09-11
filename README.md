# AI-Tuned DLP & Insider Threat Detection Platform

A defensive, lab-scale Data Loss Prevention and insider-threat detection
pipeline: endpoint telemetry (file/clipboard/HTTP) → obfuscation-aware
normalization → a deterministic detection engine (payment cards, SWIFT
codes, credentials, sensitive keywords, sensitive file types) → (planned)
local-LLM review, hybrid risk scoring, behavioral correlation, a SQLite audit
trail, and an analyst dashboard.

**Status: Phases 0-5 complete and tested (79/79 tests passing).** Phases
6-10 (AI analysis, risk scoring, behavioral correlation, database, alerting
& dashboard) are scaffolded with placeholder READMEs but not yet
implemented — see each empty phase directory for what it will contain.

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
python -m pytest tests/ -v          # expect: 79 passed
python run_pipeline_demo.py         # starts file + HTTP collectors together
```

## Documentation

| Phase | Doc | Covers |
|---|---|---|
| 0 | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, actors, scenarios, requirements, assumptions, limitations |
| 1 | [docs/INSTALLATION.md](docs/INSTALLATION.md) | Native Windows environment setup, every command, verification |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Directory structure, shared event schema, config |
| 3 | [docs/TELEMETRY.md](docs/TELEMETRY.md) | File/clipboard/HTTP collectors |
| 4 | [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | Card/SWIFT/secret/keyword/filetype detectors + known limitations |
| 5 | [docs/NORMALIZATION.md](docs/NORMALIZATION.md) | Base64/URL/JSON/gzip obfuscation detection |

Or read `IMPLEMENTATION_GUIDE_PHASE_0-5.md` in the project root for all six
combined into one sequential walkthrough with phase-to-phase checkpoints.

## Project layout

```
common/          shared event schema + JSONL logger      (Phase 2)
config/          detection_policy.yaml                   (Phase 2/4)
collectors/      file, clipboard, HTTP telemetry          (Phase 3)
detectors/       card, SWIFT, secret, keyword, filetype    (Phase 4)
normalization/   base64/URL/JSON/gzip obfuscation detect   (Phase 5)
ai/              local LLM review                          (Phase 6 — not built)
scoring/         hybrid risk scoring                        (Phase 7 — not built)
correlation/     behavioral pattern detection                (Phase 8 — not built)
database/        SQLite audit trail                          (Phase 9 — not built)
alerts/          alert routing                                (Phase 10 — not built)
dashboard/       analyst UI                                    (Phase 10 — not built)
tests/           79 tests, one file per source module
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
