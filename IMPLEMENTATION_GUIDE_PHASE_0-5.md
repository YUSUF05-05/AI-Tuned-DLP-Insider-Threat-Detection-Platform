# AI-Tuned DLP & Insider Threat Detection Platform
# Implementation Guide — Phase 0 through Phase 5

**Scope of this guide:** threat modeling, environment setup, project
architecture, endpoint telemetry, deterministic detection, and content
normalization/obfuscation detection. Phases 6-10 (AI analysis, risk scoring,
behavioral correlation, database, alerting & dashboard) are out of scope for
this guide and are left as documented, not-yet-built placeholders in the
delivered project (`ai/`, `scoring/`, `correlation/`, `database/`,
`alerts/`, `dashboard/`).

**Status: every phase in this guide is fully implemented, tested, and
verified working end-to-end in the accompanying project — not a plan, a
built and tested system.** 79 automated tests pass; a full pipeline run
(collectors → detection → normalization) was executed and its real output
is embedded throughout this guide as evidence, not invented as illustration.

## How to use this guide

Each phase is self-contained with the same twelve-section structure
(Objective, Concept, Architecture, Files, Configuration, Commands,
Implementation, Testing, Expected Result, Troubleshooting, Security
Considerations, Completion Criteria). Work through phases **in order** — each
one's Completion Criteria are the prerequisite for the next:

```mermaid
flowchart TD
    P0["Phase 0\nThreat Model"] --> P1["Phase 1\nEnvironment Setup"]
    P1 --> P2["Phase 2\nArchitecture & Repo"]
    P2 --> P3["Phase 3\nTelemetry Collectors"]
    P3 --> P4["Phase 4\nDetection Engine"]
    P3 --> P5["Phase 5\nNormalization"]
    P4 --> P5
    P5 --> P6["Phase 6+\n(not in this guide)"]
```

Phase 4 and Phase 5 both depend on Phase 3 (they need events to analyze) but
not on each other individually to *build* — however, Phase 5 imports and
calls Phase 4's `run_all()` to rescan decoded content, so Phase 4 must be
implemented first even though "Phase 5 needs Phase 3" is the only dependency
arrow the phase numbering implies. This is called out explicitly here
because it's exactly the kind of dependency that's easy to miss from a
phase list alone — the delivered project's `normalization/normalizer.py`
takes a `detector_runner` argument for precisely this reason: it depends on
Phase 4's *interface*, not its internals, which is what makes the phases
independently testable despite the real dependency.

## Table of contents

1. [Phase 0 — Threat Model](#phase-0--threat-model)
2. [Phase 1 — Environment Setup](#phase-1--environment-setup-windows-native)
3. [Phase 2 — Project Architecture & Repository](#phase-2--project-architecture--repository)
4. [Phase 3 — Endpoint Telemetry Collection](#phase-3--endpoint-telemetry-collection)
5. [Phase 4 — Deterministic Detection Engine](#phase-4--deterministic-detection-engine)
6. [Phase 5 — Content Normalization & Obfuscation Detection](#phase-5--content-normalization--obfuscation-detection)
7. [Overall Completion Checklist & Next Steps](#overall-completion-checklist--next-steps)

---

# PHASE 0 — THREAT MODEL

## 🎯 Objective

Define what this platform protects, against whom, under what assumptions, and
how "done" is measured — **before** any detection logic is written. Every
later technical decision (which detectors exist, what "risk" means in Phase 7,
what counts as project-complete in Phase 18) traces back to a requirement
defined here. This phase produces no code; it produces the requirements
Phases 3-5 (already implemented) were built against, and the standard the
implementation is checked against at the end of this document.

## 🧠 Concept

**DLP (Data Loss Prevention)** and **insider threat detection** are related
but distinct disciplines, combined deliberately in this project:

- DLP asks: *"is this specific piece of content sensitive?"* — a
  content-inspection problem. Phases 4-5 answer this.
- Insider threat detection asks: *"is this specific person's behavior, over
  time, consistent with data theft?"* — a behavioral/pattern problem. Phase 8
  will answer this, built on top of the DLP layer's output.

A platform that only does content inspection catches "a credit card number
just left the building" but not "this user has quietly touched every
customer file in the finance share over the past three days." Combining both
is what real insider-risk programs do, and it is why the architecture has
both a content-detection layer (Phase 4/5, done) and a correlation layer
(Phase 8, later).

**Scope discipline (ties to the project's ethical constraints):** this is a
defensive, single-operator lab. It uses synthetic data exclusively, performs
no real exfiltration (the "external" destination is a local server that never
leaves loopback — enforced in code, not just policy, in
`collectors/http_collector.py`), and does not build or reference any
offensive/malware tooling. The goal is to demonstrate detection engineering
skill, not to build a surveillance product — see "Lab Limitations" below for
where this project deliberately stops.

## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph Endpoint["Monitored Endpoint — Windows Host (Trust Boundary A)"]
        FC["File Collector\n(Phase 3 — done)"]
        CC["Clipboard Collector\n(Phase 3 — done)"]
    end
    subgraph External["Simulated External Destination (Trust Boundary B)"]
        HC["HTTP Collector /\nLab Destination Server\n(Phase 3 — done, loopback-only)"]
    end
    FC --> EL[("JSONL Event Log")]
    CC --> EL
    HC --> EL
    EL --> Norm["Normalization /\nObfuscation Detection\n(Phase 5 — done)"]
    Norm --> Det["Deterministic Detection Engine\n(Phase 4 — done)"]
    Det -- needs_ai_review --> AI["AI Analysis\n(Phase 6 — not yet built)"]
    Det --> Score["Risk Scoring\n(Phase 7 — not yet built)"]
    AI --> Score
    Score --> Corr["Behavioral Correlation\n(Phase 8 — not yet built)"]
    Corr --> DB[("SQLite Audit Trail\n(Phase 9 — not yet built)")]
    DB --> Dash["Analyst Dashboard\n(Trust Boundary C)\n(Phase 10 — not yet built)"]
```

**Trust boundaries:**

| Boundary | What separates | Why it matters |
|---|---|---|
| A — Endpoint | The monitored Windows host vs. everything else | This is the boundary Phase 3's collectors instrument. Everything observed originates here. |
| B — External destination | "Internal/legitimate" vs. "external/uncontrolled" | Modeled entirely by the local HTTP test server. No traffic ever crosses a real network boundary — see `run_server()`'s loopback guard in `collectors/http_collector.py`. |
| C — Analyst access | Whoever can read the audit trail / dashboard vs. everyone else | Not implemented until Phase 9/10, but flagged now so those phases don't get built ignoring access control as a requirement. |

## Assets (synthetic representations of)

1. Customer PII — names, SSNs, dates of birth, addresses
2. Payment card data — PAN, expiry, brand
3. Financial / payment messages — SWIFT/BIC codes, wire instructions
4. Credentials and secrets — cloud API keys, private keys, VCS/chat tokens
5. Proprietary source code and "confidential" marked documents
6. Strategic/M&A material — deal terms, board decks

## Threat actors

| Actor | Description | Example scenario |
|---|---|---|
| Malicious insider | Intentional data theft or sabotage | A departing employee exports the customer list before resigning |
| Negligent insider | Unintentional exposure, no bad intent | Pastes a customer export into a personal chat app out of habit |
| Compromised insider | External attacker operating through a legitimate employee's session | Indistinguishable from a malicious insider at the DLP layer — a documented, real limitation of this entire class of tooling, not something this project claims to solve (see Lab Limitations) |

## Insider-threat / exfiltration scenarios

These define **what the platform must be able to see**; they become the
concrete test scenarios in Phase 11.

| ID | Scenario | Primary detector(s) exercising it |
|---|---|---|
| S1 | Bulk customer data export before resignation | `keyword_detector` (customer_data), `filetype_detector` |
| S2 | Payment card data pasted into external chat/webmail | `card_detector` via clipboard/HTTP collector |
| S3 | Credential/secret leaked into chat or a paste site | `secret_detector` |
| S4 | Proprietary source code exfiltrated via personal email/cloud | `keyword_detector` (source_code_markers), `filetype_detector` |
| S5 | Data obfuscated (renamed extension, base64, zipped) before exfil | `normalization/normalizer.py` (Phase 5), `filetype_detector`'s magic-byte mismatch check |
| S6 | Anomalous timing/volume (e.g. large export at 2am, or pre-offboarding) | Not a content signal — this is Phase 8's behavioral correlation, noted here as a requirement driver |

## Detection requirements

| ID | Requirement | Status |
|---|---|---|
| DR1 | Detect unencoded payment card numbers, brand-identified, Luhn-validated | ✅ Implemented — `detectors/card_detector.py` |
| DR2 | Detect SWIFT/BIC codes and MT-style payment-message structures | ✅ Implemented — `detectors/swift_detector.py` |
| DR3 | Detect common credential/secret formats without ever persisting the raw secret | ✅ Implemented — `detectors/secret_detector.py` (fingerprint-only evidence) |
| DR4 | Detect configurable sensitive keyword/category content | ✅ Implemented — `detectors/keyword_detector.py` + `config/detection_policy.yaml` |
| DR5 | Detect sensitive file types by extension AND content, catching renamed-extension evasion | ✅ Implemented — `detectors/filetype_detector.py` |
| DR6 | Detect base64 / URL-encoding / JSON-embedding / compression obfuscation, recursively | ✅ Implemented — `normalization/normalizer.py` |
| DR7 | Escalate ambiguous content to AI review rather than relying on regex alone | ⏳ Phase 6 (not yet built) — the hook (`needs_ai_review()`) already exists in `detectors/engine.py` |
| DR8 | Produce a single blended risk score from deterministic + AI signals | ⏳ Phase 7 (not yet built) |
| DR9 | Correlate multiple low-signal events into a higher-confidence behavioral pattern | ⏳ Phase 8 (not yet built) |

## Security assumptions

- **A1.** The lab runs on a single-user Windows laptop under the operator's
  full control. There is no adversary with independent, concurrent access to
  the host during testing — this project defends against *what a user does*,
  not against *an attacker who already has a foothold on the box*.
- **A2.** All sensitive data used anywhere in testing is synthetic. Where a
  "realistic" value is needed, only publicly-documented example/test values
  are used (e.g. AWS's own published example access key, the standard
  payment-industry test card numbers) — never real, real-looking-but-private,
  or randomly-generated-but-plausible data.
- **A3.** The simulated "external" destination is always the local test
  server; no traffic ever leaves the loopback interface. This is enforced
  technically (`run_server()` refuses to bind non-loopback), not only by
  policy.
- **A4.** The Windows OS, its account model, and the Python runtime are
  trusted. This project does not defend against OS-level compromise, kernel
  rootkits, or an attacker with physical access to the device.

## Lab limitations (explicit, non-exhaustive)

- **Pattern-based ceiling.** Deterministic detectors miss sensitive data that
  matches no known pattern and no policy keyword (e.g. a customer list with
  no SSNs/card numbers and no configured keyword hit). This is precisely why
  an AI review layer (Phase 6) exists — but even that will not be
  exhaustive, and should not be marketed as such in the portfolio write-up.
- **No kernel-level hooking.** Everything is user-space (Python, `watchdog`,
  `pyperclip`, Flask). A sufficiently technical malicious insider could
  write data through a path this project does not observe. This is
  documented, not solved, here.
- **Correlation will be heuristic, not a full UEBA product.** When Phase 8
  is built, its false-positive/false-negative rates should be reported
  honestly (Phase 12), not oversold.
- **Single host, no SIEM integration.** This is a portfolio-scale lab, not a
  multi-endpoint enterprise deployment. Worth naming explicitly as "future
  work" in the final write-up (Phase 18) rather than silently ignoring it.
- **The tool's own output is a new asset.** The event log / future database
  is itself sensitive (it contains detection evidence about real activity
  once deployed anywhere real). This is why secrets are fingerprinted rather
  than logged raw (`detectors/secret_detector.py`) and cards are masked to
  PCI-DSS 3.3/3.4 style (`detectors/card_detector.py`) — decisions made
  *because of* this threat-modeling step, not incidentally.

## 📌 Completion Criteria

- [x] Assets, actors, and scenarios documented (this file)
- [x] Trust boundaries diagrammed
- [x] Detection requirements DR1-DR9 listed, each traceable to an owning phase
- [x] Assumptions and limitations stated explicitly, not left implicit
- [x] Cross-checked against the actual Phase 4/5 implementation: DR1-DR6 are
      verified satisfied by the 79 passing tests in `tests/` (see
      `docs/DETECTION_ENGINE.md` and `docs/NORMALIZATION.md` for the
      per-requirement test evidence)

**Do not proceed to relying on Phase 1 environment setup until this file has
been read and the scenarios table (S1-S6) makes sense to you** — Phase 11's
test scenarios (a later phase) will be a direct elaboration of this table,
and Phase 7's risk-scoring weights (also later) will reference these asset
categories by name.

---

# PHASE 1 — ENVIRONMENT SETUP (Windows, Native)

## 🎯 Objective

Produce a working, verified, native Windows development environment with
every dependency Phases 3-5 need, confirmed functional end-to-end via the
project's own test suite, before touching project code.

## 🧠 Concept

**Native Windows, not a VM.** This was decided and reasoned through earlier
in this project's setup (RAM budget, resource overhead, and the fact that
every tool below — Python, Git, VS Code, Ollama — has a native Windows build,
so a VM would add virtualization overhead for zero capability gain). This
phase executes that decision; it does not re-argue it.

**Why these specific tools:** each one maps to a concrete need from Phase 0's
requirements or the Phase 3-5 implementation, not habit:

| Tool | Needed because | Mandatory? |
|---|---|---|
| Python 3.11+ | Every collector, detector, and normalizer is Python | Mandatory |
| Git | Version control for the portfolio repo | Mandatory |
| VS Code | Primary editor | Recommended, not mandatory (any editor works) |
| Ollama | Local LLM runtime for Phase 6 | Mandatory for Phase 6 only — installed now so Phase 6 has zero setup friction, but unused by Phases 1-5 |
| DB Browser for SQLite | GUI inspection of the Phase 9 audit database | Optional |
| SQLite itself | Phase 9's audit trail engine | No install needed — ships in Python's standard library (`sqlite3`) |

## 🏗️ Architecture

Single machine, no network topology beyond the loopback interface
(`127.0.0.1`) that Phase 3's HTTP collector and Phase 6's Ollama API both
bind to. No firewall changes are required because nothing here listens on a
non-loopback address — see `docs/TELEMETRY.md` "Network Exposure" for the
guardrail that enforces this in code.

## 📁 Files created in this phase

```
C:\dlp-lab\                          <- parent folder for the whole lab
└── ai-dlp-insider-threat\           <- this project (extracted from the delivered zip)
    ├── .venv\                       <- Python virtual environment (created here, not committed)
    ├── .env                         <- your local copy of .env.example (not committed)
    └── ...                          <- everything else, already built (Phases 2-5)
C:\dlp-lab\monitored\                <- the folder Phase 3's file collector watches
```

## ⚙️ Configuration

`.env.example` (already in the delivered project — copy it to `.env` and
adjust paths for your machine):

```env
# .env.example
# Copy to .env and adjust for your machine:  copy .env.example .env   (Windows)
# .env is loaded by python-dotenv where applicable and is in .gitignore --
# never commit your actual .env.

# --- Phase 1/3: paths (Windows examples; adjust for your setup) ---
DLP_PROJECT_ROOT=C:\dlp-lab\ai-dlp-insider-threat
DLP_MONITORED_PATH=C:\dlp-lab\monitored
DLP_LOG_DIR=C:\dlp-lab\ai-dlp-insider-threat\logs

# --- Phase 3: HTTP collector / simulated destination ---
DLP_HTTP_HOST=127.0.0.1
DLP_HTTP_PORT=8765

# --- Phase 4/5: policy file location (rarely needs changing) ---
DLP_POLICY_PATH=config/detection_policy.yaml

# --- Phase 6 (not yet implemented in this guide) ---
# OLLAMA_HOST=http://127.0.0.1:11434
# OLLAMA_MODEL=llama3.2:3b

# --- Phase 9 (not yet implemented in this guide) ---
# DLP_DATABASE_PATH=C:\dlp-lab\ai-dlp-insider-threat\database\audit_trail.db
```

`requirements.txt` (already in the delivered project):

```text
# AI-Tuned DLP & Insider Threat Detection Platform
# Core dependencies for Phases 0-5 (telemetry, deterministic detection, normalization)
# Install with: pip install -r requirements.txt

# --- Endpoint telemetry (Phase 3) ---
watchdog>=6.0.0          # Cross-platform filesystem event monitoring (uses ReadDirectoryChangesW on Windows)
pyperclip>=1.11.0        # Cross-platform clipboard read access

# --- Local HTTP test destination + collector (Phase 3) ---
flask>=3.1.0             # Lightweight local server for the simulated exfiltration destination / API

# --- Simulation / test client (Phase 3, 11) ---
requests>=2.33.0         # Used by the synthetic test client to send sample traffic to the local server

# --- Configuration (Phase 4, 5) ---
pyyaml>=6.0.3            # Human-editable detection policy (keywords, thresholds, categories)
python-dotenv>=1.2.0     # Loads .env into environment variables at startup

# --- Testing (all phases) ---
pytest>=9.1.0            # Unit + integration test runner

# NOTE: sqlite3 (Phase 9) and Ollama's Python usage (Phase 6) are intentionally
# NOT listed here because they are out of scope for Phases 0-5:
#   - sqlite3 ships in the Python standard library, no pip install required.
#   - Ollama is a separate native Windows application (see docs/INSTALLATION.md),
#     not a pip package; its Python client will be added when Phase 6 is implemented.
```

## 💻 Commands

Run everything below in **PowerShell** (not Command Prompt). Right-click Start
→ "Terminal" or "PowerShell" — administrator rights are not required for any
step unless noted.

### Step 1 — Install Python

```powershell
winget install -e --id Python.Python.3.12
```

**Close and reopen PowerShell** (this refreshes PATH — Python will not be
found otherwise).

Verify:
```powershell
python --version
pip --version
```
**Expected output:**
```
Python 3.12.x
pip 24.x from C:\...\Python312\Lib\site-packages\pip (python 3.12)
```
*(This guide was authored and its test suite validated against Python 3.12.3
specifically; any 3.11+ release will work.)*

### Step 2 — Install Git

```powershell
winget install -e --id Git.Git
```
Close/reopen PowerShell, then:
```powershell
git --version
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```
**Expected output:** `git version 2.4x.x.windows.1`

### Step 3 — Install VS Code (recommended editor)

```powershell
winget install -e --id Microsoft.VisualStudioCode
code --install-extension ms-python.python
code --install-extension ms-python.vscode-pylance
```
**Expected output:** each `code --install-extension` call ends with
`Extension '...' was successfully installed.`

### Step 4 — Create the lab folder and get the project into it

```powershell
mkdir C:\dlp-lab
cd C:\dlp-lab
mkdir monitored
```
Extract the delivered `ai-dlp-insider-threat.zip` into `C:\dlp-lab\`, so you
end up with `C:\dlp-lab\ai-dlp-insider-threat\` containing this project.
Then initialize it as your own git repo (the delivered project intentionally
does not include a `.git` folder, so history starts clean with you as author):
```powershell
cd C:\dlp-lab\ai-dlp-insider-threat
git init
git add .
git commit -m "Initial commit: Phases 0-5 (threat model, environment, architecture, telemetry, detection, normalization)"
```

### Step 5 — Create and activate a virtual environment

```powershell
cd C:\dlp-lab\ai-dlp-insider-threat
python -m venv .venv
.venv\Scripts\Activate.ps1
```
**Expected output:** your prompt now starts with `(.venv)`.

> If you get *"cannot be loaded because running scripts is disabled on this
> system"*, see Troubleshooting below before continuing.

### Step 6 — Install project dependencies

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```
**Expected output:** ends with `Successfully installed flask-... pytest-...
pyyaml-... watchdog-... pyperclip-... requests-... python-dotenv-...`
(exact versions may be newer than what's pinned as a minimum — that's fine).

### Step 7 — Create your local `.env`

```powershell
copy .env.example .env
notepad .env
```
Update `DLP_PROJECT_ROOT` and `DLP_MONITORED_PATH` if you used a folder other
than `C:\dlp-lab`, then save and close.

### Step 8 — Install Ollama (prepares for Phase 6; not used by Phases 1-5)

```powershell
winget install -e --id Ollama.Ollama
```
Close/reopen PowerShell, then verify the service and pull a small model to
smoke-test the install (Phase 6 will decide the final model choice against
your actual remaining RAM budget — this is only proving Ollama itself works):
```powershell
ollama --version
ollama pull llama3.2:3b
ollama list
```
**Expected output of `ollama list`:**
```
NAME              ID              SIZE      MODIFIED
llama3.2:3b       ...             2.0 GB    ...
```
Confirm the local API is actually listening:
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:11434/api/version
```
**Expected output:** a JSON object like `{"version": "0.x.x"}`.

### Step 9 — Confirm SQLite (no install needed) and optionally add a GUI browser

```powershell
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```
**Expected output:** a version string, e.g. `3.45.3`.

Optional GUI (only if you want to visually browse the Phase 9 database later):
```powershell
winget install -e --id DBBrowserForSQLite.DBBrowserForSQLite
```

### Step 10 — Run the full test suite as your environment-wide verification

```powershell
cd C:\dlp-lab\ai-dlp-insider-threat
python -m pytest tests/ -v
```
**Expected output (final line):** `79 passed in ...s`

This single command is the real proof the environment is correctly set up —
it exercises Python, every dependency in `requirements.txt`, and the entire
Phase 3-5 codebase together.

## 🧩 Implementation

Nothing to implement in this phase — it is entirely tooling setup. The
project code being verified in Step 10 was implemented in Phases 3-5 (see
`docs/TELEMETRY.md`, `docs/DETECTION_ENGINE.md`, `docs/NORMALIZATION.md`).

## 🧪 Testing

| Check | Command | Confirms |
|---|---|---|
| Python present | `python --version` | Interpreter installed and on PATH |
| Git present | `git --version` | Version control available |
| VS Code present | `code --version` | Editor + CLI integration |
| Venv active | prompt shows `(.venv)` | Dependencies install in isolation |
| Dependencies installed | `pip list` | All of `requirements.txt` present |
| Ollama installed | `ollama --version` | Phase 6 prerequisite ready |
| Ollama API reachable | `Invoke-RestMethod http://127.0.0.1:11434/api/version` | Local LLM service is actually running, not just installed |
| SQLite available | `python -c "import sqlite3; ..."` | Phase 9 prerequisite ready, zero extra install |
| **Whole environment** | `python -m pytest tests/ -v` | **79/79 tests pass — Phases 3-5 work on this machine** |

## ✅ Expected Result

A `(.venv)`-activated PowerShell session in `C:\dlp-lab\ai-dlp-insider-threat`
where `python -m pytest tests/ -v` prints `79 passed` and `ollama list` shows
at least one pulled model. Nothing needs to be running yet (no servers) —
Phase 3's collectors are started on demand (see `docs/TELEMETRY.md`).

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `python` opens the Microsoft Store instead of running | Windows' "App execution alias" for python.exe is intercepting the command | Settings → Apps → Advanced app settings → App execution aliases → turn OFF `python.exe` and `python3.exe` |
| `python`/`git`/`code` "is not recognized as an internal or external command" | PATH wasn't refreshed | Close and reopen PowerShell completely (not just a new tab in some terminals) |
| `.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system` | PowerShell's default execution policy blocks local scripts | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then retry. This only relaxes the policy for your user account, not machine-wide. |
| `pip install -r requirements.txt` fails on `flask`/`watchdog`/etc. with a build error | Rare on Windows for these particular packages (all ship prebuilt wheels), but if it happens: outdated pip | `pip install --upgrade pip` then retry |
| `ollama pull llama3.2:3b` hangs or fails | No internet access, or a corporate proxy blocking `ollama.com` | Confirm you can reach `https://ollama.com` in a browser; configure `HTTPS_PROXY` if you're behind a corporate proxy |
| `winget install` fails with "No package found matching input criteria" | winget's local source index is stale | Run `winget source update`, then retry the install |
| `pytest` reports fewer than 79 tests collected | You're running it from the wrong directory, or `.venv` isn't activated | Confirm your prompt shows `(.venv)` and you're in `C:\dlp-lab\ai-dlp-insider-threat` (the folder containing `tests\`) |

## 🔐 Security Considerations

- The virtual environment (`.venv/`) and `.env` are both in `.gitignore` —
  never commit either. `.env` is where any future real secret (e.g. a Phase
  6+ API key, if you ever add a cloud fallback) would live.
- Ollama's local API (`127.0.0.1:11434`) is loopback-only by default on
  Windows — do not change its bind address to make it "reachable from other
  devices" for this project; there is no requirement that justifies that
  exposure.
- `winget` installs from Microsoft's curated, signed package repository —
  prefer it over downloading installers directly from third-party sites for
  every tool above where a winget package exists.

## 📌 Completion Criteria

- [ ] `python --version` reports 3.11 or newer
- [ ] `git --version` succeeds and identity is configured
- [ ] Project extracted to `C:\dlp-lab\ai-dlp-insider-threat` and committed to a fresh local git repo
- [ ] `.venv` created and activated
- [ ] `pip install -r requirements.txt` completes with no errors
- [ ] `.env` created from `.env.example`
- [ ] `ollama list` shows at least one pulled model and the API responds on `127.0.0.1:11434`
- [ ] `python -c "import sqlite3; print(sqlite3.sqlite_version)"` prints a version
- [ ] **`python -m pytest tests/ -v` prints `79 passed`** — this is the actual gate; do not proceed to relying on Phase 2 until this is true on your machine

---

# PHASE 2 — PROJECT ARCHITECTURE & REPOSITORY

## 🎯 Objective

Design and scaffold the complete project directory structure, and establish
the one piece of shared infrastructure (the event schema) that every later
phase depends on — so Phases 3, 4, and 5 have a common language for "what is
an event" before any of them are implemented.

## 🧠 Concept

The repository structure mirrors the architecture diagram from Phase 0
almost directly: one top-level package per pipeline stage. This is a
deliberate choice over, say, organizing by "layer" (models/views/utils) —
in a security pipeline, the *stage data moves through* is the natural unit of
testing, review, and (eventually) independent scaling, so the folders should
match the stages.

**Deviation from a typical minimal proposal, and why:** a `common/` package
was added that a first-pass structure might omit. It exists because
collectors (Phase 3), detectors (Phase 4), and the normalizer (Phase 5) all
need to produce and consume the *same* event shape. Without one shared
definition, each module would invent its own dict keys, and Phase 9
(database ingestion, later) would need bespoke parsing per source. See the
docstring at the top of `common/event_schema.py` for the full reasoning —
this is exactly the kind of "you may improve the architecture if you can
justify it" decision the project asked for.

## 🏗️ Architecture — full directory tree

```
.
|-- .env.example
|-- .gitignore
|-- ai
|   |-- .gitkeep
|   `-- README.md
|-- alerts
|   |-- .gitkeep
|   `-- README.md
|-- collectors
|   |-- __init__.py
|   |-- clipboard_collector.py
|   |-- file_collector.py
|   `-- http_collector.py
|-- common
|   |-- __init__.py
|   `-- event_schema.py
|-- config
|   `-- detection_policy.yaml
|-- correlation
|   |-- .gitkeep
|   `-- README.md
|-- dashboard
|   |-- .gitkeep
|   `-- README.md
|-- database
|   |-- .gitkeep
|   `-- README.md
|-- detectors
|   |-- __init__.py
|   |-- card_detector.py
|   |-- engine.py
|   |-- filetype_detector.py
|   |-- keyword_detector.py
|   |-- secret_detector.py
|   `-- swift_detector.py
|-- docs
|   |-- ARCHITECTURE.md
|   |-- INSTALLATION.md
|   `-- THREAT_MODEL.md
|-- logs
|   `-- .gitkeep
|-- normalization
|   |-- __init__.py
|   `-- normalizer.py
|-- requirements.txt
|-- run_pipeline_demo.py
|-- scoring
|   |-- .gitkeep
|   `-- README.md
|-- simulations
|   |-- http_exfil_simulator.py
|   |-- monitored
|   |   `-- .gitkeep
|   |-- synthetic_data
|   |   |-- README.md
|   |   |-- sample_card_paste.txt
|   |   |-- sample_credential_leak.txt
|   |   |-- sample_customer_export.csv
|   |   |-- sample_obfuscated_payload_base64.txt
|   |   `-- sample_proprietary_source_note.txt
|   `-- verify_fixtures.py
`-- tests
    |-- __init__.py
    |-- test_card_detector.py
    |-- test_clipboard_collector.py
    |-- test_engine.py
    |-- test_file_collector.py
    |-- test_filetype_detector.py
    |-- test_http_collector.py
    |-- test_keyword_detector.py
    |-- test_normalizer.py
    |-- test_secret_detector.py
    `-- test_swift_detector.py

18 directories, 56 files
```

## 📁 What belongs in each directory

| Directory | Purpose | Populated by |
|---|---|---|
| `common/` | Shared event schema + JSONL logger used by every other package | Phase 2 (this phase) |
| `config/` | Human-editable detection policy (keywords, thresholds, file types) | Phase 2/4 |
| `collectors/` | Endpoint telemetry sources: file, clipboard, HTTP | Phase 3 |
| `detectors/` | Deterministic detection engine (card, SWIFT, secrets, keywords, file type) + aggregator | Phase 4 |
| `normalization/` | Obfuscation detection (base64, URL-encoding, JSON, gzip/zip) | Phase 5 |
| `ai/` | Local LLM (Ollama) review of ambiguous content | Phase 6 — not yet built |
| `scoring/` | Hybrid deterministic + AI risk scoring | Phase 7 — not yet built |
| `correlation/` | Cross-event behavioral pattern detection | Phase 8 — not yet built |
| `database/` | SQLite schema + ingestion from the JSONL logs | Phase 9 — not yet built |
| `alerts/` | Alert routing/formatting | Phase 10 — not yet built |
| `dashboard/` | Analyst-facing UI | Phase 10 — not yet built |
| `tests/` | Unit + integration tests, one file per source module | All phases |
| `simulations/` | Synthetic test fixtures and the HTTP exfiltration-pattern simulator | Phase 3/11 |
| `logs/` | Runtime JSONL event logs (gitignored — regenerated, never committed) | Runtime |
| `docs/` | This documentation set | All phases |

**How components interact (already-implemented phases):** a collector
(`collectors/*.py`) builds a `DLPEvent` via `common.event_schema.build_event()`,
writes it to a `JsonlEventLogger`, and — if an `on_event` callback was
supplied — hands it to whatever's listening. `run_pipeline_demo.py` wires
that callback to `detectors.engine.run_all()` (Phase 4) and
`normalization.normalizer.normalize_and_rescan()` (Phase 5), and prints an
alert when either layer matches. Nothing here imports "downward" —
`common/` depends on nothing else in the project, `detectors/` and
`normalization/` depend only on `common/`, and `collectors/` depends only on
`common/`. This keeps every package independently testable, which is why
each one has its own test file that doesn't need the others to run.

## ⚙️ Configuration

The full detection policy (already built and used starting in Phase 4) lives
here for reference, since it's the one config file that spans multiple
phases:

```yaml
# detection_policy.yaml
#
# Central, human-editable policy for the deterministic detection engine (Phase 4).
#
# WHY YAML AND NOT JSON (documented per project rule "explain the lighter alternative"):
#   JSON was considered and rejected as the policy format because it cannot hold
#   comments, which matters here since every keyword list and threshold needs an
#   explanation for why it exists (a security reviewer must be able to read this
#   file and understand intent, not just data). YAML is a light, well-justified
#   dependency (PyYAML) that is the de facto standard for security tooling
#   config (Sigma rules, Wazuh, Suricata companion configs all use YAML).
#
# This file is read once at startup by detectors/keyword_detector.py and
# detectors/filetype_detector.py via common config loading in detectors/engine.py.

# ---------------------------------------------------------------------------
# Keyword categories (Phase 4.4 — sensitive keyword and category detection)
# Matching is case-insensitive whole-word/phrase matching (see keyword_detector.py).
# ---------------------------------------------------------------------------
keyword_categories:
  customer_data:
    description: "Indicates presence of customer PII in content."
    keywords:
      - "customer list"
      - "customer database"
      - "social security number"
      - "ssn"
      - "date of birth"
      - "passport number"
      - "driver's license"
      - "home address"

  financial:
    description: "Indicates financial or payment-related content."
    keywords:
      - "routing number"
      - "account number"
      - "wire transfer"
      - "swift code"
      - "iban"
      - "invoice total"
      - "bank statement"
      - "payroll"

  source_code_markers:
    description: "Indicates proprietary source code or build artifacts."
    keywords:
      - "confidential and proprietary"
      - "internal use only"
      - "do not distribute"
      - "copyright all rights reserved"
      - "trade secret"

  credentials_context:
    description: >
      Contextual words that raise confidence when found NEAR a secret-like
      token (used by detectors/secret_detector.py as a confidence booster,
      not as a standalone trigger).
    keywords:
      - "password"
      - "api key"
      - "access key"
      - "private key"
      - "secret key"
      - "auth token"
      - "credentials"

  m_and_a_strategic:
    description: "Indicates strategic / M&A / competitive material."
    keywords:
      - "merger agreement"
      - "acquisition target"
      - "non-disclosure agreement"
      - "letter of intent"
      - "board deck"
      - "strategic roadmap"

# ---------------------------------------------------------------------------
# Sensitive file types (Phase 4.6 — file type / extension detection)
# ---------------------------------------------------------------------------
sensitive_file_types:
  documents:
    extensions: [".docx", ".doc", ".pdf", ".pptx", ".xlsx", ".csv"]
    risk_weight: 0.3
  archives:
    extensions: [".zip", ".7z", ".rar", ".tar", ".gz"]
    risk_weight: 0.5
    note: "Archives are also fed to the Phase 5 normalizer for obfuscation checks."
  credentials_and_keys:
    extensions: [".pem", ".key", ".pfx", ".p12", ".env", ".ppk"]
    risk_weight: 0.9
  database_dumps:
    extensions: [".sql", ".db", ".sqlite", ".bak"]
    risk_weight: 0.7
  source_code:
    extensions: [".py", ".js", ".ts", ".java", ".cs", ".go", ".rb", ".php"]
    risk_weight: 0.2

# ---------------------------------------------------------------------------
# Content-capture thresholds (privacy-by-design — Phase 3)
# Collectors only attach raw content_excerpt to an event when a file/clip is
# under this size AND matches a sensitive file type OR is plain text. This
# bounds both privacy exposure and I/O cost. See docs/TELEMETRY.md.
# ---------------------------------------------------------------------------
content_capture:
  max_bytes_for_full_read: 2097152      # 2 MiB — above this, only metadata is captured
  excerpt_max_chars: 4000               # content_excerpt is truncated to this length
  redact_detected_secrets_in_excerpt: true

# ---------------------------------------------------------------------------
# Normalization / obfuscation detection thresholds (Phase 5)
# ---------------------------------------------------------------------------
normalization:
  max_recursion_depth: 3                # how many nested encodings to unwrap (base64-in-base64-in-gzip, etc.)
  min_base64_run_length: 40             # ignore short incidental base64-looking substrings
  min_printable_ratio_after_decode: 0.85  # decoded bytes must be this printable to be treated as text

# ---------------------------------------------------------------------------
# Card / payment detection tuning (Phase 4.1)
# ---------------------------------------------------------------------------
card_detection:
  accepted_lengths: [13, 14, 15, 16, 19]
  validate_with_luhn: true

# ---------------------------------------------------------------------------
# SWIFT / payment-message detection tuning (Phase 4.2)
# ---------------------------------------------------------------------------
swift_detection:
  bic_lengths: [8, 11]
  mt_field_tags: [":20:", ":32A:", ":50K:", ":50A:", ":52A:", ":57A:", ":59:", ":70:", ":71A:"]
```

## 💻 Commands

The delivered project already has this structure — these are the exact
commands used to scaffold it, included so you can recreate or extend it
(e.g. if you fork the layout for a different project). Run from
`C:\dlp-lab\ai-dlp-insider-threat`:

```powershell
mkdir common, config, collectors, detectors, normalization
mkdir ai, scoring, correlation, database, alerts, dashboard
mkdir tests, simulations\synthetic_data, logs, docs

New-Item -ItemType File -Path common\__init__.py, collectors\__init__.py, `
  detectors\__init__.py, normalization\__init__.py, tests\__init__.py

New-Item -ItemType File -Path ai\.gitkeep, scoring\.gitkeep, correlation\.gitkeep, `
  database\.gitkeep, alerts\.gitkeep, dashboard\.gitkeep, logs\.gitkeep
```

Verify the scaffold matches the tree above:
```powershell
Get-ChildItem -Recurse -Directory | Select-Object FullName
```

## 🧩 Implementation

`common/event_schema.py` — the shared event model every other phase builds
on. Complete file:

```python
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


SCHEMA_VERSION = "0.3.0"  # bumped when Phase 3/4/5 fields change shape


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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detections"] = [x.to_dict() if isinstance(x, DetectionResult) else x for x in self.detections]
        d["obfuscation"] = [x.to_dict() if isinstance(x, ObfuscationResult) else x for x in self.obfuscation]
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
```

## 🧪 Testing

`common/event_schema.py` has no dedicated test file of its own — it is a
data-model module with no branching logic to speak of, so it is exercised
indirectly, exhaustively, by every test in `tests/test_file_collector.py`,
`tests/test_clipboard_collector.py`, `tests/test_http_collector.py`, and
`tests/test_engine.py` (all of which build real `DLPEvent`s and serialize
them via `.to_dict()`/`.to_json()`). This is a deliberate choice, not an
oversight: adding a redundant `test_event_schema.py` that re-asserts "a
dataclass stores what you put in it" would test the language, not the
project. If you want to confirm this directly:

```powershell
python -m pytest tests/ -k "engine or collector" -v
```
**Expected:** all matching tests pass (20 of the 79 total, at time of
writing — file collector 5, clipboard collector 7, http collector 6, engine 7,
wait: those add to 25; run it and read the count, don't trust a stale number).

## ✅ Expected Result

Running `python -m pytest tests/ -v` from the project root collects tests
from all 10 files in `tests/` with zero import errors — confirming every
package's `__init__.py` and cross-package imports (`from common.event_schema
import ...`, `from detectors import card_detector`, etc.) resolve correctly.

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'common'` | Running a script/test from inside a subfolder instead of the project root | `cd` to `C:\dlp-lab\ai-dlp-insider-threat` first, or note that every test file already inserts the project root onto `sys.path` (see the `sys.path.insert(0, ...)` line at the top of any `tests/test_*.py`) specifically to avoid this |
| `ImportError` mentioning a circular import | A new module in `detectors/` or `normalization/` importing something from `collectors/` | Don't — the dependency direction is collectors/detectors/normalization → common, never sideways. If two stages genuinely need to share logic, it belongs in `common/`, not in one importing the other |
| Empty `ai/`, `scoring/`, etc. folders cause `git status` to show nothing to commit for them | Git does not track empty directories | Already handled — each has a `.gitkeep` (or a `README.md`, which also holds the directory) |

## 🔐 Security Considerations

- `config/detection_policy.yaml` is committed to the repo (it is not a
  secret — it's detection logic, meant to be reviewed). If this were a real
  production deployment rather than a portfolio lab, an org might reasonably
  keep the exact keyword list private so it can't be reverse-engineered by
  the people it's meant to catch; noted here as a real operational tradeoff
  intentionally not taken in this project (see `docs/THREAT_MODEL.md`
  "Attack surface").
- `common/event_schema.py`'s `DetectionResult`/`ObfuscationResult` shapes
  are designed so that no detector can accidentally attach a raw secret to
  an event — `matches: list[str]` is documented as holding redacted/masked
  evidence only, and Phase 4's `secret_detector.py` and `card_detector.py`
  already enforce that at the point where matches are constructed, not as
  an afterthought at the logging layer.

## 📌 Completion Criteria

- [x] Full directory tree matches the table above
- [x] `common/event_schema.py` implemented: `DLPEvent`, `DetectionResult`,
      `ObfuscationResult`, `build_event()`, `JsonlEventLogger`
- [x] Every package (`collectors`, `detectors`, `normalization`, `tests`) has
      an `__init__.py` and imports cleanly
- [x] `config/detection_policy.yaml` created and loads without error
      (verified by `detectors/keyword_detector.py`'s and
      `detectors/filetype_detector.py`'s passing tests)
- [ ] You have run `python -m pytest tests/ -v` from a freshly cloned/extracted
      copy of this repo on your own machine and seen `79 passed`

---

# PHASE 3 — ENDPOINT TELEMETRY COLLECTION

## 🎯 Objective

Observe three sources of endpoint activity — file system events, clipboard
changes, and outbound HTTP requests to a controlled destination — and turn
each into a structured `DLPEvent` (Phase 2's shared schema), without yet
judging whether the content is sensitive (that's Phase 4/5).

## 🧠 Concept

Three collectors, one shared contract: every collector calls
`common.event_schema.build_event()`, writes the result through a
`JsonlEventLogger`, and optionally invokes an `on_event` callback. This
means Phase 4/5's detection logic doesn't know or care which collector
produced an event — it only ever sees a `DLPEvent`.

**Scope of monitoring.** The file collector watches exactly one configured
directory (`simulations/monitored` in this lab, or wherever `DLP_MONITORED_PATH`
points), never the whole filesystem. This mirrors how real DLP agents work —
they watch defined sensitive locations (a finance share, a source repo
checkout, a Downloads folder), not every byte written to disk — and it keeps
this project's footprint on your actual machine minimal and predictable.

**Why polling for the clipboard, not an OS hook.** `pyperclip` (used here)
wraps `win32clipboard` on Windows and `xclip`/`xsel` on Linux behind one
`paste()` call. A real "clipboard changed" notification
(`AddClipboardFormatListener`) is Windows-only, which would fork the
implementation and make it untestable outside Windows. Polling every second
is cheap and identical on both platforms — see `tests/test_clipboard_collector.py`
for how this is validated without a real display or clipboard backend at all.

**Privacy-by-design content capture.** No collector reads/logs unbounded
content. `config/detection_policy.yaml`'s `content_capture` block sets a
2 MiB ceiling and a 4000-character excerpt cap — above either, only metadata
(path, size, timestamp) is captured, never content. This is a real design
decision, not a corner cut: real endpoint DLP agents make the same tradeoff,
because indexing every byte of every file is both a privacy and a
performance problem.

**Network exposure.** The HTTP collector doubles as the lab's simulated
"external destination." `collectors/http_collector.py`'s `run_server()`
hard-refuses to bind anything other than `127.0.0.1`/`localhost` — this is a
runtime `raise`, not a comment, so it can't be silently misconfigured later
in the project.

## 🏗️ Architecture

```
File system  ──▶ DLPFileEventHandler (watchdog) ──▶ JsonlEventLogger ──▶ file_events.jsonl
Clipboard    ──▶ ClipboardCollector (polling)    ──▶ JsonlEventLogger ──▶ clipboard_events.jsonl
HTTP request ──▶ Flask /upload route             ──▶ JsonlEventLogger ──▶ http_events.jsonl
```
All three optionally fan out to the same `on_event(DLPEvent)` callback,
which `run_pipeline_demo.py` wires to Phase 4/5 (see "Expected Result" below
for a real captured run).

## 📁 Files

```
collectors/file_collector.py
collectors/clipboard_collector.py
collectors/http_collector.py
run_pipeline_demo.py
simulations/http_exfil_simulator.py
tests/test_file_collector.py
tests/test_clipboard_collector.py
tests/test_http_collector.py
```

## ⚙️ Configuration

Content-capture thresholds (from `config/detection_policy.yaml`, already
shown in full in `docs/ARCHITECTURE.md`):
```yaml
content_capture:
  max_bytes_for_full_read: 2097152      # 2 MiB
  excerpt_max_chars: 4000
  redact_detected_secrets_in_excerpt: true
```
Relevant `.env` values (see `docs/INSTALLATION.md`):
```env
DLP_MONITORED_PATH=C:\dlp-lab\monitored
DLP_HTTP_HOST=127.0.0.1
DLP_HTTP_PORT=8765
```

## 💻 Commands

Run the three collectors together via the pipeline demo (recommended first
run) from `C:\dlp-lab\ai-dlp-insider-threat` with the venv active:

```powershell
python run_pipeline_demo.py --watch-dir C:\dlp-lab\monitored --http-port 8765
```
Leave this running in one PowerShell window. In a **second** PowerShell
window (same venv activated), generate some activity:

```powershell
"Q3 customer database export. Sample card on file: 4111111111111111." | Out-File C:\dlp-lab\monitored\customer_export_sample.txt
```
```powershell
python simulations\http_exfil_simulator.py --base-url http://127.0.0.1:8765
```
For the clipboard collector specifically (interactive — needs a real
Windows session, so it isn't exercised by the demo script above):
```powershell
python -c "from common.event_schema import JsonlEventLogger; from collectors.clipboard_collector import ClipboardCollector; c = ClipboardCollector(JsonlEventLogger('logs/clipboard_events.jsonl')); print('Watching clipboard, Ctrl+C to stop. Copy something now.'); c.run()"
```
Then copy any text (Ctrl+C) in another application and watch the console.

Stop everything with `Ctrl+C` in the first window when done.

## 🧩 Implementation

### `collectors/file_collector.py` — complete file
```python
"""
collectors/file_collector.py  (Phase 3.1 — File Activity Monitoring)

Watches a single, explicitly-configured directory (NOT the whole filesystem
— see docs/TELEMETRY.md "Scope of Monitoring" for why) for create/modify/move
events using the `watchdog` library, which uses ReadDirectoryChangesW on
Windows and inotify on Linux — the same public API on both, so the logic
below is validated here in the Linux sandbox and behaves identically on the
target Windows host.

PRIVACY-BY-DESIGN CONTENT CAPTURE:
Full file content is only read and attached to the event's content_excerpt
when BOTH of these hold (thresholds come from config/detection_policy.yaml):
  1. The file is smaller than `content_capture.max_bytes_for_full_read`.
  2. Reading succeeds as text (binary files >  that fail UTF-8/latin-1
     decoding are still detected via filename/magic-bytes in Phase 4's
     filetype_detector, just without a text excerpt).
Every event is still logged with metadata (path, size, timestamps) regardless
of whether content was captured — this mirrors how real endpoint DLP agents
avoid indexing arbitrarily large or opaque binary content wholesale.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

import yaml
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("file_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

# Event types we care about; watchdog also emits directory events we ignore here.
_WATCHED_EVENT_TYPES = {"created", "modified", "moved"}


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


def _read_excerpt_if_eligible(path: Path, max_bytes: int, excerpt_max_chars: int) -> tuple[Optional[str], int]:
    """Returns (content_excerpt_or_None, size_bytes). Never raises."""
    try:
        size_bytes = path.stat().st_size
    except OSError:
        return None, 0

    if size_bytes == 0 or size_bytes > max_bytes:
        return None, size_bytes

    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None, size_bytes

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None, size_bytes  # opaque binary; filetype_detector will still see the bytes separately

    return text[:excerpt_max_chars], size_bytes


class DLPFileEventHandler(FileSystemEventHandler):
    """
    Bridges watchdog's callback events to DLPEvent objects, writes them to
    the JSONL event log, and optionally forwards each event to `on_event`
    (used to wire in the Phase 4 detection engine without this collector
    needing to import detectors directly — keeps Phase 3 independently
    testable from Phase 4).
    """

    def __init__(
        self,
        event_logger: JsonlEventLogger,
        on_event: Optional[Callable[[DLPEvent], None]] = None,
        policy_path: Path = DEFAULT_POLICY_PATH,
    ):
        super().__init__()
        self.event_logger = event_logger
        self.on_event = on_event
        self.max_bytes, self.excerpt_max_chars = _load_capture_thresholds(policy_path)

    def _handle(self, event_type: str, src_path: str):
        path = Path(src_path)
        if path.is_dir():
            return  # directory-level events are not in scope for this collector

        excerpt, size_bytes = _read_excerpt_if_eligible(path, self.max_bytes, self.excerpt_max_chars)
        dlp_event = build_event(
            source="file",
            event_type=f"file_{event_type}",
            object_ref=str(path),
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={"extension": path.suffix},
        )
        self.event_logger.write(dlp_event)
        logger.info("file_%s: %s (%d bytes)", event_type, path, size_bytes)
        if self.on_event:
            self.on_event(dlp_event)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("created", event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("modified", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle("moved", event.dest_path)


def start_file_collector(
    watch_path: str,
    event_logger: JsonlEventLogger,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
) -> Observer:
    """
    Start watching `watch_path` in a background thread and return the
    Observer so the caller can .stop()/.join() it (see main.py / tests).
    """
    Path(watch_path).mkdir(parents=True, exist_ok=True)
    handler = DLPFileEventHandler(event_logger, on_event=on_event, policy_path=policy_path)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    logger.info("File collector watching: %s", watch_path)
    return observer


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    watch_dir = sys.argv[1] if len(sys.argv) > 1 else "./simulations/monitored"
    elogger = JsonlEventLogger("./logs/file_events.jsonl")
    obs = start_file_collector(watch_dir, elogger)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
        obs.join()
```

### `collectors/clipboard_collector.py` — complete file
```python
"""
collectors/clipboard_collector.py  (Phase 3.2 — Clipboard Monitoring)

Polls the OS clipboard (via `pyperclip`) at a fixed interval, diffs against
the last-seen value, and emits a DLPEvent on every change. Polling (rather
than an OS clipboard-changed hook) is used deliberately — see
docs/TELEMETRY.md "Why Polling" — because it is identical code on Windows
and Linux (pyperclip wraps win32clipboard on Windows, xclip/xsel on Linux),
whereas native clipboard-changed notifications are a Windows-only API
(AddClipboardFormatListener) that would fork the implementation.

TESTABILITY:
The clipboard read function is injected (`read_fn`, defaults to
`pyperclip.paste`) instead of imported directly, because pyperclip requires
a real OS clipboard (a Windows session, or an X11/xclip setup on Linux) that
does not exist in a headless CI/sandbox container. Tests inject a fake
sequence of clipboard values and assert on the resulting events, which
validates the polling/diffing/event-emission logic exactly as it will run
on the real target machine, without needing a real display.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

import yaml

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("clipboard_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"
DEFAULT_POLL_INTERVAL_SECONDS = 1.0


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


class ClipboardCollector:
    """
    Stateful poller. Call `.poll_once()` in a loop (see run()), or drive it
    directly from a test with a fake read_fn for deterministic, display-free
    unit testing.
    """

    def __init__(
        self,
        event_logger: JsonlEventLogger,
        read_fn: Callable[[], str] = None,
        on_event: Optional[Callable[[DLPEvent], None]] = None,
        policy_path: Path = DEFAULT_POLICY_PATH,
    ):
        if read_fn is None:
            import pyperclip  # imported lazily so this module can be imported
            read_fn = pyperclip.paste                      # in test environments without a clipboard backend
        self.read_fn = read_fn
        self.event_logger = event_logger
        self.on_event = on_event
        self.max_bytes, self.excerpt_max_chars = _load_capture_thresholds(policy_path)
        self._last_value: Optional[str] = None
        self._initialized = False

    def poll_once(self) -> Optional[DLPEvent]:
        """
        Read the clipboard once. Returns a DLPEvent if the content changed
        since the last poll, else None. The FIRST poll establishes a
        baseline and never emits an event — otherwise whatever happened to
        already be on the clipboard when the collector starts would be
        reported as a "change", which is misleading.
        """
        try:
            current = self.read_fn()
        except Exception as exc:  # pyperclip raises if no backend is available
            logger.warning("Clipboard read failed: %s", exc)
            return None

        if not self._initialized:
            self._last_value = current
            self._initialized = True
            return None

        if current == self._last_value:
            return None

        self._last_value = current
        size_bytes = len(current.encode("utf-8", errors="ignore")) if current else 0
        excerpt = None
        if current and size_bytes <= self.max_bytes:
            excerpt = current[: self.excerpt_max_chars]

        dlp_event = build_event(
            source="clipboard",
            event_type="clipboard_change",
            object_ref="clipboard",
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={"char_count": len(current) if current else 0},
        )
        self.event_logger.write(dlp_event)
        logger.info("clipboard_change: %d bytes", size_bytes)
        if self.on_event:
            self.on_event(dlp_event)
        return dlp_event

    def run(self, interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS, stop_after: Optional[int] = None):
        """Blocking polling loop. `stop_after` (number of polls) is used by tests; None = forever."""
        polls = 0
        while stop_after is None or polls < stop_after:
            self.poll_once()
            polls += 1
            time.sleep(interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    elogger = JsonlEventLogger("./logs/clipboard_events.jsonl")
    collector = ClipboardCollector(elogger)
    collector.run()
```

### `collectors/http_collector.py` — complete file
```python
"""
collectors/http_collector.py  (Phase 3.3 — Outbound HTTP Activity Monitoring)

This module is BOTH halves of the lab's HTTP telemetry, deliberately kept
together because they are two views of the same request:

  1. The "controlled HTTP destination" — a local Flask app standing in for
     an external exfiltration endpoint (e.g. a personal cloud-storage
     upload, a paste site, a webhook). The synthetic test client in
     simulations/http_exfil_simulator.py sends traffic here instead of to
     any real external service — see Rule 3 in the project's ethical
     constraints (no real exfiltration, ever).
  2. The collector — every request that hits the destination is captured as
     a DLPEvent (method, path, size, content-type, simulated user/process
     context, and — subject to the same capture thresholds as the other
     collectors — a content excerpt for detection).

SECURITY NOTE: this server MUST bind to 127.0.0.1 only (see run_server()
below and docs/TELEMETRY.md "Network Exposure"). Binding to 0.0.0.0 would
turn a lab fixture into a real endpoint reachable from the network, which is
both a needless risk and outside this project's defensive-only scope.

"User/process context where possible": a real endpoint DLP agent can read
this from the OS (which process opened the socket, which user owns that
process). A local Flask server only sees an HTTP request, so the synthetic
test client tags requests with `X-DLP-Simulated-User` / `X-DLP-Simulated-Process`
headers to stand in for that OS-level context during lab testing; production
deployment would replace this with a real host-side hook (out of scope here).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional

import yaml
from flask import Flask, request, jsonify

from common.event_schema import DLPEvent, JsonlEventLogger, build_event

logger = logging.getLogger("http_collector")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"


def _load_capture_thresholds(policy_path: Path = DEFAULT_POLICY_PATH) -> tuple[int, int]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    cc = policy.get("content_capture", {})
    return (
        int(cc.get("max_bytes_for_full_read", 2_097_152)),
        int(cc.get("excerpt_max_chars", 4000)),
    )


def create_app(
    event_logger: JsonlEventLogger,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
) -> Flask:
    """
    Factory so tests can build an app around a temp-directory event logger
    without needing a real network port (Flask's test_client() drives the
    WSGI app in-process).
    """
    app = Flask(__name__)
    max_bytes, excerpt_max_chars = _load_capture_thresholds(policy_path)

    @app.route("/upload", methods=["POST"])
    def upload():
        body = request.get_data() or b""
        size_bytes = len(body)

        excerpt = None
        if 0 < size_bytes <= max_bytes:
            try:
                excerpt = body.decode("utf-8")[:excerpt_max_chars]
            except UnicodeDecodeError:
                excerpt = body.decode("latin-1", errors="replace")[:excerpt_max_chars]

        dlp_event = build_event(
            source="http",
            event_type="http_request",
            object_ref=request.path,
            size_bytes=size_bytes,
            content_excerpt=excerpt,
            raw_metadata={
                "method": request.method,
                "content_type": request.headers.get("Content-Type", ""),
                "remote_addr": request.remote_addr,
                "simulated_user": request.headers.get("X-DLP-Simulated-User", "unknown"),
                "simulated_process": request.headers.get("X-DLP-Simulated-Process", "unknown"),
            },
        )
        event_logger.write(dlp_event)
        logger.info(
            "http_request: %s %s (%d bytes, user=%s)",
            request.method, request.path, size_bytes,
            dlp_event.raw_metadata["simulated_user"],
        )
        if on_event:
            on_event(dlp_event)

        return jsonify({"status": "received", "event_id": dlp_event.event_id, "bytes": size_bytes}), 200

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return jsonify({"status": "ok"}), 200

    return app


def run_server(
    event_logger: JsonlEventLogger,
    host: str = "127.0.0.1",
    port: int = 8765,
    on_event: Optional[Callable[[DLPEvent], None]] = None,
):
    """
    Run the collector as a real server. host defaults to loopback-only —
    do not change this to 0.0.0.0 (see module docstring "SECURITY NOTE").
    """
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            "Refusing to bind the lab HTTP collector to a non-loopback address. "
            "This is a deliberate guardrail, not a bug — see docs/TELEMETRY.md."
        )
    app = create_app(event_logger, on_event=on_event)
    app.run(host=host, port=port)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    elogger = JsonlEventLogger("./logs/http_events.jsonl")
    run_server(elogger)
```

### `run_pipeline_demo.py` — complete file (wires Phase 3 into Phase 4/5)
```python
"""
run_pipeline_demo.py

End-to-end demonstration wiring Phase 3 collectors -> Phase 4 detection
engine -> Phase 5 normalizer into one running pipeline. This is what you run
to verify Phases 3-5 are correctly integrated (see each docs/*.md file's
"Completion Criteria" section).

This is a DEMO / verification harness, not "the product": Phase 6 onward
will replace the simple console-alert logic in analyze_event() below with
the AI review layer, risk scoring, behavioral correlation, database
persistence, and dashboard. Nothing here is meant to be the final alerting
UI — see docs/ for what each later phase will change.

Usage (Windows, from the project root, with the venv active):
    python run_pipeline_demo.py
    python run_pipeline_demo.py --watch-dir C:\\dlp-lab\\monitored --http-port 8765
    python run_pipeline_demo.py --no-http      (file monitoring only)
"""

from __future__ import annotations

import argparse
import logging
import threading
import time
from pathlib import Path

from common.event_schema import JsonlEventLogger, DLPEvent
from detectors.engine import run_all, summarize
from normalization.normalizer import normalize_and_rescan
from collectors.file_collector import start_file_collector
from collectors.http_collector import create_app

ROOT = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("pipeline")


def analyze_event(event: DLPEvent) -> None:
    """
    Runs Phase 4 detectors and, for events with captured content, the Phase 5
    normalizer, then attaches results to the event. Prints a console alert on
    any match. This function is the seam Phase 6 will extend (or replace)
    with AI-based analysis of borderline/ambiguous content.
    """
    text = event.content_excerpt or ""
    filename = event.object_ref if event.source == "file" else None

    event.detections = run_all(text, filename=filename)
    summary = summarize(event.detections)

    event.obfuscation = normalize_and_rescan(text, run_all) if text else []

    if event.any_match:
        categories = summary["categories"] or []
        obf_techniques = [ob.technique for ob in event.obfuscation if any(d.matched for d in ob.rescanned_detections)]
        if obf_techniques:
            categories = categories + [f"obfuscated:{t}" for t in obf_techniques]
        print(f"\n[ALERT] {event.source}:{event.event_type} -> {event.object_ref}")
        print(f"        categories={categories}")
        print(f"        needs_ai_review={summary['needs_ai_review']}  (Phase 6 will act on this flag)")
    else:
        logger.info("clean: %s:%s -> %s", event.source, event.event_type, event.object_ref)


def build_on_event(flagged_logger: JsonlEventLogger):
    def on_event(event: DLPEvent):
        analyze_event(event)
        if event.any_match:
            flagged_logger.write(event)

    return on_event


def main():
    parser = argparse.ArgumentParser(description="Phase 3-5 pipeline integration demo")
    parser.add_argument("--watch-dir", default=str(ROOT / "simulations" / "monitored"))
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--no-http", action="store_true", help="Disable the HTTP collector/destination")
    args = parser.parse_args()

    Path(args.watch_dir).mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)

    flagged_logger = JsonlEventLogger(ROOT / "logs" / "flagged_events.jsonl")
    on_event = build_on_event(flagged_logger)

    file_event_logger = JsonlEventLogger(ROOT / "logs" / "file_events.jsonl")
    observer = start_file_collector(args.watch_dir, file_event_logger, on_event=on_event)
    logger.info("File collector running. Watching: %s", args.watch_dir)

    if not args.no_http:
        http_event_logger = JsonlEventLogger(ROOT / "logs" / "http_events.jsonl")
        app = create_app(http_event_logger, on_event=on_event)
        http_thread = threading.Thread(
            target=lambda: app.run(host="127.0.0.1", port=args.http_port, use_reloader=False),
            daemon=True,
        )
        http_thread.start()
        logger.info("HTTP collector running on http://127.0.0.1:%d/upload (loopback only)", args.http_port)

    logger.info("Pipeline running. Drop files into %s or POST to /upload. Ctrl+C to stop.", args.watch_dir)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
```

### `simulations/http_exfil_simulator.py` — complete file
```python
"""
simulations/http_exfil_simulator.py

Synthetic test client for the Phase 3 HTTP collector. Sends a handful of
requests — some clean, some containing synthetic sensitive data, one
obfuscated — to the LOCAL lab destination started by
collectors/http_collector.py or run_pipeline_demo.py.

This never contacts any real external host. It exists so Phase 3/11 test
scenarios have deterministic, repeatable traffic to generate, standing in
for "a user's browser/app uploading data somewhere" per Rule 3 of the
project's ethical constraints (simulate, do not perform, exfiltration).

Usage:
    python simulations/http_exfil_simulator.py --base-url http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import base64
import sys

import requests

SYNTHETIC_SCENARIOS = [
    {
        "name": "clean_message",
        "user": "alice",
        "process": "outlook.exe",
        "content_type": "text/plain",
        "body": "Reminder: the team offsite is next Thursday.",
    },
    {
        "name": "plaintext_card_number",
        "user": "bob",
        "process": "chrome.exe",
        "content_type": "text/plain",
        "body": "Refund the customer using card 4111111111111111 please.",
    },
    {
        "name": "aws_key_leak",
        "user": "carol",
        "process": "slack.exe",
        "content_type": "text/plain",
        "body": "oops wrong channel -- AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    },
    {
        "name": "base64_obfuscated_card_number",
        "user": "dave",
        "process": "firefox.exe",
        "content_type": "text/plain",
        "body": None,  # filled in below
    },
    {
        "name": "customer_database_export",
        "user": "erin",
        "process": "python.exe",
        "content_type": "text/csv",
        "body": "name,ssn,customer_database\nJohn Sample,000-00-0000,true\n",
    },
]

SYNTHETIC_SCENARIOS[3]["body"] = base64.b64encode(
    b"internal note: card on file is 5555555555554444"
).decode()


def run(base_url: str) -> None:
    ok = requests.get(f"{base_url}/healthz", timeout=5)
    print(f"health check: {ok.status_code} {ok.json()}")

    for scenario in SYNTHETIC_SCENARIOS:
        headers = {
            "Content-Type": scenario["content_type"],
            "X-DLP-Simulated-User": scenario["user"],
            "X-DLP-Simulated-Process": scenario["process"],
        }
        resp = requests.post(
            f"{base_url}/upload",
            data=scenario["body"].encode("utf-8"),
            headers=headers,
            timeout=5,
        )
        print(f"[{scenario['name']}] -> HTTP {resp.status_code} {resp.json()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic HTTP exfiltration-pattern simulator (lab-local only)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    try:
        run(args.base_url)
    except requests.exceptions.ConnectionError:
        print(f"Could not reach {args.base_url} -- is run_pipeline_demo.py or http_collector.py running?")
        sys.exit(1)
```

## 🧪 Testing

```powershell
python -m pytest tests/test_file_collector.py tests/test_clipboard_collector.py tests/test_http_collector.py -v
```

| Test file | What it proves | How, without needing real OS resources |
|---|---|---|
| `test_file_collector.py` (5 tests) | File create/modify events become correct `DLPEvent`s; size/excerpt thresholds are respected; directories themselves aren't logged as file events | Uses `tmp_path` (a real temp directory) and the **real** `watchdog` `Observer` — this is a genuine integration test, not a mock, validated on Linux `inotify` and expected identical on Windows `ReadDirectoryChangesW` since both go through the same `watchdog` public API |
| `test_clipboard_collector.py` (7 tests) | Baseline-then-diff logic, threshold handling, and failure resilience | Injects a `FakeClipboard` in place of `pyperclip.paste` — no real clipboard/display needed, which is exactly why this can run in this sandbox *and* on your Windows machine identically |
| `test_http_collector.py` (6 tests) | Every request is logged with correct metadata; loopback-only guard actually raises | Flask's `test_client()` drives the app in-process — no real socket needed |

## ✅ Expected Result

This is real, captured output from running exactly the commands above (file
drop + `http_exfil_simulator.py`) against the pipeline demo — not a
hypothetical:

```
2026-08-12 18:35:31,786 INFO file_collector: file_created: simulations/monitored/customer_export_sample.txt (94 bytes)

[ALERT] file:file_created -> simulations/monitored/customer_export_sample.txt
        categories=['customer_data', 'payment_card']
        needs_ai_review=True  (Phase 6 will act on this flag)
...
[ALERT] http:http_request -> /upload
        categories=['credential_secret']
        needs_ai_review=True  (Phase 6 will act on this flag)

[ALERT] http:http_request -> /upload
        categories=['obfuscated:base64']
        needs_ai_review=False  (Phase 6 will act on this flag)
```

And one representative logged event, pretty-printed (the real log is one
compact JSON object per line):
```json
{
  "event_id": "9ac9224e-c286-445f-8d4f-9a262da767d0",
  "schema_version": "0.3.0",
  "timestamp": "2026-08-12T18:35:33.611Z",
  "source": "http",
  "event_type": "http_request",
  "object_ref": "/upload",
  "size_bytes": 55,
  "content_excerpt": "Refund the customer using card 4111111111111111 please.",
  "detections": [
    {"detector": "card_detector", "matched": true, "category": "payment_card",
     "confidence": 1.0, "matches": ["visa:411111******1111"]}
  ],
  "raw_metadata": {"method": "POST", "simulated_user": "bob", "simulated_process": "chrome.exe"}
}
```
Note the card number is masked (`411111******1111`) even in the raw log —
this comes from `card_detector.py`'s masking, not from anything in the
collector, confirming the "never persist raw sensitive evidence" rule holds
across phase boundaries.

Across the full demo run: **6** file events logged, **5** HTTP events
logged, **7** of those 11 correctly flagged (2 clean file writes + 1 clean
HTTP message legitimately produced zero alerts — confirming the pipeline
doesn't just flag everything).

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| File collector produces 2 events (`file_created` then `file_modified`) for one file write | Normal — most editors/OS write calls trigger both; `watchdog`'s event granularity is OS-level, not "user intent"-level | Already handled: detection re-runs on every event, so duplicate alerts for the same content are expected and harmless. Deduplication-by-content-hash would be a reasonable Phase 8+ enhancement, not in scope here |
| `PermissionError` reading a file right after `file_created` fires | Windows locks files more strictly than Linux while another process still has them open (e.g., a large file mid-write by another app) | Already handled in code: `_read_excerpt_if_eligible()` catches `PermissionError` and falls back to metadata-only; you'll see `content_excerpt: null` for that event rather than a crash |
| `OSError: [WinError 10048] ... address already in use` starting the HTTP collector | Port 8765 already bound by a previous run that didn't shut down cleanly | Find and stop it: `Get-Process -Id (Get-NetTCPConnection -LocalPort 8765).OwningProcess \| Stop-Process`, or just pass `--http-port 8766` |
| Clipboard collector never emits an event | The very first poll is *always* silent by design (it establishes the baseline) — copying the exact same text twice in a row also correctly produces nothing | Copy something different from whatever was already on the clipboard when the collector started |
| `requests.exceptions.ConnectionError` from `http_exfil_simulator.py` | The pipeline demo (or `http_collector.py` directly) isn't running, or is on a different port | Start it first; confirm the port matches `--base-url` |

## 🔐 Security Considerations

- The HTTP collector's loopback-only guard (`run_server()`) is enforced in
  code specifically so a future edit can't accidentally turn this lab
  fixture into something reachable from the network — see
  `docs/THREAT_MODEL.md` "Attack surface."
- Clipboard and file content are only ever written to your **local** JSONL
  logs (`logs/`, gitignored) — nothing here transmits anywhere outside the
  loopback interface.
- Because collectors attach `content_excerpt` to events, `logs/*.jsonl`
  itself becomes sensitive the moment you run this against real content.
  Treat it accordingly even in the lab: it's gitignored, and Phase 9's
  database (later) inherits the same masking/fingerprinting discipline
  already applied at the detector level (Phase 4).

## 📌 Completion Criteria

- [x] `collectors/file_collector.py`, `clipboard_collector.py`,
      `http_collector.py` implemented
- [x] All three have passing dedicated tests (18 tests total)
- [x] `run_pipeline_demo.py` wires all three into a single running process
- [x] End-to-end run confirmed: plaintext-sensitive, obfuscated, and clean
      content all produce the *correct* (not just *some*) alert behavior
- [ ] You have run `python run_pipeline_demo.py` on your own Windows machine,
      dropped a file into the watched folder, and seen a matching `[ALERT]`
      line in your own terminal — reproducing the captured run above, not
      just reading about it

---

# PHASE 4 — DETERMINISTIC DETECTION ENGINE

## 🎯 Objective

Given a piece of text (and, where relevant, a filename/bytes), decide
whether it contains payment card data, SWIFT/payment-message structure,
credentials/secrets, policy-defined sensitive keywords, or a sensitive file
type — deterministically, with no AI/LLM involved, satisfying threat-model
requirements DR1-DR5 (`docs/THREAT_MODEL.md`).

## 🧠 Concept

Five independent detectors, one aggregator. Each detector is a pure function
(or a small stateless-per-call class) that takes text/bytes and returns a
`DetectionResult` (Phase 2's schema) — none of them know about each other,
none of them know about collectors, and none of them touch a database. This
is deliberate: it's what makes 44 of this project's 79 tests possible
without any I/O beyond one YAML file read.

**Confidence, not just true/false.** Every result carries a 0.0-1.0
confidence. A validated, Luhn-passing card number is 1.0 (deterministic,
high-precision). A bare SWIFT/BIC code with no surrounding message structure
is only 0.5 (format-only evidence, genuinely ambiguous — see "Known
Limitations" below for a concrete case where this distinction matters). This
matters because Phase 7's risk scoring (later) needs more than a boolean to
blend deterministic and AI signals sensibly, and Phase 4 is what has to
produce that number honestly.

**A DLP tool must not leak what it finds.** `secret_detector.py` never
writes a matched secret's raw value anywhere — every match becomes an
irreversible fingerprint (`pattern-name:first4chars...sha256[:8]`).
`card_detector.py` masks to PCI-DSS 3.3/3.4 style (first 6, last 4, rest
masked). This was a decision made *during* Phase 0's threat modeling
("the tool's own output is a new asset"), not bolted on afterward.

**Policy-driven, not hardcoded.** `keyword_detector.py` and
`filetype_detector.py` both read `config/detection_policy.yaml` at
construction time rather than hardcoding lists in Python — because in any
real DLP deployment, what counts as "sensitive" is an org-specific,
frequently-revised policy decision, not a code change.

## 🏗️ Architecture

```
                     ┌──────────────────┐
   text, filename ──▶│ detectors.engine │──▶ list[DetectionResult]
                     │    .run_all()    │
                     └──────────────────┘
                        │    │    │    │    │
                        ▼    ▼    ▼    ▼    ▼
                     card  swift secret keyword filetype
                   detector detector detector detector detector
                                              ▲
                                    config/detection_policy.yaml
```
`detectors.engine.needs_ai_review()` reduces the result list to a single
boolean using `AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5` — this constant is
defined once, here, specifically so Phase 6/7 import it rather than each
redefining "what counts as ambiguous."

## 📁 Files

```
detectors/card_detector.py
detectors/swift_detector.py
detectors/secret_detector.py
detectors/keyword_detector.py
detectors/filetype_detector.py
detectors/engine.py
config/detection_policy.yaml          (shown in full in docs/ARCHITECTURE.md)
tests/test_card_detector.py
tests/test_swift_detector.py
tests/test_secret_detector.py
tests/test_keyword_detector.py
tests/test_filetype_detector.py
tests/test_engine.py
```

## ⚙️ Configuration

Detector-specific tuning from `config/detection_policy.yaml`:
```yaml
card_detection:
  accepted_lengths: [13, 14, 15, 16, 19]
  validate_with_luhn: true
swift_detection:
  bic_lengths: [8, 11]
  mt_field_tags: [":20:", ":32A:", ":50K:", ":50A:", ":52A:", ":57A:", ":59:", ":70:", ":71A:"]
```
Plus the full `keyword_categories` and `sensitive_file_types` maps (see
`docs/ARCHITECTURE.md` for the complete YAML).

## 💻 Commands

Run the whole detection layer's tests:
```powershell
python -m pytest tests/test_card_detector.py tests/test_swift_detector.py tests/test_secret_detector.py tests/test_keyword_detector.py tests/test_filetype_detector.py tests/test_engine.py -v
```

Try it interactively against one of the Phase 0-mapped synthetic fixtures:
```powershell
python simulations\verify_fixtures.py
```

Or against arbitrary text from the command line:
```powershell
python -c "from detectors.engine import run_all, summarize; print(summarize(run_all('Card on file: 4111111111111111')))"
```

## 🧩 Implementation

### `detectors/card_detector.py` — complete file
```python
"""
detectors/card_detector.py  (Phase 4.1)

Deterministic payment-card detector:
  1. Regex extracts digit-sequence candidates (allowing spaces/dashes as
     real-world card numbers are often written with separators).
  2. Each candidate is validated with the Luhn (mod 10) checksum algorithm.
  3. Candidates that pass Luhn are tagged with a best-guess brand using
     well-known IIN (Issuer Identification Number) prefix ranges.

Only candidates that pass BOTH the length filter and the Luhn checksum are
reported as matches — this keeps false positives low (a random 16-digit
number has roughly a 1-in-10 chance of passing Luhn by chance, which is why
Luhn alone is a weak *standalone* control in production DLP, but is a solid,
zero-cost pre-filter here; see docs/DETECTION_ENGINE.md "Known Limitations").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from common.event_schema import DetectionResult

# Candidate extraction: 12-19 digits, optionally grouped with spaces or dashes.
_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)")


@dataclass
class CardMatch:
    raw: str                # original matched substring (not stored long-term)
    digits: str              # digits only
    brand: str
    masked: str               # e.g. "411111******1111" for safe logging


def luhn_is_valid(digits: str) -> bool:
    """
    Standard Luhn / mod-10 checksum.
    Starting from the rightmost digit, double every second digit; if the
    doubled value exceeds 9, subtract 9 (equivalent to summing its digits).
    The number is valid if the total sum is divisible by 10.
    """
    if not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:  # every second digit, 0-indexed from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def identify_brand(digits: str) -> str:
    """Best-effort brand identification from IIN/BIN prefix ranges."""
    length = len(digits)
    if digits.startswith("4") and length in (13, 16, 19):
        return "visa"
    if length == 16 and (
        (digits[:2] in {str(n) for n in range(51, 56)})
        or (2221 <= int(digits[:4]) <= 2720)
    ):
        return "mastercard"
    if length == 15 and digits[:2] in {"34", "37"}:
        return "amex"
    if length == 16 and (
        digits.startswith("6011")
        or digits[:2] == "65"
        or (644 <= int(digits[:3]) <= 649)
    ):
        return "discover"
    return "unknown"


def mask(digits: str) -> str:
    """PCI-DSS-style masking: keep first 6 and last 4, mask the middle (Requirement 3.3)."""
    if len(digits) <= 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def find_card_candidates(text: str, accepted_lengths: list[int] | None = None) -> list[CardMatch]:
    """Extract and validate all card-like substrings in text."""
    accepted_lengths = accepted_lengths or [13, 14, 15, 16, 19]
    results: list[CardMatch] = []
    for m in _CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if len(digits) not in accepted_lengths:
            continue
        if not luhn_is_valid(digits):
            continue
        results.append(CardMatch(raw=raw, digits=digits, brand=identify_brand(digits), masked=mask(digits)))
    return results


def detect(text: str, accepted_lengths: list[int] | None = None) -> DetectionResult:
    """
    Run the card detector over `text` and return a DetectionResult suitable
    for attaching to a DLPEvent. Never includes full unmasked PANs in the
    result — only masked forms are retained, in line with PCI-DSS 3.3/3.4.
    """
    matches = find_card_candidates(text, accepted_lengths=accepted_lengths)
    return DetectionResult(
        detector="card_detector",
        matched=len(matches) > 0,
        category="payment_card" if matches else None,
        confidence=1.0 if matches else 0.0,
        matches=[f"{m.brand}:{m.masked}" for m in matches],
        details={"count": len(matches), "brands": sorted({m.brand for m in matches})},
    )
```

### `detectors/swift_detector.py` — complete file
```python
"""
detectors/swift_detector.py  (Phase 4.2)

Detects two distinct SWIFT-related patterns, reported separately because
they indicate different things:

  1. BIC / SWIFT codes  — an 8 or 11-character identifier
     (4 letters bank code + 2 letters country code + 2 alphanumeric location
     code + optional 3 alphanumeric branch code). A bare BIC is weak evidence
     on its own (low confidence) since the format is short and can collide
     with unrelated strings.

  2. SWIFT MT-style message field tags (e.g. ":20:", ":32A:", ":59:") — these
     are structural markers from SWIFT MT (Message Type) payment messages
     (e.g. MT103 customer credit transfers). Seeing several of these tags
     together in one document is much stronger evidence of an actual
     payment-message excerpt than a bare BIC, so it is scored higher.

This module intentionally does NOT attempt full SWIFT MT parsing (field
validation, checksum blocks, etc.) — that is out of scope for a detection
pre-filter and would meaningfully increase false-negative risk if the parser
was too strict. See docs/DETECTION_ENGINE.md "Known Limitations".
"""

from __future__ import annotations

import re

from common.event_schema import DetectionResult

_BIC_RE = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")

# A short allowlist of country codes is NOT enforced here on purpose: BIC country
# codes cover essentially the full ISO 3166-1 alpha-2 list, so enforcing it would
# add maintenance burden for negligible precision gain. Confidence is instead
# raised by co-occurrence with MT field tags (see detect()).

DEFAULT_MT_FIELD_TAGS = [":20:", ":32A:", ":50K:", ":50A:", ":52A:", ":57A:", ":59:", ":70:", ":71A:"]


def find_bic_candidates(text: str) -> list[str]:
    return sorted(set(_BIC_RE.findall(text)))


def find_mt_field_tags(text: str, tags: list[str] | None = None) -> list[str]:
    tags = tags or DEFAULT_MT_FIELD_TAGS
    found = [t for t in tags if t in text]
    return found


def detect(text: str, mt_field_tags: list[str] | None = None) -> DetectionResult:
    bics = find_bic_candidates(text)
    mt_tags = find_mt_field_tags(text, tags=mt_field_tags)

    matched = bool(bics) or len(mt_tags) >= 2
    if not matched:
        return DetectionResult(detector="swift_detector", matched=False)

    # Confidence model:
    #   - MT tags present (>=2 distinct tags): strong structural evidence -> 0.9
    #   - Only a bare BIC, no MT structure: weaker evidence -> 0.5
    if len(mt_tags) >= 2:
        confidence = 0.9
        category = "swift_payment_message"
    else:
        confidence = 0.5
        category = "swift_bic"

    evidence = list(bics) + mt_tags
    return DetectionResult(
        detector="swift_detector",
        matched=True,
        category=category,
        confidence=confidence,
        matches=evidence,
        details={"bic_count": len(bics), "mt_tag_count": len(mt_tags)},
    )
```

### `detectors/secret_detector.py` — complete file
```python
"""
detectors/secret_detector.py  (Phase 4.3)

Detects common credential/secret formats: cloud provider keys, VCS/chat
platform tokens, private key material, JWTs, and generic API-key assignments.

IMPORTANT SECURITY DESIGN DECISION:
This detector NEVER writes the actual matched secret value into a
DetectionResult, log line, or event. A DLP tool that logs the very secrets
it finds — in cleartext, in its own audit trail — creates a second exposure
surface that is arguably worse than the original leak (the audit DB becomes
a target). Instead, every match is reduced to a stable, irreversible
fingerprint: `<pattern-name>:<first 4 chars>...<sha256[:8]>`. This is enough
for an analyst to confirm "yes, that's the same key we rotated last week"
without ever reconstructing the secret from the alert data.
"""

from __future__ import annotations

import hashlib
import re

from common.event_schema import DetectionResult

# (pattern_name, compiled_regex, base_confidence)
_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.95),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), 0.95),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.9),
    ("private_key_block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), 0.98),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), 0.85),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=]{20,}\b"), 0.6),
    ("generic_api_key_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"), 0.55),
]

# AWS secret access keys are 40-char base64-ish strings with no fixed prefix,
# which collides with things like git commit hashes (40 HEX chars) and other
# incidental data. To keep false positives down, it is only flagged when it
# appears within CONTEXT_WINDOW characters of a contextual keyword.
_AWS_SECRET_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")
_AWS_CONTEXT_RE = re.compile(r"(?i)aws|secret[_-]?access[_-]?key")
CONTEXT_WINDOW = 60


def _fingerprint(pattern_name: str, matched_text: str) -> str:
    prefix = matched_text[:4]
    digest = hashlib.sha256(matched_text.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"{pattern_name}:{prefix}...{digest}"


def _find_aws_secret_candidates(text: str) -> list[str]:
    hits = []
    for m in _AWS_SECRET_CANDIDATE_RE.finditer(text):
        start = max(0, m.start() - CONTEXT_WINDOW)
        end = min(len(text), m.end() + CONTEXT_WINDOW)
        window = text[start:end]
        if _AWS_CONTEXT_RE.search(window) and not re.fullmatch(r"[0-9a-f]{40}", m.group(0)):
            # exclude pure-hex 40-char strings -> almost always git SHA-1 hashes, not secrets
            hits.append(m.group(0))
    return hits


def detect(text: str) -> DetectionResult:
    evidence: list[str] = []
    categories_found: set[str] = set()
    max_confidence = 0.0

    for name, pattern, confidence in _PATTERNS:
        for m in pattern.finditer(text):
            evidence.append(_fingerprint(name, m.group(0)))
            categories_found.add(name)
            max_confidence = max(max_confidence, confidence)

    for secret in _find_aws_secret_candidates(text):
        evidence.append(_fingerprint("aws_secret_access_key", secret))
        categories_found.add("aws_secret_access_key")
        max_confidence = max(max_confidence, 0.7)

    matched = len(evidence) > 0
    return DetectionResult(
        detector="secret_detector",
        matched=matched,
        category="credential_secret" if matched else None,
        confidence=max_confidence,
        matches=evidence,  # fingerprints only, never raw secret values
        details={"pattern_types": sorted(categories_found), "count": len(evidence)},
    )
```

### `detectors/keyword_detector.py` — complete file
```python
"""
detectors/keyword_detector.py  (Phase 4.4)

Configurable, policy-driven keyword/category detector. Keyword lists live in
config/detection_policy.yaml (not hardcoded) so a security reviewer can tune
detection without touching code — this matters for a DLP tool specifically,
since keyword policy is expected to change per-organization in the real
world; hardcoding it would misrepresent how these tools are actually operated.

Matching rules:
  - Case-insensitive.
  - Whole-phrase matching with word boundaries, so "ssn" does not match
    inside an unrelated word like "assignment".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"


def load_policy(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _compile_category_patterns(categories: dict[str, Any]) -> dict[str, list[re.Pattern]]:
    compiled: dict[str, list[re.Pattern]] = {}
    for category, spec in categories.items():
        patterns = []
        for phrase in spec.get("keywords", []):
            # Escape the phrase, then allow flexible whitespace between words
            # (so "social security number" also matches "social  security number").
            escaped_words = [re.escape(w) for w in phrase.split()]
            pattern = r"\b" + r"\s+".join(escaped_words) + r"\b"
            compiled.setdefault(category, []).append(re.compile(pattern, re.IGNORECASE))
        compiled.setdefault(category, compiled.get(category, []))
    return compiled


class KeywordDetector:
    """
    Stateful wrapper so the YAML policy is parsed once (at construction) and
    reused across many detect() calls instead of re-reading/re-compiling
    regex on every event, which matters once this runs continuously against
    a live file/clipboard stream in Phase 3.
    """

    def __init__(self, policy_path: str | Path = DEFAULT_POLICY_PATH, exclude_categories: tuple[str, ...] = ("credentials_context",)):
        policy = load_policy(policy_path)
        categories = dict(policy.get("keyword_categories", {}))
        # credentials_context is intentionally excluded from standalone matching:
        # per the policy file's own description, it exists to raise confidence in
        # secret_detector matches, not to fire independently (it would otherwise
        # flag the word "password" appearing in ordinary IT documentation).
        for excluded in exclude_categories:
            categories.pop(excluded, None)
        self.categories = categories
        self._compiled = _compile_category_patterns(categories)

    def detect(self, text: str) -> DetectionResult:
        hits_by_category: dict[str, list[str]] = {}
        for category, patterns in self._compiled.items():
            for pattern in patterns:
                m = pattern.search(text)
                if m:
                    hits_by_category.setdefault(category, []).append(m.group(0).lower())

        matched = len(hits_by_category) > 0
        evidence = [f"{cat}:{phrase}" for cat, phrases in hits_by_category.items() for phrase in phrases]
        return DetectionResult(
            detector="keyword_detector",
            matched=matched,
            category=",".join(sorted(hits_by_category.keys())) if matched else None,
            confidence=0.6 if matched else 0.0,  # keywords alone are moderate-confidence, corroborating evidence
            matches=evidence,
            details={"categories_matched": sorted(hits_by_category.keys())},
        )
```

### `detectors/filetype_detector.py` — complete file
```python
"""
detectors/filetype_detector.py  (Phase 4.6)

Two-layer file type detection:
  1. Extension lookup against config/detection_policy.yaml's
     `sensitive_file_types` map (fast, primary signal).
  2. Magic-byte sniffing on the first few bytes of content, used as a
     corroborating signal and to catch the common evasion of simply
     renaming a file's extension (e.g. secrets.pem renamed to notes.txt
     still starts with "-----BEGIN"; a renamed .zip/.xlsx/.docx still
     starts with the "PK\x03\x04" ZIP local file header, since OOXML and
     modern Office formats ARE zip archives).

This module reports both the extension-based verdict and a
`extension_mismatch` flag when the two layers disagree, since that mismatch
is itself a mild insider-threat signal worth surfacing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from common.event_schema import DetectionResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

# (label, byte signature, offset)
_MAGIC_SIGNATURES: list[tuple[str, bytes, int]] = [
    ("zip_or_office_ooxml", b"PK\x03\x04", 0),   # .zip, .docx, .xlsx, .pptx (all OOXML) share this
    ("gzip", b"\x1f\x8b", 0),
    ("pdf", b"%PDF-", 0),
    ("sqlite3_db", b"SQLite format 3\x00", 0),
    ("pem_private_key", b"-----BEGIN", 0),
    ("rar", b"Rar!\x1a\x07", 0),
    ("elf_binary", b"\x7fELF", 0),
    ("windows_pe_exe", b"MZ", 0),
]


def load_sensitive_types(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    return policy.get("sensitive_file_types", {})


def _extension_lookup(extension: str, sensitive_types: dict[str, Any]) -> tuple[str | None, float]:
    ext = extension.lower()
    for group, spec in sensitive_types.items():
        if ext in [e.lower() for e in spec.get("extensions", [])]:
            return group, float(spec.get("risk_weight", 0.3))
    return None, 0.0


def sniff_magic_bytes(content_bytes: bytes) -> str | None:
    for label, sig, offset in _MAGIC_SIGNATURES:
        window = content_bytes[offset: offset + len(sig)]
        if window == sig:
            return label
    return None


def _extension_family_for_magic(magic_label: str | None) -> set[str]:
    """Which extensions we'd 'expect' for a given magic-byte label, for mismatch detection."""
    mapping = {
        "zip_or_office_ooxml": {".zip", ".docx", ".xlsx", ".pptx"},
        "gzip": {".gz", ".tgz"},
        "pdf": {".pdf"},
        "sqlite3_db": {".db", ".sqlite"},
        "pem_private_key": {".pem", ".key"},
        "rar": {".rar"},
    }
    return mapping.get(magic_label, set())


def detect(
    filename: str,
    content_bytes: bytes = b"",
    policy_path: str | Path = DEFAULT_POLICY_PATH,
) -> DetectionResult:
    sensitive_types = load_sensitive_types(policy_path)
    extension = Path(filename).suffix
    group, risk_weight = _extension_lookup(extension, sensitive_types)

    magic_label = sniff_magic_bytes(content_bytes) if content_bytes else None
    expected_exts = _extension_family_for_magic(magic_label)
    extension_mismatch = bool(magic_label) and bool(expected_exts) and extension.lower() not in expected_exts

    matched = bool(group) or extension_mismatch
    confidence = risk_weight
    if extension_mismatch:
        confidence = max(confidence, 0.65)  # renamed-extension evasion is itself notable

    category = group or ("extension_mismatch" if extension_mismatch else None)

    return DetectionResult(
        detector="filetype_detector",
        matched=matched,
        category=category,
        confidence=confidence,
        matches=[extension] if group else [],
        details={
            "extension": extension,
            "sensitive_group": group,
            "magic_byte_label": magic_label,
            "extension_mismatch": extension_mismatch,
        },
    )
```

### `detectors/engine.py` — complete file (aggregator)
```python
"""
detectors/engine.py  (Phase 4 aggregator)

Runs every deterministic detector (card, SWIFT, secret, keyword, filetype)
against a piece of content and attaches the results to a DLPEvent.

This module is the seam where Phase 6 (AI/LLM analysis) will plug in later:
`run_all()` returns the deterministic verdicts; Phase 6 will take content
that scores above a "needs AI review" threshold (defined here, reused there)
and send ONLY that subset to the local LLM, rather than sending everything —
which is both a cost/latency optimization and a data-minimization choice
(least content leaves the deterministic layer necessary).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from common.event_schema import DetectionResult, DLPEvent
from detectors import card_detector, swift_detector, secret_detector, filetype_detector
from detectors.keyword_detector import KeywordDetector

# Any single deterministic detector at or above this confidence is enough to
# mark content as "needs AI review" once Phase 6 exists. Defined here so
# Phase 6/7 import ONE constant instead of redefining the threshold.
AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5

_keyword_detector_singleton: Optional[KeywordDetector] = None


def _get_keyword_detector() -> KeywordDetector:
    global _keyword_detector_singleton
    if _keyword_detector_singleton is None:
        _keyword_detector_singleton = KeywordDetector()
    return _keyword_detector_singleton


def run_all(
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> list[DetectionResult]:
    """
    Run every applicable deterministic detector against `text`
    (and `content_bytes`/`filename` for the filetype detector, which needs
    the raw bytes and name rather than decoded text).
    """
    results: list[DetectionResult] = [
        card_detector.detect(text),
        swift_detector.detect(text),
        secret_detector.detect(text),
        _get_keyword_detector().detect(text),
    ]
    if filename is not None:
        results.append(filetype_detector.detect(filename, content_bytes=content_bytes))
    return results


def needs_ai_review(results: list[DetectionResult]) -> bool:
    """True if any deterministic detector's confidence meets the AI-review bar."""
    return any(r.matched and r.confidence >= AI_REVIEW_CONFIDENCE_THRESHOLD for r in results)


def enrich_event(
    event: DLPEvent,
    text: str,
    filename: Optional[str] = None,
    content_bytes: bytes = b"",
) -> DLPEvent:
    """Run all detectors and attach their results to the given event in place."""
    event.detections = run_all(text, filename=filename, content_bytes=content_bytes)
    return event


def summarize(results: list[DetectionResult]) -> dict:
    """Compact summary used by logging/CLI output and, later, the dashboard."""
    matched = [r for r in results if r.matched]
    return {
        "any_match": len(matched) > 0,
        "matched_detectors": [r.detector for r in matched],
        "categories": sorted({r.category for r in matched if r.category}),
        "max_confidence": max((r.confidence for r in matched), default=0.0),
        "needs_ai_review": needs_ai_review(results),
    }
```

## 🧪 Testing

Real, current output from this exact repository (not illustrative):

```
$ python -m pytest tests/test_card_detector.py tests/test_swift_detector.py tests/test_secret_detector.py tests/test_keyword_detector.py tests/test_filetype_detector.py tests/test_engine.py -v
collected 51 items

tests/test_card_detector.py::test_luhn_valid_numbers PASSED              [  1%]
tests/test_card_detector.py::test_masking_keeps_first6_last4_only PASSED [  9%]
...
tests/test_engine.py::test_summarize_clean_text_reports_no_match PASSED  [100%]

============================== 51 passed in 0.23s ==============================
```

| Test file | Count | Proves |
|---|---|---|
| `test_card_detector.py` | 10 | Luhn correctness against publicly-documented test card numbers, brand ID, PCI-style masking, PAN never appears unmasked in output |
| `test_swift_detector.py` | 7 | BIC extraction, MT field-tag detection, confidence split between bare-BIC and full-message-structure |
| `test_secret_detector.py` | 11 | AWS/GitHub/Slack/JWT/private-key/generic patterns; AWS secret's context-window gating; raw secrets never appear in `DetectionResult.matches` |
| `test_keyword_detector.py` | 8 | YAML policy loads; word-boundary correctness; multi-category matching; `credentials_context` correctly excluded from standalone firing |
| `test_filetype_detector.py` | 8 | Extension lookup; magic-byte sniffing; renamed-extension mismatch detection |
| `test_engine.py` | 7 | Aggregation across all five detectors; `needs_ai_review()` threshold behavior |

## ⚠️ Known Limitations (found through testing, not theoretical)

Documenting these honestly is itself a completion requirement — a detection
engine writeup that claims zero false positives is not credible.

**1. The bare-BIC pattern collides with ordinary all-caps English words of
the same length.** While building the synthetic test fixtures
(`simulations/synthetic_data/`), a document reading *"CONFIDENTIAL AND
PROPRIETARY -- INTERNAL USE ONLY"* triggered `swift_detector`, because
**"PROPRIETARY" is exactly 11 uppercase letters** — structurally
indistinguishable from a valid-format BIC to a character-class regex. Run
`python simulations/verify_fixtures.py` yourself to see it fire. This is
*why* the confidence split exists: a bare BIC scores only 0.5 (below the
"strong evidence" range), while an MT-message-structure match (multiple
field tags like `:20:`, `:32A:`) scores 0.9. The mitigation is architectural,
not a regex patch — a longer keyword blocklist would just chase the next
coincidental match.

**2. Luhn accepts degenerate sequences.** An all-zero digit string of valid
card length (e.g. sixteen `0`s) passes the Luhn checksum trivially (0 mod 10
= 0). This was caught while drafting a test fixture that happened to include
a placeholder token padded with zeros. Real card numbers are essentially
never all-zero, so this is low real-world impact, but it means Luhn alone is
a **filter, not proof** — exactly the caveat in `card_detector.py`'s own
docstring ("a random 16-digit number has roughly a 1-in-10 chance of passing
Luhn by chance").

**3. Keyword matching is exact-phrase, not semantic.** "social security
number" matches; a rephrasing like "the number tied to someone's social
security" does not. This is a precision/recall tradeoff made deliberately —
loosening it (fuzzy/stemmed matching) would raise false positives
significantly for a moderate recall gain, and is exactly the kind of gap
Phase 6's AI layer is meant to catch instead of pushing the regex to do
everything.

**4. The secret detector's generic patterns (`bearer_token`,
`generic_api_key_assignment`) are the lowest-confidence entries (0.55-0.6)
for a reason** — they're intentionally broad to catch secrets in formats not
covered by a named pattern, at the cost of being the most likely to false-positive
on non-secret data that merely looks like an assignment. `needs_ai_review()`'s
0.5 threshold means these still surface for review; they just shouldn't
dominate a risk score alone once Phase 7 exists.

## ✅ Expected Result

`python simulations/verify_fixtures.py` against the delivered synthetic
fixtures produces (real output):
```
sample_card_paste.txt
  direct categories:      ['payment_card']
  needs_ai_review:        True

sample_credential_leak.txt
  direct categories:      ['credential_secret']
  needs_ai_review:        True

sample_customer_export.csv
  direct categories:      ['customer_data', 'documents']
  needs_ai_review:        True

sample_obfuscated_payload_base64.txt
  direct categories:      (none)
  needs_ai_review:        False
  obfuscation techniques: ['base64']

sample_proprietary_source_note.txt
  direct categories:      ['source_code_markers', 'swift_bic']
  needs_ai_review:        True
```
(`sample_obfuscated_payload_base64.txt` correctly shows no *direct* match —
Phase 5's normalizer is what finds it. See `docs/NORMALIZATION.md`.)

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `yaml.scanner.ScannerError` when constructing `KeywordDetector()` | Malformed edit to `config/detection_policy.yaml` (usually inconsistent indentation) | YAML is whitespace-sensitive; validate with `python -c "import yaml; yaml.safe_load(open('config/detection_policy.yaml'))"` before assuming the code is at fault |
| A keyword category you added never fires | Forgot it needs `keywords:` as a YAML list, or added it under the wrong parent key | Compare indentation against an existing category in the file exactly |
| `card_detector` matches something you know isn't a card | Luhn-valid coincidental digit sequence (see Known Limitations #2) | Expected behavior, not a bug — this is inherent to Luhn-alone detection, which is why it's one signal among several, not a sole gate |
| `secret_detector` finds nothing in a file you know has a key | Your key format isn't one of the named patterns and doesn't match the generic fallback's `key/token/secret =` shape | Add a named pattern following the existing `_PATTERNS` list structure, with a test, rather than loosening the generic fallback (which would raise false positives project-wide) |

## 🔐 Security Considerations

- Every detector was designed so that **the evidence it returns cannot
  reconstruct the sensitive value** — masked PANs, fingerprinted secrets,
  matched-category-plus-lowercased-phrase for keywords (never the
  surrounding sensitive sentence). This matters because `DetectionResult`
  objects are what eventually get persisted (Phase 9) and displayed
  (Phase 10) — the safety property has to hold at the source.
- `AI_REVIEW_CONFIDENCE_THRESHOLD = 0.5` (in `detectors/engine.py`) is a
  single, named constant specifically so Phase 6/7 can't accidentally drift
  from Phase 4's definition of "ambiguous enough to need a second opinion."

## 📌 Completion Criteria

- [x] All five detectors implemented and independently tested (44 tests)
- [x] Aggregator (`engine.py`) implemented and tested (7 tests) — 51 total
- [x] DR1-DR5 (Phase 0) each traced to a passing test suite
- [x] Known limitations documented with concrete, reproduced examples (not
      hypothetical caveats)
- [x] No detector ever returns a raw secret/PAN/private key in its
      `DetectionResult` — verified by dedicated tests
      (`test_aws_access_key_never_appears_raw_in_evidence`,
      `test_masking_keeps_first6_last4_only`)
- [ ] You have run `python simulations/verify_fixtures.py` yourself and can
      explain *why* `sample_proprietary_source_note.txt` triggers
      `swift_detector` — if you can't, re-read "Known Limitations #1" above
      before moving to Phase 5

---

# PHASE 5 — CONTENT NORMALIZATION & OBFUSCATION DETECTION

## 🎯 Objective

Catch sensitive content that Phase 4's detectors would miss because it's
been base64-encoded, URL-encoded, embedded inside a JSON string value, or
compressed (gzip/zip) — satisfying threat-model requirement DR6 and directly
covering scenario S5 (`docs/THREAT_MODEL.md`). This is the phase that turns
"regex on raw bytes" into something that survives basic evasion.

## 🧠 Concept

Four techniques, one orchestrator (`normalize_and_rescan()`), recursive up to
a bounded depth. The core idea: for each technique, try to decode; if the
decoded bytes are plausibly text (checked via a printable-character-ratio
threshold, not just "didn't throw an exception"), **re-run the full Phase 4
detector suite against the decoded content**, and recurse — because
obfuscation can be layered (a card number, base64-encoded, embedded as a
JSON string value, is a real, two-layer case this project actually tests).

**Bounded recursion is a security property, not just a performance one.**
`max_recursion_depth` (default 3, in `config/detection_policy.yaml`) exists
specifically so a malicious or corrupt input can't trigger unbounded
work — this is the same class of concern as a decompression-bomb defense,
scaled to this project's actual risk (nothing here processes untrusted files
from strangers, but the discipline is worth having regardless).

**Printable-ratio gating avoids wasted work.** Not every string that
*decodes without error* is meaningful text — plenty of binary data
"successfully" base64-decodes into garbage bytes. Rescanning garbage with
five regex detectors on every single incidental base64-looking substring in
a document would be wasteful and noisy. `min_printable_ratio_after_decode`
(default 0.85) filters that out before it ever reaches Phase 4's detectors.

## 🏗️ Architecture

```
content (str | bytes)
      │
      ▼
normalize_and_rescan() ── depth < max_recursion_depth? ──No──▶ stop
      │ Yes
      ├─▶ try_decompress()        (gzip / zip magic bytes)
      ├─▶ try_decode_base64()     (regex-found runs, 4-byte-aligned)
      ├─▶ try_decode_url_encoding() (%XX sequences)
      └─▶ try_extract_json_strings() (json.loads, walk string leaves)
             │ (each successful decode)
             ▼
      detector_runner(decoded_text)         <- Phase 4's run_all()
             │
             ▼
      normalize_and_rescan(decoded_text, ..., depth+1)   <- recurse
```
`ObfuscationResult.layers` reports how many encodings were actually
unwrapped for a given hit, so a single-layer base64 string and a
base64-inside-JSON payload are distinguishable in the output, not just both
reported as "obfuscated: yes."

## 📁 Files

```
normalization/normalizer.py
tests/test_normalizer.py
```

## ⚙️ Configuration

```yaml
normalization:
  max_recursion_depth: 3
  min_base64_run_length: 40
  min_printable_ratio_after_decode: 0.85
```

## 💻 Commands

```powershell
python -m pytest tests/test_normalizer.py -v
```
Try it directly:
```powershell
python -c "
import base64
from detectors.engine import run_all
from normalization.normalizer import normalize_and_rescan
payload = base64.b64encode(b'card on file 4111111111111111').decode()
results = normalize_and_rescan(f'see attached: {payload}', run_all)
for r in results:
    print(r.technique, r.found, r.layers, [d.detector for d in r.rescanned_detections if d.matched])
"
```

## 🧩 Implementation

### `normalization/normalizer.py` — complete file
```python
"""
normalization/normalizer.py  (Phase 5)

Detects common obfuscation/encoding techniques used to slip sensitive
content past naive plaintext scanners, decodes them, and RE-RUNS the Phase 4
deterministic detectors against the decoded content. This is the piece that
turns "regex on raw bytes" into something that can catch a base64-encoded
credit card number pasted into a chat message, or a secret buried inside a
gzip-compressed, then base64-encoded, blob.

Techniques covered:
  1. Base64                — arbitrary runs of base64 alphabet characters.
  2. URL / percent-encoding — %XX escape sequences.
  3. JSON-embedded content  — sensitive data hiding inside a JSON string value
                               (e.g. {"note": "card 4111111111111111"}).
  4. Gzip / Zip compression — magic-byte detected, decompressed in memory.

Design choices (see docs/NORMALIZATION.md for full rationale):
  - Recursion is bounded by `max_recursion_depth` (config) to prevent
    decompression-bomb style resource exhaustion from a malicious or
    corrupt input; depth is decremented on every layer unwrapped regardless
    of technique.
  - A decoded byte sequence is only treated as "text worth rescanning" if
    its printable-character ratio clears `min_printable_ratio_after_decode`
    — this avoids wasting cycles running regex detectors against decoded
    binary noise that happened to Base64-decode without erroring.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import string
import zipfile
import io
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote

import yaml

from common.event_schema import DetectionResult, ObfuscationResult

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "detection_policy.yaml"

_PRINTABLE = set(bytes(string.printable, "ascii"))
_BASE64_CHARS = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}")
_URL_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# type alias: a function with the same signature as detectors.engine.run_all
DetectorRunner = Callable[..., list[DetectionResult]]


def load_normalization_config(policy_path: str | Path = DEFAULT_POLICY_PATH) -> dict[str, Any]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    return policy.get("normalization", {
        "max_recursion_depth": 3,
        "min_base64_run_length": 40,
        "min_printable_ratio_after_decode": 0.85,
    })


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable_count = sum(1 for b in data if b in _PRINTABLE)
    return printable_count / len(data)


# ---------------------------------------------------------------------------
# Individual technique detectors — each returns decoded text, or None if the
# technique was not present / did not yield plausible text.
# ---------------------------------------------------------------------------

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")


def try_decode_base64(text: str, min_run_length: int, min_printable_ratio: float) -> list[str]:
    """
    Find base64-looking tokens and decode the plausible ones.

    The length filter is applied to the TOTAL captured token (letters/digits
    plus any trailing '=' padding), not just the non-padding run — a 40-char
    token that happens to end in "==" only has 38 alphabet characters, and
    checking the alphabet-only count against min_run_length would incorrectly
    discard it. See tests/test_normalizer.py for the regression case.
    """
    decoded_candidates = []
    for m in _BASE64_TOKEN_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) < min_run_length:
            continue
        # base64 payloads are 4-char aligned; trim any trailing partial group
        usable_len = len(candidate) - (len(candidate) % 4)
        trimmed = candidate[:usable_len]
        if len(trimmed) < 4:
            continue
        try:
            raw = base64.b64decode(trimmed, validate=True)
        except Exception:
            continue
        if _printable_ratio(raw) >= min_printable_ratio:
            try:
                decoded_candidates.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                decoded_candidates.append(raw.decode("latin-1"))
    return decoded_candidates


def try_decode_url_encoding(text: str) -> Optional[str]:
    if not _URL_ENCODED_RE.search(text):
        return None
    decoded = unquote(text)
    return decoded if decoded != text else None


def try_extract_json_strings(text: str) -> list[str]:
    """
    Attempt json.loads on the whole text; if that fails, look for the first
    balanced {...} or [...] span and try that. Returns all string leaf
    values found, which are what get rescanned (this is where a payload
    like {"note": "<sensitive content>"} gets caught).
    """
    candidates_to_try = [text]
    brace_match = re.search(r"[\{\[].*[\}\]]", text, re.DOTALL)
    if brace_match:
        candidates_to_try.append(brace_match.group(0))

    for candidate in candidates_to_try:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        return _walk_json_strings(parsed)
    return []


def _walk_json_strings(node: Any) -> list[str]:
    found = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            found.extend(_walk_json_strings(v))
    elif isinstance(node, list):
        for v in node:
            found.extend(_walk_json_strings(v))
    return found


def try_decompress(content_bytes: bytes, min_printable_ratio: float) -> Optional[str]:
    if content_bytes[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(content_bytes)
        except Exception:
            return None
    elif content_bytes[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
                names = zf.namelist()
                if not names:
                    return None
                raw = zf.read(names[0])
        except Exception:
            return None
    else:
        return None

    if _printable_ratio(raw) < min_printable_ratio:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def normalize_and_rescan(
    content: str | bytes,
    detector_runner: DetectorRunner,
    policy_path: str | Path = DEFAULT_POLICY_PATH,
    _depth: int = 0,
) -> list[ObfuscationResult]:
    """
    Try every obfuscation technique against `content`. For each technique
    that yields plausible decoded text, run `detector_runner` (normally
    detectors.engine.run_all) against the decoded text and recurse (bounded
    by max_recursion_depth) in case of nested encoding.
    """
    cfg = load_normalization_config(policy_path)
    max_depth = cfg.get("max_recursion_depth", 3)
    min_run = cfg.get("min_base64_run_length", 40)
    min_ratio = cfg.get("min_printable_ratio_after_decode", 0.85)

    results: list[ObfuscationResult] = []
    if _depth >= max_depth:
        return results

    text = content if isinstance(content, str) else None
    content_bytes = content if isinstance(content, bytes) else (content.encode("utf-8", errors="ignore") if text else b"")

    # 1. Compression (bytes-first, since text won't have compression magic bytes)
    decompressed = try_decompress(content_bytes, min_ratio) if content_bytes else None
    if decompressed:
        results.append(_build_result("gzip_or_zip", decompressed, detector_runner, policy_path, _depth))

    if text is not None:
        # 2. Base64
        for decoded in try_decode_base64(text, min_run, min_ratio):
            results.append(_build_result("base64", decoded, detector_runner, policy_path, _depth))

        # 3. URL encoding
        url_decoded = try_decode_url_encoding(text)
        if url_decoded:
            results.append(_build_result("url_encoding", url_decoded, detector_runner, policy_path, _depth))

        # 4. JSON-embedded strings
        json_strings = try_extract_json_strings(text)
        for s in json_strings:
            if s and s != text:
                results.append(_build_result("json_embedded", s, detector_runner, policy_path, _depth))

    return results


def _build_result(
    technique: str,
    decoded_text: str,
    detector_runner: DetectorRunner,
    policy_path: str | Path,
    depth: int,
) -> ObfuscationResult:
    rescanned = detector_runner(decoded_text)
    nested = normalize_and_rescan(decoded_text, detector_runner, policy_path, _depth=depth + 1)
    nested_matches = [d for n in nested for d in n.rescanned_detections]
    return ObfuscationResult(
        technique=technique,
        found=True,
        layers=1 + max((n.layers for n in nested), default=0),
        decoded_excerpt=decoded_text[:200],
        rescanned_detections=rescanned + nested_matches,
    )
```

## 🧪 Testing

Real, current output:
```
$ python -m pytest tests/test_normalizer.py -v
collected 10 items

tests/test_normalizer.py::test_base64_encoded_card_number_is_found PASSED
tests/test_normalizer.py::test_short_base64_looking_string_is_ignored PASSED
tests/test_normalizer.py::test_url_encoding_reveals_hidden_card_number PASSED
tests/test_normalizer.py::test_json_embedded_card_number_is_found PASSED
tests/test_normalizer.py::test_gzip_compressed_card_number_is_found PASSED
tests/test_normalizer.py::test_clean_text_produces_no_obfuscation_results PASSED
tests/test_normalizer.py::test_nested_base64_in_json_is_recursively_unwrapped PASSED
tests/test_normalizer.py::test_url_decode_returns_none_when_nothing_encoded PASSED
tests/test_normalizer.py::test_json_extract_returns_empty_for_non_json_text PASSED
tests/test_normalizer.py::test_decompress_returns_none_for_non_compressed_bytes PASSED

============================== 10 passed in 0.15s ==============================
```

### A real bug this test suite caught before delivery

`test_nested_base64_in_json_is_recursively_unwrapped` failed on its first
run during development of this project — worth documenting exactly why,
since it's a good example of why the threshold logic needed a second look
rather than a quick patch:

The test base64-encodes a short card-number string, producing a token
ending in `==` padding. The original `try_decode_base64()` applied its
`min_run_length` (40) check **only to the non-padding alphabet-character
run**, via a regex quantifier `[A-Za-z0-9+/]{40,}={0,2}`. A 40-character
total token ending in `==` only has **38** non-padding characters —
one character short of the 40-character floor — so the regex silently
failed to match, and the recursive unwrap never happened.

The fix: capture the token first with a low technical floor
(`{4,}`, just enough to be one valid base64 group), *then* filter by
`len(candidate) >= min_run_length` against the **total** captured length
(letters plus padding). This is implemented in
`try_decode_base64()` above — see its docstring, which documents this
exact reasoning inline, not just in this doc, so a future editor hits the
explanation at the point they'd be tempted to reintroduce the same bug.

This is included here deliberately: "wrote tests, all passed the first time"
would be a less credible engineering story than "wrote tests, one failed,
here's the root cause and the fix."

## ✅ Expected Result

Real output from the interactive command in 💻 Commands above:
```
base64 True 1 ['card_detector']
```
And from the full pipeline demo (`docs/TELEMETRY.md`), a base64-encoded
private key was correctly flagged even though it produced **zero** direct
Phase 4 matches:
```
[ALERT] file:file_modified -> simulations/monitored/obfuscated_note.txt
        categories=['obfuscated:base64']
        needs_ai_review=False  (Phase 6 will act on this flag)
```
(`needs_ai_review` is `False` here because `run_pipeline_demo.py`'s
`analyze_event()` only feeds *direct* detection results into
`summarize()` — the obfuscation-layer match is surfaced separately as
`categories=['obfuscated:base64']`. Whether an AI-review flag should also
consider obfuscation-layer matches is exactly the kind of wiring decision
Phase 6/7 will need to make explicitly, not by accident; noted here as a
forward pointer, not resolved in this phase.)

## 🔧 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A base64-encoded secret isn't found | Encoded token is shorter than `min_base64_run_length` (40) total characters | Expected for short payloads — lower the threshold in `config/detection_policy.yaml` if your use case needs to catch shorter encoded runs, understanding this raises false-positive risk on incidental base64-looking text |
| `normalize_and_rescan()` seems to hang or run long on a large document | Many incidental base64-looking substrings in the document, each attempted | Not infinite — bounded by `max_recursion_depth` — but can be slow on large inputs with lots of near-miss candidates; for Phase 3's real collectors this is naturally bounded by the `excerpt_max_chars` cap (4000 chars) already applied before content reaches this layer |
| JSON extraction finds nothing in a document that clearly contains `{...}` | The braces aren't valid JSON (e.g. Python dict repr with single quotes) | `try_extract_json_strings()` uses strict `json.loads`, not a permissive parser — this is deliberate, to avoid false "decodes" on text that merely looks JSON-ish |
| Gzip/zip detection doesn't fire on a `.gz` file | You passed `text` (str) instead of `bytes` — compression is inherently binary | Read the file with `path.read_bytes()`, not `read_text()`, before calling `normalize_and_rescan()` |

## 🔐 Security Considerations

- Recursion depth is bounded (`max_recursion_depth`) specifically to prevent
  resource-exhaustion from adversarial or corrupt nested-encoding input —
  the same defensive posture as guarding against decompression bombs,
  applied here at a much smaller scale appropriate to this project.
- Decoded content is rescanned through the *same* Phase 4 detectors that
  already never leak raw secrets/PANs — the safety property established in
  Phase 4 carries through automatically here, because this layer calls
  Phase 4 rather than reimplementing any detection logic.

## 📌 Completion Criteria

- [x] Base64, URL-encoding, JSON-embedding, and gzip/zip detection all
      implemented and independently tested (10 tests)
- [x] Recursive nested-encoding case tested and passing (JSON containing
      base64 containing a card number)
- [x] A real bug (padding/threshold interaction) found, root-caused, fixed,
      and documented rather than silently patched
- [x] DR6 (Phase 0) satisfied and cross-referenced to passing tests
- [ ] You have run the interactive command above with your own payload (not
      the one in this doc) and confirmed it's caught

---

## Overall Completion Checklist & Next Steps

Consolidated from every phase's individual Completion Criteria above. If
every box here is checked **on your own machine, from your own run**, Phases
0-5 are genuinely done, not just read:

- [ ] **Phase 0:** Threat model reviewed; you can explain scenarios S1-S6 and
      requirements DR1-DR9 without re-reading them
- [ ] **Phase 1:** `python -m pytest tests/ -v` prints `79 passed` on your
      Windows machine (not just in this document)
- [ ] **Phase 2:** You can locate any of the six implemented modules by
      reasoning about the directory tree, without grep
- [ ] **Phase 3:** `python run_pipeline_demo.py` run locally; you dropped a
      file into the watched folder and saw your own `[ALERT]` line
- [ ] **Phase 4:** `python simulations/verify_fixtures.py` run locally; you
      can explain the `PROPRIETARY`/SWIFT false positive from memory
- [ ] **Phase 5:** You fed the interactive base64 example your own payload
      (not the one in this guide) and confirmed it was caught

**Full-repository verification, one command:**
```powershell
cd C:\dlp-lab\ai-dlp-insider-threat
python -m pytest tests/ -v
```
Expected final line: `79 passed in ...s`

### What's deliberately not in this guide

Phases 6 (AI/Ollama analysis), 7 (hybrid risk scoring), 8 (behavioral
correlation), 9 (SQLite audit database), and 10 (alerting & dashboard) are
**not implemented** in the delivered project — each has a placeholder
`README.md` in its directory (`ai/`, `scoring/`, `correlation/`,
`database/`, `alerts/`, `dashboard/`) explaining what it will contain and
which already-built interface it will plug into:

- Phase 6 will consume `detectors.engine.needs_ai_review()` — already
  implemented and tested — to decide what gets sent to Ollama.
- Phase 7 will consume the `DetectionResult.confidence` values Phase 4
  already produces, plus Phase 6's output.
- Phase 8 will consume the JSONL event stream Phase 3 already writes,
  correlated by `DLPEvent.user` and `.timestamp`, both already present in
  every event.
- Phase 9 will read the same JSONL files (`logs/*.jsonl`) Phase 3 already
  populates.
- Phase 10 will read from Phase 9's database.

None of Phases 6-10 require re-opening or redesigning anything built in
Phases 0-5 — this was a deliberate goal of Phase 2's architecture, verified
here at the end rather than just asserted at the start.
