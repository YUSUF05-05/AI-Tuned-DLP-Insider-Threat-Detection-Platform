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
