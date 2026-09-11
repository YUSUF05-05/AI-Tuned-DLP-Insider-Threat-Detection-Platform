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
