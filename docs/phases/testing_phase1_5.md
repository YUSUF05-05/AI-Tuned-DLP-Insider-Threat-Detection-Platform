# Testing and Verification Guide

## 1. Purpose

This document explains how to test the AI-Tuned DLP & Insider Threat Detection Platform implemented through Phases 0–5.

The testing process verifies:

* Python environment and dependencies
* Individual detectors
* Detection engine aggregation
* Content normalization and obfuscation detection
* File-system telemetry
* Clipboard telemetry
* HTTP telemetry
* End-to-end pipeline behavior
* JSONL event logging

The testing environment uses synthetic data and a local loopback HTTP destination. No real external exfiltration is performed.

---

# 2. Testing Architecture

The testing flow is:

```text
                    TEST INPUT
                        │
          ┌─────────────┼─────────────┐
          │             │             │
          ▼             ▼             ▼
   Synthetic files   File activity   HTTP activity
          │             │             │
          ▼             ▼             ▼
  verify_fixtures   file_collector  http_exfil_simulator
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                   DLPEvent
                        │
                        ▼
                Detection Engine
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
       Card          SWIFT         Secrets
       Detector      Detector      Detector
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                  Keyword/Filetype
                        │
                        ▼
                  Phase 5 Normalizer
                        │
                        ▼
                Decode / Rescan
                        │
                        ▼
                   Detection
                        │
                        ▼
                     Alert
                        │
                        ▼
                   JSONL Logs
```

---

# 3. Test Environment

The project uses a Python virtual environment.

Activate it from Git Bash:

```bash
source .venv/Scripts/activate
```

Verify:

```bash
python --version
pip --version
```

The prompt should contain:

```text
(.venv)
```

---

# 4. Dependency Verification

Install the project dependencies with:

```bash
pip install -r requirements.txt
```

Verify the required modules:

```bash
python -c "import watchdog, pyperclip, flask, requests, yaml, dotenv, pytest; print('All dependencies installed successfully')"
```

SQLite does not require a separate installation because it is provided by Python.

Verify:

```bash
python -c "import sqlite3; print('SQLite:', sqlite3.sqlite_version)"
```

---

# 5. Automated Test Suite

Run:

```bash
python -m pytest tests/ -v
```

The expected result for the documented project version is:

```text
79 passed
```

The test suite covers the collectors, detectors, detection engine, and normalization layer.

The Phase 4 detection suite contains 51 tests:

```text
44 detector tests
+
7 engine tests
=
51 tests
```

---

# 6. Synthetic Fixture Testing

Run:

```bash
python simulations/verify_fixtures.py
```

The script verifies the predefined synthetic fixtures located in:

```text
simulations/synthetic_data/
```

The fixtures include:

```text
sample_card_paste.txt
sample_credential_leak.txt
sample_customer_export.csv
sample_obfuscated_payload_base64.txt
sample_proprietary_source_note.txt
```

These files are permanent test fixtures and should not be deleted after testing.

Expected detection behavior includes:

```text
sample_card_paste.txt
    → payment_card

sample_credential_leak.txt
    → credential_secret

sample_customer_export.csv
    → customer_data
    → documents

sample_obfuscated_payload_base64.txt
    → no direct Phase 4 match
    → Base64 detected during normalization

sample_proprietary_source_note.txt
    → source_code_markers
    → swift_bic
```

The `swift_bic` result in the proprietary-source fixture is a known false-positive example caused by a token structurally resembling a BIC. This behavior is documented as a known limitation.

---

# 7. Phase 5 Obfuscation Test

Phase 5 verifies that sensitive data hidden using basic encoding or compression can be recovered and rescanned.

The normalizer supports:

```text
Base64
URL encoding
JSON embedding
GZIP
ZIP
```

The general process is:

```text
Obfuscated content
       │
       ▼
normalize_and_rescan()
       │
       ▼
Decode
       │
       ▼
Check whether decoded content is plausible text
       │
       ▼
Run Phase 4 detectors
       │
       ▼
Detection
```

A direct Base64 test can be executed with:

```bash
python -c "import base64; from detectors.engine import run_all; from normalization.normalizer import normalize_and_rescan; payload=base64.b64encode(b'card on file 4111111111111111').decode(); results=normalize_and_rescan(f'see attached: {payload}', run_all); print([(r.technique, r.found, r.layers, [d.detector for d in r.rescanned_detections if d.matched]) for r in results])"
```

A successful result should show Base64 normalization followed by a `payment_card` detection.

---

# 8. End-to-End Pipeline Test

Start the complete pipeline:

```bash
python run_pipeline_demo.py
```

The demo starts the file collector and the local HTTP collector.

The default monitored directory is:

```text
simulations/monitored/
```

The local HTTP destination is:

```text
http://127.0.0.1:8765
```

The pipeline remains active until:

```text
Ctrl+C
```

is pressed.

---

# 9. File Collector Test

While the pipeline is running, create a temporary test file:

```bash
echo "Customer database with confidential customer information" > simulations/monitored/test_customer.txt
```

The file collector should detect the file activity.

To test payment-card detection:

```bash
echo "Customer card: 4111111111111111" > simulations/monitored/test_card.txt
```

The expected detection is:

```text
payment_card
```

Depending on operating-system file behavior, one write can produce both:

```text
file_created
file_modified
```

This is expected.

---

# 10. Clipboard Collector Test

With the pipeline running, copy a new clipboard value such as:

```text
Customer card: 4111111111111111
```

The expected flow is:

```text
Clipboard change
       ↓
clipboard_collector.py
       ↓
DLPEvent
       ↓
Detection Engine
       ↓
card_detector.py
       ↓
payment_card
       ↓
ALERT
```

The first clipboard poll establishes the initial baseline and therefore does not generate an event.

---

# 11. HTTP Exfiltration Simulation

With the pipeline running, open another terminal:

```bash
python simulations/http_exfil_simulator.py
```

The simulator sends deterministic synthetic HTTP requests to:

```text
127.0.0.1:8765
```

The simulator contains clean and suspicious scenarios.

The flow is:

```text
http_exfil_simulator.py
          │
          ▼
127.0.0.1:8765/upload
          │
          ▼
http_collector.py
          │
          ▼
DLPEvent
          │
          ▼
Detection Engine
          │
          ▼
Normalizer
          │
          ▼
ALERT
```

The HTTP simulator must remain local and must not be modified to send traffic to real external destinations.

---

# 12. Log Verification

The current implementation uses JSONL as an intermediate event store.

After running the pipeline:

```bash
ls logs/
```

Typical runtime files include:

```text
file_events.jsonl
clipboard_events.jsonl
http_events.jsonl
flagged_events.jsonl
```

Inspect the logs:

```bash
cat logs/*.jsonl
```

or:

```bash
tail -f logs/*.jsonl
```

Events contain structured fields such as:

```text
event_id
timestamp
host
user
source
event_type
object_ref
content_excerpt
detections
obfuscation
```

---

# 13. Cleanup After Manual Testing

Temporary files created during manual testing should be removed after verification.

Remove temporary monitored files:

```bash
rm -f simulations/monitored/test_*.txt
```

Remove runtime JSONL logs:

```bash
rm -f logs/*.jsonl
```

Remove pytest cache:

```bash
rm -rf .pytest_cache
```

Remove Python bytecode caches:

```bash
find . -type d -name "__pycache__" -exec rm -rf {} +
```

After cleanup, the following directories should remain available:

```text
logs/
└── .gitkeep

simulations/monitored/
└── .gitkeep
```

Do not delete:

```text
tests/
simulations/synthetic_data/
simulations/verify_fixtures.py
simulations/http_exfil_simulator.py
```

These are permanent components of the testing framework.

Do not delete:

```text
.venv/
```

unless the entire Python virtual environment is intentionally being removed.

---

# 14. Recommended Verification Sequence

For a complete verification, execute:

```bash
# 1. Activate environment
source .venv/Scripts/activate

# 2. Verify environment
python --version
pip --version

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated tests
python -m pytest tests/ -v

# 5. Verify synthetic fixtures
python simulations/verify_fixtures.py

# 6. Run the complete pipeline
python run_pipeline_demo.py

# 7. Test file monitoring
# Create a temporary sensitive file in simulations/monitored/

# 8. Test clipboard monitoring
# Copy synthetic sensitive content

# 9. Test HTTP simulation
python simulations/http_exfil_simulator.py

# 10. Inspect logs
ls logs/
cat logs/*.jsonl

# 11. Clean temporary test artifacts
rm -f logs/*.jsonl
rm -f simulations/monitored/test_*.txt
rm -rf .pytest_cache
find . -type d -name "__pycache__" -exec rm -rf {} +
```

---

# 15. Testing Status

A successful Phase 0–5 verification means:

```text
[✓] Python environment configured
[✓] Dependencies installed
[✓] Automated tests passing
[✓] Synthetic fixtures verified
[✓] Card detection verified
[✓] Secret detection verified
[✓] Keyword detection verified
[✓] File-type detection verified
[✓] SWIFT/BIC detection verified
[✓] Detection engine verified
[✓] Base64 normalization verified
[✓] File telemetry verified
[✓] Clipboard telemetry verified
[✓] HTTP telemetry verified
[✓] JSONL event logging verified
[✓] Temporary test artifacts removed
```

Phases 6–10 are not included in this verification because AI/Ollama analysis, hybrid risk scoring, behavioral correlation, SQLite persistence, and the final alert/dashboard layer are not implemented in the current Phase 0–5 project.
