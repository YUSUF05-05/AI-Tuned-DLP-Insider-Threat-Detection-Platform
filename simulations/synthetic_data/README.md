# simulations/synthetic_data/

Static, reusable synthetic test fixtures — one per threat-model scenario
(see docs/THREAT_MODEL.md, table "Insider-threat / exfiltration scenarios").
All values are fabricated or drawn from publicly-documented example
credentials (e.g. AWS's own SDK documentation example key). None of this is
real data. See docs/DETECTION_ENGINE.md and docs/NORMALIZATION.md for how to
run these through the pipeline manually.

| File | Scenario | Verified detections (re-run `python3 verify_fixtures.py` to reproduce) |
|---|---|---|
| sample_customer_export.csv | S1 — bulk customer data | `keyword_detector` (customer_data) + `filetype_detector` (.csv is a "documents" extension) |
| sample_card_paste.txt | S2 — payment card paste | `card_detector` (visa + mastercard) |
| sample_credential_leak.txt | S3 — credential leak | `secret_detector` (aws_access_key_id, aws_secret_access_key, github_token) |
| sample_proprietary_source_note.txt | S4 — proprietary source exfil | `keyword_detector` (source_code_markers) **and** `swift_detector` (see note below) |
| sample_obfuscated_payload_base64.txt | S5 — obfuscated payload | Not flagged directly; `normalization.normalizer` (base64) reveals `swift_detector` + `card_detector` hits on decode |

**Note on `sample_proprietary_source_note.txt`:** this fixture is deliberately
kept as-is rather than "cleaned up," because it demonstrates a real,
documented false positive: the word **"PROPRIETARY"** is exactly 11 uppercase
letters, which is indistinguishable from a valid-format BIC/SWIFT code to a
character-class regex. `swift_detector` does fire on it — but only at the
low, bare-BIC confidence level (0.5), not the high MT-message-structure level
(0.9), which is exactly why that confidence split exists. See
`docs/DETECTION_ENGINE.md` → SWIFT detector → Known Limitations for the full
discussion.
