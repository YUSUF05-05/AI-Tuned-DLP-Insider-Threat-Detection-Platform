"""
simulations/scenario_catalog.py  (Phase 11.3)

The scenario catalog: docs/THREAT_MODEL.md's S1-S6 turned into executable
scenarios. Pure data -- see simulations/scenarios.py for the contract and
simulations/scenario_runner.py for how these run.

All "sensitive" values are synthetic or publicly documented test values
(THREAT_MODEL.md assumption A2): the payment industry's standard test card
numbers, AWS's documented example access key id, a PEM header wrapped around
an obviously fake body, and SSA-invalid SSNs (000-xx-xxxx).

Expectations are written from the requirements, NOT from observed output.
Severity floors use the policy in config/risk_policy.yaml and the alert
threshold in config/alert_policy.yaml; whether those numbers are the RIGHT
numbers is a Phase 12 (calibration) question, not a Phase 11 one.
"""

from __future__ import annotations

import base64
import gzip

from simulations.scenarios import Expect, Scenario, Step, validate_catalog

# --------------------------------------------------------------------------
# Shared synthetic payloads
# --------------------------------------------------------------------------
CUSTOMER_CSV = (
    "name,ssn,date of birth\n"
    "John Sample,000-00-0000,1990-01-01\n"
    "Jane Sample,000-00-0001,1991-02-02\n"
)
PROPRIETARY_SOURCE = (
    "# Copyright All Rights Reserved. Confidential and Proprietary.\n"
    "def price_quote(customer_tier, volume):\n"
    "    return volume * RATE_TABLE[customer_tier]\n"
)
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "(synthetic placeholder body - not a real key)\n"
    "-----END RSA PRIVATE KEY-----\n"
)
CARD_NOTE = "internal note: card on file is 5555555555554444"

_b64 = lambda s: base64.b64encode(s.encode("utf-8")).decode("ascii")  # noqa: E731

# Expectation shorthands, so each scenario reads as its requirement.
FLAGGED = Expect(flagged=True)
CLEAN = Expect(flagged=False)
NO_ALERT = Expect(would_alert=False, max_severity="low")


def _export_step(n: int, at_minutes: int, expect: Expect | None = None, user: str = "insider") -> Step:
    return Step("file", CUSTOMER_CSV, at_minutes, user=user, filename=f"customers_export_{n}.csv", expect=expect)


CATALOG: tuple[Scenario, ...] = (
    # ======================================================================
    # S1 -- Bulk customer data export before resignation
    # ======================================================================
    Scenario(
        id="s1_bulk_customer_export", threat="S1", kind="attack",
        title="Five customer exports by one user over six hours",
        rationale=(
            "THREAT_MODEL S1 / DR4 / DR9. Each export alone is a moderate finding; the "
            "pattern is the threat. The first export must not carry a behavioral bonus "
            "(no history yet); by the fifth, correlation must have lifted the event to "
            "HIGH."
        ),
        steps=(
            _export_step(1, 0, Expect(flagged=True, categories_include=("customer_data",),
                                      max_behavioral_adjustment=0, would_alert=True)),
            _export_step(2, 60, FLAGGED),
            _export_step(3, 120, FLAGGED),
            _export_step(4, 240, FLAGGED),
            _export_step(5, 360, Expect(flagged=True, min_severity="high",
                                        min_behavioral_adjustment=10, would_alert=True)),
        ),
    ),
    Scenario(
        id="s1_single_customer_export", threat="S1", kind="benign_control",
        title="One customer export, no history",
        rationale=(
            "Control for S1: a lone export is still a finding (it contains PII markers), "
            "but with no prior activity the behavioral layer must add nothing and the "
            "event must not reach HIGH."
        ),
        steps=(
            _export_step(1, 0, Expect(flagged=True, categories_include=("customer_data",),
                                      max_behavioral_adjustment=0, max_severity="medium")),
        ),
    ),
    Scenario(
        id="s1_plain_csv_report", threat="S1", kind="benign_control",
        title="Ordinary CSV with no sensitive content",
        rationale=(
            "Control for S1: file TYPE alone (.csv is in sensitive_file_types) is weak "
            "evidence. An ordinary sales summary must never page an analyst."
        ),
        steps=(
            Step("file", "region,units\nEMEA,10\nAPAC,7\n", 0, user="analyst",
                 filename="sales_summary.csv", expect=NO_ALERT),
        ),
    ),

    # ======================================================================
    # S2 -- Payment card data pasted into external chat / webmail
    # ======================================================================
    Scenario(
        id="s2_pan_over_http", threat="S2", kind="attack",
        title="Luhn-valid card number sent over HTTP",
        rationale=(
            "THREAT_MODEL S2 / DR1. HTTP is the only source the lab models as data "
            "actually leaving, so a validated PAN there must be HIGH or above."
        ),
        steps=(
            Step("http", "Refund the customer using card 4111111111111111 please.", 0, user="agent",
                 expect=Expect(flagged=True, categories_include=("payment_card",),
                               min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s2_pan_clipboard_formats", threat="S2", kind="attack",
        title="Card numbers pasted with spaces, dashes and mixed brands",
        rationale=(
            "DR1: the detector must tolerate the separators humans actually type "
            "(spaces, dashes, grouped 4-6-5 for Amex) and must alert on a PAN that "
            "is only staged on the clipboard."
        ),
        steps=(
            Step("clipboard", "pay with 4111 1111 1111 1111", 0, user="agent",
                 expect=Expect(flagged=True, categories_include=("payment_card",), min_severity="medium", would_alert=True)),
            Step("clipboard", "card: 5555-5555-5555-4444", 10, user="agent",
                 expect=Expect(flagged=True, categories_include=("payment_card",), min_severity="medium", would_alert=True)),
            Step("clipboard", "amex 3782 822463 10005", 20, user="agent",
                 expect=Expect(flagged=True, categories_include=("payment_card",), min_severity="medium", would_alert=True)),
        ),
    ),
    Scenario(
        id="s2_luhn_invalid_digits", threat="S2", kind="benign_control",
        title="16-digit order reference that fails the Luhn check",
        rationale="Control for DR1: a 16-digit number is not a card number unless it validates.",
        steps=(
            Step("clipboard", "order reference 4111111111111112 shipped", 0, user="agent", expect=CLEAN),
        ),
    ),

    # ======================================================================
    # S3 -- Credential / secret leaked into chat or a paste site
    # ======================================================================
    Scenario(
        id="s3_aws_key_over_http", threat="S3", kind="attack",
        title="AWS documented example access key id posted over HTTP",
        rationale="THREAT_MODEL S3 / DR3. A cloud key id leaving over HTTP must be HIGH or above.",
        steps=(
            Step("http", "oops wrong channel -- AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", 0, user="dev",
                 expect=Expect(flagged=True, categories_include=("credential_secret",),
                               min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s3_private_key_on_clipboard", threat="S3", kind="attack",
        title="PEM private-key header copied to the clipboard",
        rationale="DR3: key material staged on the clipboard must alert.",
        steps=(
            Step("clipboard", FAKE_PEM, 0, user="dev",
                 expect=Expect(flagged=True, categories_include=("credential_secret",),
                               min_severity="medium", would_alert=True)),
        ),
    ),
    Scenario(
        id="s3_password_in_it_prose", threat="S3", kind="benign_control",
        title="The word 'password' in ordinary IT guidance",
        rationale=(
            "Control for DR3/DR4: credentials_context words are confidence boosters only "
            "(detection_policy.yaml) and must never fire on their own."
        ),
        steps=(
            Step("clipboard",
                 "Reminder: rotate your password every 90 days. The password policy lives on the intranet.",
                 0, user="helpdesk", expect=CLEAN),
        ),
    ),
    Scenario(
        id="s3_git_sha_near_aws", threat="S3", kind="benign_control",
        title="40-hex git commit hash next to the word 'aws'",
        rationale=(
            "Control for DR3: secret_detector deliberately excludes pure-hex 40-char "
            "strings (git SHA-1) even inside the AWS context window."
        ),
        steps=(
            Step("clipboard", "deployed to aws from commit 3f786850e387550fdab836ed7e6dc881de23001b",
                 0, user="dev", expect=CLEAN),
        ),
    ),

    # ======================================================================
    # S4 -- Proprietary source code exfiltrated via personal email/cloud
    # ======================================================================
    Scenario(
        id="s4_proprietary_code_over_http", threat="S4", kind="attack",
        title="Source with proprietary markers uploaded over HTTP",
        rationale="THREAT_MODEL S4 / DR4: 'confidential and proprietary' markers leaving over HTTP must alert.",
        steps=(
            Step("http", PROPRIETARY_SOURCE, 0, user="dev",
                 expect=Expect(flagged=True, categories_include=("source_code_markers",),
                               min_severity="medium", would_alert=True)),
        ),
    ),
    Scenario(
        id="s4_proprietary_code_saved", threat="S4", kind="attack",
        title="Proprietary source saved to a monitored folder",
        rationale="DR4/DR5: the same markers in a .py file must be flagged and alert-worthy at the file stage.",
        steps=(
            Step("file", PROPRIETARY_SOURCE, 0, user="dev", filename="pricing_engine.py",
                 expect=Expect(flagged=True, categories_include=("source_code_markers",),
                               min_severity="medium", would_alert=True)),
        ),
    ),
    Scenario(
        id="s4_ordinary_code_saves", threat="S4", kind="benign_control",
        title="A developer saves four ordinary Python files in 90 minutes",
        known_gap=(
            "GAP-1 (false positive): behavior_tracker counts EVERY any_match event, including events "
            "flagged only by file extension (base score 12). Three .py saves inside 24h earn +5 "
            "(activity) +8 (repeated category) = +13, lifting a LOW event to MEDIUM and over the alert "
            "threshold. Fix in Phase 13: ignore extension-only events (or events below a base-score "
            "floor) when correlating."
        ),
        rationale=(
            "Control for S4: routine development is the highest-volume benign activity "
            "on a developer endpoint. Nothing in these files is sensitive, so no save "
            "may reach the alert threshold -- including through behavioral correlation."
        ),
        steps=(
            Step("file", "def add(a, b):\n    return a + b\n", 0, user="dev", filename="util_add.py", expect=NO_ALERT),
            Step("file", "def sub(a, b):\n    return a - b\n", 30, user="dev", filename="util_sub.py", expect=NO_ALERT),
            Step("file", "def mul(a, b):\n    return a * b\n", 60, user="dev", filename="util_mul.py", expect=NO_ALERT),
            Step("file", "def div(a, b):\n    return a / b\n", 90, user="dev", filename="util_div.py", expect=NO_ALERT),
        ),
    ),

    # ======================================================================
    # S5 -- Data obfuscated before exfiltration
    # ======================================================================
    Scenario(
        id="s5_base64_over_http", threat="S5", kind="evasion",
        title="Card number hidden in a base64 blob",
        rationale=(
            "THREAT_MODEL S5 / DR6. The decoded content is what matters, and the "
            "evasion itself should add risk (context component)."
        ),
        steps=(
            Step("http", _b64(CARD_NOTE), 0, user="insider",
                 expect=Expect(flagged=True, obfuscation_include=("base64",), categories_include=("payment_card",),
                               min_layers=1, min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_url_encoded_over_http", threat="S5", kind="evasion",
        title="Card number hidden by percent-encoding the separators",
        rationale=(
            "DR6. The %20 separators leave only digit runs too short for the direct card "
            "regex, so only the URL-decode pass can see it."
        ),
        steps=(
            Step("http", "customer card%3A%204111%201111%201111%201111%20refund", 0, user="insider",
                 expect=Expect(flagged=True, obfuscation_include=("url_encoding",), categories_include=("payment_card",),
                               min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_json_escaped_over_http", threat="S5", kind="evasion",
        title="Card number split by JSON unicode escapes",
        rationale=(
            "DR6. \\u0020 escapes break the digit run in the raw text; only parsing the "
            "JSON string value reveals the PAN."
        ),
        steps=(
            Step("http", r'{"note": "card 4111\u00201111\u00201111\u00201111"}', 0, user="insider",
                 expect=Expect(flagged=True, obfuscation_include=("json_embedded",), categories_include=("payment_card",),
                               min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_nested_base64_over_http", threat="S5", kind="evasion",
        title="Base64 wrapped in base64",
        rationale="DR6 'recursively': two layers must both be unwrapped and the layer count reported.",
        steps=(
            Step("http", _b64(_b64(CARD_NOTE)), 0, user="insider",
                 expect=Expect(flagged=True, obfuscation_include=("base64",), categories_include=("payment_card",),
                               min_layers=2, min_severity="high", would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_gzip_file_odd_extension", threat="S5", kind="evasion",
        title="Gzip-compressed card data saved as .dat",
        known_gap=(
            "GAP-2 (evasion): the file collector decodes binary content as latin-1 and analyze_event "
            "hands the normalizer that str; re-encoding it as UTF-8 destroys the gzip magic bytes (0x8b "
            "becomes 0xc2 0x8b), so decompression never runs in the live pipeline (it works when given "
            "real bytes). Fix in Phase 13: carry raw bytes (or a magic-byte header) from the collector "
            "to the normalizer."
        ),
        rationale=(
            "DR6 (compression). A gzip stream under a non-archive extension is a classic way "
            "to hide content from a text scanner. The decompressed card number must be found "
            "even though the file extension tells the filetype detector nothing."
        ),
        steps=(
            Step("file", gzip.compress(b"card on file: 4111111111111111", mtime=0), 0, user="insider",
                 filename="export.dat",
                 expect=Expect(flagged=True, obfuscation_include=("gzip_or_zip",),
                               categories_include=("payment_card",), would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_pem_renamed_txt", threat="S5", kind="evasion",
        title="Private key saved with a .txt extension",
        rationale=(
            "DR5/DR3. Renaming key.pem to notes.txt defeats the extension lookup; the "
            "content-based secret detector must still catch it."
        ),
        steps=(
            Step("file", FAKE_PEM, 0, user="insider", filename="notes.txt",
                 expect=Expect(flagged=True, categories_include=("credential_secret",),
                               min_severity="medium", would_alert=True)),
        ),
    ),
    Scenario(
        id="s5_sqlite_renamed_txt", threat="S5", kind="evasion",
        title="SQLite database renamed to .txt",
        known_gap=(
            "GAP-3 (evasion): analyze_event calls run_all() without content_bytes and the file collector "
            "never captures bytes, so filetype_detector's magic-byte mismatch check is unreachable in "
            "the live pipeline (it works when called with bytes, as the unit tests do). Same root cause "
            "family as GAP-2; fix in Phase 13."
        ),
        rationale=(
            "DR5 / THREAT_MODEL S5: 'filetype_detector's magic-byte mismatch check'. A SQLite "
            "file named meeting_notes.txt has no text for any content detector to match; only "
            "the magic-byte vs extension comparison can flag it."
        ),
        steps=(
            Step("file", b"SQLite format 3\x00" + b"\x00" * 84, 0, user="insider", filename="meeting_notes.txt",
                 expect=Expect(flagged=True, categories_include=("extension_mismatch",))),
        ),
    ),
    Scenario(
        id="s5_benign_encoded_content", threat="S5", kind="benign_control",
        title="A checksum and a harmless base64 message",
        rationale=(
            "Control for DR6: long hex strings and base64 that decodes to ordinary text are "
            "common in normal traffic. Decoding them must not manufacture a finding."
        ),
        steps=(
            Step("http", "release checksum sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                 0, user="release_bot", expect=CLEAN),
            Step("http", _b64("Reminder: the team offsite is next Thursday, please confirm your attendance by Friday."),
                 5, user="release_bot", expect=CLEAN),
        ),
    ),

    # ======================================================================
    # S6 -- Anomalous timing / volume (Phase 8 behavioral correlation)
    # ======================================================================
    Scenario(
        id="s6_escalating_burst", threat="S6", kind="attack",
        title="Eight flagged events in two hours, escalating from notes to card data over HTTP",
        rationale=(
            "THREAT_MODEL S6 / DR9. Many low-signal events that climb in severity are the "
            "behavioral signature of staging followed by exfiltration. By the last event the "
            "three Phase 8 signals (volume, escalation, repeated category) should all have "
            "fired and pushed it to CRITICAL."
        ),
        steps=(
            Step("clipboard", "notes: customer database cleanup batch 1", 0, user="insider", expect=FLAGGED),
            Step("clipboard", "notes: customer database cleanup batch 2", 15, user="insider", expect=FLAGGED),
            Step("clipboard", "notes: customer database cleanup batch 3", 30, user="insider", expect=FLAGGED),
            Step("clipboard", "notes: customer database cleanup batch 4", 45, user="insider", expect=FLAGGED),
            Step("http", "upload 1: card 4111111111111111", 60, user="insider", expect=FLAGGED),
            Step("http", "upload 2: card 5555555555554444", 75, user="insider", expect=FLAGGED),
            Step("http", "upload 3: card 378282246310005", 90, user="insider", expect=FLAGGED),
            Step("http", "upload 4: card 6011111111111117", 105, user="insider",
                 expect=Expect(flagged=True, min_severity="critical", min_behavioral_adjustment=20, would_alert=True)),
        ),
    ),
    Scenario(
        id="s6_offhours_single_export", threat="S6", kind="attack",
        title="One customer export at 02:00 UTC on a Sunday",
        known_gap=(
            "GAP-4 (missing signal): behavior_tracker has no time-of-day or weekend signal, only count, "
            "escalation and repeated category. THREAT_MODEL S6 names a 2am export as a requirement "
            "driver. Phase 13 decision: add an off-hours bonus to risk_policy.yaml, or record it as a "
            "documented limitation."
        ),
        rationale=(
            "THREAT_MODEL S6 names 'a large export at 2am' explicitly. The identical export at "
            "02:00 on a weekend must score higher than at 09:00 on a Monday, i.e. timing must "
            "contribute SOME behavioral adjustment."
        ),
        start="2026-03-08T02:00:00Z",
        steps=(
            _export_step(1, 0, Expect(flagged=True, min_behavioral_adjustment=1)),
        ),
    ),
    Scenario(
        id="s6_low_and_slow_exports", threat="S6", kind="evasion",
        title="Five customer exports spaced 20 hours apart",
        known_gap=(
            "GAP-5 (design limit): correlation uses a fixed 24h window with count tiers, so events more "
            "than 24h apart never accumulate. Spacing exports 20h apart makes the pattern invisible. "
            "Phase 13 decision: add a longer secondary window, or record it as a documented limitation."
        ),
        rationale=(
            "THREAT_MODEL S1/S6 ('before resignation' usually means days or weeks, not hours). "
            "Spacing exports just inside the correlation window's blind spot should not make "
            "the pattern invisible: by the fifth export some behavioral adjustment is expected."
        ),
        steps=(
            _export_step(1, 0),
            _export_step(2, 20 * 60),
            _export_step(3, 40 * 60),
            _export_step(4, 60 * 60),
            _export_step(5, 80 * 60, Expect(flagged=True, min_behavioral_adjustment=5)),
        ),
    ),
    Scenario(
        id="s6_light_office_day", threat="S6", kind="benign_control",
        title="Two ordinary documents saved four hours apart",
        rationale=(
            "Control for DR9: light, ordinary activity must not accumulate behavioral points "
            "(the lowest activity tier needs two PRIOR flagged events)."
        ),
        steps=(
            Step("file", "Minutes of the weekly sync.", 0, user="analyst", filename="minutes.docx",
                 expect=Expect(would_alert=False, max_severity="low", max_behavioral_adjustment=0)),
            Step("file", "Quarterly travel budget, draft.", 240, user="analyst", filename="budget.xlsx",
                 expect=Expect(would_alert=False, max_severity="low", max_behavioral_adjustment=0)),
        ),
    ),
)

validate_catalog(CATALOG)  # fail at import time, not mid-run, if the catalog breaks its own rules

BY_ID = {sc.id: sc for sc in CATALOG}
