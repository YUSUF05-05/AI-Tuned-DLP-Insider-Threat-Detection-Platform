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
