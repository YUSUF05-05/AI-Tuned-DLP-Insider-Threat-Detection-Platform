import base64
import json
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.secret_detector import (
    detect,
    _find_aws_secret_candidates,
    get_pattern,
)

# AKIAIOSFODNN7EXAMPLE and the matching secret below are AWS's OWN publicly
# published documentation example credentials (used in every AWS SDK
# tutorial); they are not a real, active credential pair.
AWS_EXAMPLE_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_EXAMPLE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_" + "A" * 36
SLACK_TOKEN = "TEST_SLACK_TOKEN_NOT_REAL"
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"


def _make_fake_jwt() -> str:
    def b64url(obj: dict) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64url({"alg": "HS256", "typ": "JWT"})
    payload = b64url({"sub": "test-user", "role": "demo"})
    signature = "fakeSignatureForTestingOnly123"
    return f"{header}.{payload}.{signature}"


def test_detects_aws_access_key_id():
    result = detect(f"export AWS_ACCESS_KEY_ID={AWS_EXAMPLE_ACCESS_KEY}")
    assert result.matched is True
    assert "aws_access_key_id" in result.details["pattern_types"]


def test_aws_access_key_never_appears_raw_in_evidence():
    result = detect(f"export AWS_ACCESS_KEY_ID={AWS_EXAMPLE_ACCESS_KEY}")
    assert all(AWS_EXAMPLE_ACCESS_KEY not in m for m in result.matches)


def test_detects_aws_secret_key_with_context():
    text = f"aws_secret_access_key = {AWS_EXAMPLE_SECRET_KEY}"
    candidates = _find_aws_secret_candidates(text)
    assert AWS_EXAMPLE_SECRET_KEY in candidates


def test_ignores_40char_hex_git_sha_even_near_aws_word():
    # A git commit SHA is 40 hex chars; must not be flagged as an AWS secret
    # just because the word "aws" happens to appear nearby (e.g. an "aws-cli"
    # repo commit reference).
    git_sha = "a" * 40  # valid 40-char hex-looking string
    text = f"aws-cli commit reference {git_sha} fixed the bug"
    candidates = _find_aws_secret_candidates(text)
    assert git_sha not in candidates


def test_detects_github_token():
    result = detect(f"GITHUB_TOKEN={GITHUB_TOKEN}")
    assert result.matched is True
    assert "github_token" in result.details["pattern_types"]


def test_detects_slack_token():
    result = detect(f"Slack webhook token: {SLACK_TOKEN}")
    assert result.matched is True
    assert "slack_token" in result.details["pattern_types"]


def test_detects_slack_token():
    synthetic_slack_pattern = re.compile(
        r"\bTEST_SLACK_TOKEN_[A-Z0-9_-]{10,}\b"
    )

    test_patterns = [
        (
            "slack_token",
            synthetic_slack_pattern,
            0.9,
        )
    ]

    result = detect(
        "Slack webhook token: TEST_SLACK_TOKEN_NOT_REAL_123456",
        patterns=test_patterns,
    )

    assert result.matched is True
    assert "slack_token" in result.details["pattern_types"]


def test_slack_production_pattern_structure():
    pattern = get_pattern("slack_token")

    assert pattern.pattern == r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"

def test_detects_jwt():
    token = _make_fake_jwt()
    result = detect(f"Authorization header value: {token}")
    assert result.matched is True
    assert "jwt" in result.details["pattern_types"]


def test_detects_generic_api_key_assignment():
    result = detect('api_key = "TEST_SLACK_TOKEN_NOT_REAL"')
    assert result.matched is True
    assert "generic_api_key_assignment" in result.details["pattern_types"]


def test_no_match_on_clean_text():
    result = detect("The quarterly report is due next Friday.")
    assert result.matched is False
    assert result.matches == []


def test_multiple_secret_types_in_one_document():
    text = (
        f"AWS_ACCESS_KEY_ID={AWS_EXAMPLE_ACCESS_KEY}\n"
        f"GITHUB_TOKEN={GITHUB_TOKEN}\n"
        f"{PRIVATE_KEY_HEADER}\n"
    )
    result = detect(text)
    assert result.details["count"] >= 3
    assert len(result.details["pattern_types"]) >= 3
