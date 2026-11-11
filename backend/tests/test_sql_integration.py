"""SQL integration (auto-skip without MySQL). Mirrors src/sql/*.test.ts."""
import os

import pytest

from backend import db

NEED_DB = os.environ.get("SCAMALERT_TEST_DB", "0") == "1"


def _needs_db():
    if not NEED_DB:
        pytest.skip("no MySQL (set SCAMALERT_TEST_DB=1 to enable)")
    try:
        db.query("SELECT 1")
    except Exception as e:
        pytest.skip(f"no MySQL: {e}")


def test_reputation_tier_boundaries():
    _needs_db()
    cases = [(95, "moderator"), (90, "moderator"), (88, "expert"), (75, "expert"),
             (58, "trusted"), (48, "trusted"), (40, "trusted"), (20, "new"), (0, "newcomer")]
    for score, tier in cases:
        row = db.query_one("SELECT fn_get_reputation_tier(%s) AS t", (score,))
        assert row["t"] == tier


def test_normalize_url():
    _needs_db()
    cases = [
        ("https://www.Example.com/?utm_source=x", "https://example.com"),
        ("amazon.in", "https://amazon.in"),
        ("https:/amazon.in", "https://amazon.in"),
        ("https:/amazon.com", "https://amazon.com"),
        ("http:/example.com", "https://example.com"),
        ("HTTP://EXAMPLE.COM/", "https://example.com"),
        ("www.example.com", "https://example.com"),
        ("https://example.com:443/", "https://example.com"),
        ("https://example.com:80/", "https://example.com"),
        ("https://example.com/path?utm_source=x&fbclid=y", "https://example.com/path"),
    ]
    for inp, expected_start in cases:
        row = db.query_one("SELECT fn_normalize_url(%s) AS u", (inp,))
        assert row["u"].startswith(expected_start), f"Input: {inp}, Got: {row['u']}, Expected start: {expected_start}"
