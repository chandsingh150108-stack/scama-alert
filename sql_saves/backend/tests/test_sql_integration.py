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
    row = db.query_one("SELECT fn_normalize_url(%s) AS u", ("https://www.Example.com/?utm_source=x",))
    assert row["u"].startswith("https://example.com")


def test_domain_age_null():
    _needs_db()
    row = db.query_one("SELECT fn_calculate_domain_age(NULL) AS a")
    assert int(row["a"]) == -1
