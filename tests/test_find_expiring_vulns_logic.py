#!/usr/bin/env python3
"""Unit tests for check_dot_snyk_expiry and check_rego_limit."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import find_expiring_vulns  # noqa: E402

NOW_TS = 1748736000.0   # 2025-06-01 00:00:00 UTC
WARNING_DAYS = 7
PROD_MAX_DAYS = {"critical": 3, "high": 7, "medium": 30, "low": 90}
BETA_MAX_DAYS = {"critical": 0, "high": 7, "medium": 30, "low": 90}


def _high_vuln_no_ignore(first_seen_ts=None):
    """Return a minimal attestation_data dict for a high-severity vuln with no ignore."""
    return {
        "trail_name": "creator-high-SNYK-GOLANG-NETHTTP-3321444",
        "full_id": "SNYK-GOLANG-NETHTTP-3321444",
        "severity": "high",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
        "ignore_expires_exists": False,
        "ignore_expires_ts": 0,
        "ignore_expires": "",
        "first_seen_ts": first_seen_ts if first_seen_ts is not None else NOW_TS - 4 * 86400,
    }


class TestCheckDotSnykExpiry(unittest.TestCase):

    def test_returns_result_when_expiry_within_warning_window(self):
        """Expiry 3 days out with a 7-day warning window produces a result."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS + 3 * 86400,
                "ignore_expires": "2025-06-04 00:00:00+00:00"}
        result = find_expiring_vulns.check_dot_snyk_expiry(data, "aws-prod", WARNING_DAYS, NOW_TS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "dot_snyk_expiry")
        self.assertAlmostEqual(result["days_remaining"], 3.0, places=5)
        self.assertEqual(result["env"], "aws-prod")

    def test_returns_none_when_expiry_beyond_warning_window(self):
        """Expiry 10 days out is not yet close enough to warn."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS + 10 * 86400,
                "ignore_expires": "2025-06-11 00:00:00+00:00"}
        result = find_expiring_vulns.check_dot_snyk_expiry(data, "aws-prod", WARNING_DAYS, NOW_TS)
        self.assertIsNone(result)

    def test_returns_none_when_expiry_already_passed(self):
        """An already-expired ignore is non-compliant, not approaching-expiry."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS - 1,
                "ignore_expires": "2025-05-31 23:59:59+00:00"}
        result = find_expiring_vulns.check_dot_snyk_expiry(data, "aws-prod", WARNING_DAYS, NOW_TS)
        self.assertIsNone(result)

    def test_returns_none_when_no_ignore_entry(self):
        """check_dot_snyk_expiry does not apply when there is no .snyk ignore entry."""
        result = find_expiring_vulns.check_dot_snyk_expiry(
            _high_vuln_no_ignore(), "aws-prod", WARNING_DAYS, NOW_TS)
        self.assertIsNone(result)


class TestCheckRegoLimit(unittest.TestCase):

    def test_returns_result_when_age_approaching_limit(self):
        """High vuln 4 days old against a 7-day limit has 3 days remaining."""
        data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 4 * 86400)
        result = find_expiring_vulns.check_rego_limit(
            data, "aws-prod", WARNING_DAYS, NOW_TS, PROD_MAX_DAYS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "rego_limit")
        self.assertAlmostEqual(result["days_remaining"], 3.0, places=5)
        self.assertEqual(result["limit_days"], 7)

    def test_returns_none_when_age_far_from_limit(self):
        """Low vuln 1 day old against a 90-day limit is not close enough to warn."""
        data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400),
                "severity": "low",
                "trail_name": "creator-low-SNYK-GOLANG-NETHTTP-3321444"}
        result = find_expiring_vulns.check_rego_limit(
            data, "aws-prod", WARNING_DAYS, NOW_TS, PROD_MAX_DAYS)
        self.assertIsNone(result)

    def test_returns_none_when_limit_already_exceeded(self):
        """High vuln 10 days old against a 7-day limit is already non-compliant."""
        data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 10 * 86400)
        result = find_expiring_vulns.check_rego_limit(
            data, "aws-prod", WARNING_DAYS, NOW_TS, PROD_MAX_DAYS)
        self.assertIsNone(result)

    def test_returns_none_when_ignore_entry_exists(self):
        """check_rego_limit does not apply when a .snyk ignore entry exists (check_dot_snyk_expiry handles it)."""
        data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 4 * 86400),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS + 3 * 86400}
        result = find_expiring_vulns.check_rego_limit(
            data, "aws-prod", WARNING_DAYS, NOW_TS, PROD_MAX_DAYS)
        self.assertIsNone(result)

    def test_returns_none_for_critical_in_beta_where_limit_is_zero(self):
        """Critical vulns in aws-beta have a 0-day limit so days_remaining is always negative."""
        data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 1),
                "severity": "critical",
                "trail_name": "creator-critical-SNYK-GOLANG-NETHTTP-3321444"}
        result = find_expiring_vulns.check_rego_limit(
            data, "aws-beta", WARNING_DAYS, NOW_TS, BETA_MAX_DAYS)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
