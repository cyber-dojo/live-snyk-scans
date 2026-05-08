#!/usr/bin/env python3
"""Find Snyk vulnerabilities approaching their compliance expiry."""

import argparse
import json
import subprocess
import sys
import time


def kosli_list_trails(flow, page, page_limit):
    """Call kosli list trails and return the parsed JSON response."""
    result = subprocess.run(
        [
            "kosli", "list", "trails",
            "--flow", flow,
            "--page", str(page),
            "--page-limit", str(page_limit),
            "--output", "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def kosli_get_attestation_data(flow, trail_name):
    """Call kosli get attestation snyk and return the attestation_data dict."""
    result = subprocess.run(
        [
            "kosli", "get", "attestation", "snyk",
            "--flow", flow,
            "--trail", trail_name,
            "--output", "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    items = json.loads(result.stdout)
    return items[0]["attestation_data"]


def check_dot_snyk_expiry(data, env, warning_days, now_ts):
    """Return a result dict if the explicit .snyk ignore entry is approaching expiry, else None."""
    if not data.get("ignore_expires_exists"):
        return None
    warning_secs = warning_days * 86400
    secs_remaining = data["ignore_expires_ts"] - now_ts
    if 0 < secs_remaining <= warning_secs:
        return {
            "env": env,
            "trail_name": data["trail_name"],
            "full_id": data["full_id"],
            "severity": data["severity"],
            "vuln_url": data["vuln_url"],
            "mechanism": "dot_snyk_expiry",
            "days_remaining": secs_remaining / 86400,
            "ignore_expires": data["ignore_expires"],
            "age_days": None,
            "limit_days": None,
        }
    return None


def check_rego_limit(data, env, warning_days, now_ts, max_days):
    """Return a result dict if the vuln is approaching the rego age limit, else None."""
    if data.get("ignore_expires_exists"):
        return None
    severity = data["severity"]
    limit = max_days[severity]
    age_days = (now_ts - data["first_seen_ts"]) / 86400
    days_remaining = limit - age_days
    if 0 < days_remaining <= warning_days:
        return {
            "env": env,
            "trail_name": data["trail_name"],
            "full_id": data["full_id"],
            "severity": data["severity"],
            "vuln_url": data["vuln_url"],
            "mechanism": "rego_limit",
            "days_remaining": days_remaining,
            "ignore_expires": None,
            "age_days": age_days,
            "limit_days": limit,
        }
    return None


def find_expiring_vulns_for_env(env, warning_days, now_ts, cutoff_ts):
    """Return a list of approaching-expiry vuln dicts for a single environment."""
    params_file = f"rego.params.{env}.json"
    with open(params_file) as f:
        params = json.load(f)
    max_days = params["max_days_by_severity"]

    flow = f"snyk-{env}-per-vuln"
    results = []
    page = 1

    while True:
        response = kosli_list_trails(flow, page, 200)
        trails = response.get("data", [])
        if not trails:
            break

        for trail in trails:
            if trail["last_modified_at"] < cutoff_ts:
                continue
            data = kosli_get_attestation_data(flow, trail["name"])
            result = check_dot_snyk_expiry(data, env, warning_days, now_ts)
            if result:
                results.append(result)
            result = check_rego_limit(data, env, warning_days, now_ts, max_days)
            if result:
                results.append(result)

        oldest_ts = min(t["last_modified_at"] for t in trails)
        if oldest_ts < cutoff_ts:
            break
        pagination = response.get("pagination", {})
        if page >= pagination.get("page_count", 1):
            break
        page += 1

    return results


def main():
    """Parse args, find expiring vulns for all specified envs, print JSON to stdout."""
    parser = argparse.ArgumentParser(description="Find Snyk vulns approaching expiry.")
    parser.add_argument("--warning-days", type=int, required=True,
                        help="Warn if expiry is within this many days.")
    parser.add_argument("--envs", required=True,
                        help="Comma-separated list of environments, e.g. aws-beta,aws-prod")
    args = parser.parse_args()

    now_ts = time.time()
    cutoff_ts = now_ts - 48 * 3600
    envs = [e.strip() for e in args.envs.split(",")]

    results = []
    for env in envs:
        results.extend(find_expiring_vulns_for_env(env, args.warning_days, now_ts, cutoff_ts))

    print(json.dumps(results))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
