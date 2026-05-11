#!/usr/bin/env python3
"""Find Snyk vulnerabilities that have not yet caused non-compliance."""

import argparse
import json
import re
import subprocess
import sys
import time


def extract_artifact_name(trail_name):
    """Extract artifact name by taking the trail_name segment before the first -severity- part."""
    match = re.search(r'-(critical|high|medium|low)-', trail_name)
    if match:
        return trail_name[:match.start()]
    return trail_name


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


def dot_snyk_result(data, env, now_ts):
    """Return a result dict if the .snyk ignore entry has a future expiry, else None."""
    if not data.get("ignore_expires_exists"):
        return None
    secs_remaining = data["ignore_expires_ts"] - now_ts
    if secs_remaining <= 0:
        return None
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
        "artifact": extract_artifact_name(data["trail_name"]),
    }


def rego_result(data, env, now_ts, max_days):
    """Return a result dict if the vuln is still within its rego age limit, else None."""
    if data.get("ignore_expires_exists"):
        return None
    severity = data["severity"]
    limit = max_days.get(severity, 0)
    if limit <= 0:
        return None
    age_days = (now_ts - data["first_seen_ts"]) / 86400
    days_remaining = limit - age_days
    if days_remaining <= 0:
        return None
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
        "artifact": extract_artifact_name(data["trail_name"]),
    }


def find_vulns_for_env(env, now_ts, cutoff_ts):
    """Return all currently-compliant vulns sorted by days_remaining for a single environment."""
    params_file = f"rego.params.{env}.json"
    with open(params_file) as f:
        params = json.load(f)
    max_days = params["max_days_by_severity"]

    flow = f"snyk-{env}-per-vuln"
    vulns = []
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
            result = dot_snyk_result(data, env, now_ts)
            if result:
                vulns.append(result)
            result = rego_result(data, env, now_ts, max_days)
            if result:
                vulns.append(result)

        oldest_ts = min(t["last_modified_at"] for t in trails)
        if oldest_ts < cutoff_ts:
            break
        pagination = response.get("pagination", {})
        if page >= pagination.get("page_count", 1):
            break
        page += 1

    vulns.sort(key=lambda v: v["days_remaining"])
    return vulns


def main():
    """Parse args, find all currently-compliant vulns, print JSON to stdout."""
    parser = argparse.ArgumentParser(description="Find Snyk vulns with time remaining before non-compliance.")
    parser.add_argument("--envs", required=True,
                        help="Comma-separated list of environments, e.g. aws-beta,aws-prod")
    args = parser.parse_args()

    now_ts = time.time()
    cutoff_ts = now_ts - 48 * 3600
    envs = [e.strip() for e in args.envs.split(",")]

    all_vulns = []
    for env in envs:
        all_vulns.extend(find_vulns_for_env(env, now_ts, cutoff_ts))

    all_vulns.sort(key=lambda v: v["days_remaining"])
    print(json.dumps({"vulns": all_vulns}))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
