#!/usr/bin/env python3
"""Find Snyk vulnerabilities approaching their compliance expiry."""

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


def _next_up_candidates(data, env, warning_days, now_ts, max_days):
    """Return result dicts for future expiries outside the warning window on this trail."""
    candidates = []
    warning_secs = warning_days * 86400

    if data.get("ignore_expires_exists"):
        secs_remaining = data["ignore_expires_ts"] - now_ts
        if secs_remaining > warning_secs:
            candidates.append({
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
            })
    else:
        severity = data["severity"]
        limit = max_days.get(severity, 0)
        if limit > 0:
            age_days = (now_ts - data["first_seen_ts"]) / 86400
            days_remaining = limit - age_days
            if days_remaining > warning_days:
                candidates.append({
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
                })

    return candidates


def find_expiring_vulns_for_env(env, warning_days, now_ts, cutoff_ts):
    """Return (expiring_list, next_up_or_None) for a single environment."""
    params_file = f"rego.params.{env}.json"
    with open(params_file) as f:
        params = json.load(f)
    max_days = params["max_days_by_severity"]

    flow = f"snyk-{env}-per-vuln"
    results = []
    next_up_candidates = []
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
            next_up_candidates.extend(_next_up_candidates(data, env, warning_days, now_ts, max_days))

        oldest_ts = min(t["last_modified_at"] for t in trails)
        if oldest_ts < cutoff_ts:
            break
        pagination = response.get("pagination", {})
        if page >= pagination.get("page_count", 1):
            break
        page += 1

    next_up_candidates.sort(key=lambda c: c["days_remaining"])
    return results, next_up_candidates[0] if next_up_candidates else None


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

    expiring = []
    env_next_ups = []
    for env in envs:
        env_results, env_next_up = find_expiring_vulns_for_env(env, args.warning_days, now_ts, cutoff_ts)
        expiring.extend(env_results)
        if env_next_up is not None:
            env_next_ups.append(env_next_up)

    env_next_ups.sort(key=lambda c: c["days_remaining"])
    next_up = env_next_ups[0] if env_next_ups else None
    print(json.dumps({"expiring": expiring, "next_up": next_up}))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
