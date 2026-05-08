#!/usr/bin/env python3
"""Print a Markdown summary of expiring Snyk vulnerabilities for the GitHub step summary."""

import argparse
import json
import re
import sys
from datetime import date, timedelta


SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def extract_artifact_name(trail_name):
    """Extract artifact name by taking the trail_name segment before the first -severity- part."""
    match = re.search(r'-(critical|high|medium|low)-', trail_name)
    if match:
        return trail_name[:match.start()]
    return trail_name


def severity_sort_key(vuln):
    """Return a sort tuple (severity_rank, days_remaining) for ordering rows in a table."""
    rank = SEVERITY_ORDER.index(vuln["severity"]) if vuln["severity"] in SEVERITY_ORDER else 99
    return (rank, vuln["days_remaining"])


def max_expiry_line(env, today_str):
    """Return a formatted string showing the maximum pasteable .snyk expiry date for env."""
    with open(f"rego.params.{env}.json") as f:
        params = json.load(f)
    max_days = params["max_ignore_expiry_days"]
    max_date = date.fromisoformat(today_str) + timedelta(days=max_days)
    return f"Maximum .snyk ignore expiry: {max_date}T00:00:00.000Z ({max_days} days from today)"


def format_env_section(env_label, vulns, expiry_line):
    """Return a list of Markdown lines for one environment's section."""
    if not vulns:
        return [f"## {env_label} (Snyk vulns nearing expiry: Count=0)", ""]

    lines = [f"## {env_label} (Snyk vulns nearing expiry: Count={len(vulns)})", ""]
    lines.append(expiry_line)
    lines.append("")

    artifacts = {}
    for v in vulns:
        artifact = extract_artifact_name(v["trail_name"])
        artifacts.setdefault(artifact, []).append(v)

    for artifact in sorted(artifacts):
        artifact_vulns = sorted(artifacts[artifact], key=severity_sort_key)
        lines.append(f"### {artifact} (Count={len(artifact_vulns)})")
        lines.append("")
        lines.append("| Level | Days remaining | Mechanism | Vuln ID |")
        lines.append("|-------|----------------|-----------|---------|")
        for v in artifact_vulns:
            days = int(round(v["days_remaining"]))
            link = f"[{v['full_id']}]({v['vuln_url']})"
            lines.append(f"| {v['severity']} | {days} | {v['mechanism']} | {link} |")
        lines.append("")

    return lines


def main():
    """Parse --env and --vulns JSON array and print a Markdown step summary to stdout."""
    parser = argparse.ArgumentParser(description="Print Markdown expiry summary.")
    parser.add_argument("--env",   required=True, help="Environment name, e.g. aws-beta")
    parser.add_argument("--vulns", required=True, help="JSON array of expiring vulns for the environment")
    parser.add_argument("--today", default=date.today().isoformat(),
                        help="Today's date as YYYY-MM-DD (default: system date)")
    args = parser.parse_args()

    vulns = json.loads(args.vulns)
    lines = format_env_section(args.env, vulns, max_expiry_line(args.env, args.today))
    print("\n".join(lines).rstrip("\n"))


if __name__ == "__main__":  # pragma: no cover
    main()
