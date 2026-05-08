#!/usr/bin/env python3
"""Print a Markdown summary of expiring Snyk vulnerabilities for the GitHub step summary."""

import argparse
import json
import re
import sys


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


def format_env_section(env_label, vulns):
    """Return a list of Markdown lines for one environment's section."""
    if not vulns:
        return [f"## {env_label} (Count=0)", ""]

    lines = [f"## {env_label}", ""]

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
    """Parse --beta and --prod JSON arrays and print a Markdown step summary to stdout."""
    parser = argparse.ArgumentParser(description="Print Markdown expiry summary.")
    parser.add_argument("--beta", required=True, help="JSON array of expiring vulns for aws-beta")
    parser.add_argument("--prod", required=True, help="JSON array of expiring vulns for aws-prod")
    args = parser.parse_args()

    beta_vulns = json.loads(args.beta)
    prod_vulns = json.loads(args.prod)

    lines = []
    lines.extend(format_env_section("aws-beta", beta_vulns))
    lines.extend(format_env_section("aws-prod", prod_vulns))
    print("\n".join(lines).rstrip("\n"))


if __name__ == "__main__":  # pragma: no cover
    main()
