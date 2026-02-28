#!/usr/bin/env python3

import datetime
import sys
import json
import yaml

if __name__ == "__main__":  # pragma: no cover
    sarif_filename = sys.argv[1]
    snyk_policy_filename = sys.argv[2]

    # Extract ids and severities of each vulnerability in sarif file
    with open(sarif_filename) as sarif_file:
        sarif_data = json.load(sarif_file)

    epoch_start = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)

    vulns = {}
    for run in sarif_data['runs']:
        for rule in run['tool']['driver']['rules']:
            id = rule['id']
            url = f"https://security.snyk.io/vuln/{id}"
            short_text = rule['shortDescription']['text']
            #cvssv3_base_score = rule['properties']['cvssv3_baseScore'] # eg 6.8 can be None
            #security_severity = rule['properties']['security-severity'] # eg 6.8 can be None
            severity = short_text.split(' ')[0]  # eg "Medium"
            assert severity in ["Critical", "High", "Medium", "Low"]

            vulns[id] = {
                'severity': severity,
                'url': url,
                'expires': epoch_start
            }

    # Overwrite specific vulnerability expiry dates if found in snyk policy file (yaml)
    with open(snyk_policy_filename) as snyk_file:
        snyk_data = yaml.safe_load(snyk_file)

    ignore = snyk_data['ignore']
    for id in ignore:
        if id in vulns:
            vulns[id]['expires'] = ignore[id][0]['*']['expires']

    flat = []
    for id, values in vulns.items():
        flat.append({
            'snyk_id': id,
            'snyk_severity': values['severity'],
            'snyk_url': values['url'],
            'snyk_expires': values['expires']
        })

    print(json.dumps(flat, default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
