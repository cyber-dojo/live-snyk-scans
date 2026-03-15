#!/usr/bin/env python3

from collections import defaultdict
import json
import os
import subprocess
import sys

# Reads the json output from a call to
#   kosli get trail "${KOSLI_TRAIL} --output=json
# and gets the json custom-attestation-data in each attestation.

if __name__ == "__main__":
    trail_filename = sys.argv[1]

    with open(trail_filename) as trail_file:
        trail_json = json.load(trail_file)

    atts = defaultdict(list)
    for event in trail_json['events']:
        if event['type'] == 'trail_attestation_reported':
            id = event['attestation_id']
            command = [
                'kosli', 'get', 'attestation',
                f"--attestation-id={id}",
                '--org=cyber-dojo',
                '--api-token=read-only',
                '--debug=false',
                '--output=json'
            ]

            # NOTE: `kosli get attestation` will NOT work if these env-vars are set
            # KOSLI_FLOW, KOSLI_TRAIL, KOSLI_FINGERPRINT
            env = {}
            for name, value in os.environ.items():
                if not name.startswith("KOSLI_"):
                    env[name] = value

            result = subprocess.run(command, capture_output=True, env=env, text=True)
            if result.returncode == 0:
                att_json = json.loads(result.stdout)
                att_data_json = att_json['data'][0]['attestation_data']
                if att_data_json['snyk_full_id'] != '':
                    fingerprint = att_data_json['artifact_fingerprint']
                    atts[fingerprint].append(att_data_json)
            else:
                print(result.stderr)
                sys.exit(result.returncode)

    print(json.dumps(atts, default=str))

