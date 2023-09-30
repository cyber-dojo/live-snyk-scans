#!/usr/bin/env bash
set -Eeu

export KOSLI_ORG=cyber-dojo
#export KOSLI_HOST=https://app.kosli.com
#export CYBER_DOJO_ENVIRONMENT=aws-prod
export KOSLI_HOST=https://staging.app.kosli.com
export CYBER_DOJO_ENVIRONMENT=aws-beta

# Global variables
FLOW=
GIT_COMMIT=
FINGERPRINT=
NAME=
SNYK_EXIT_CODE=

snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli()
{
    local -r snapshot_json_filename=snapshot.json
    # Use Kosli CLI to get info on what artifacts are currently running in production
    kosli get snapshot "${CYBER_DOJO_ENVIRONMENT}" --output=json > "${snapshot_json_filename}"
    # Save artifact info in array variables.
    # Note: Assumes all artifacts have provenance.
    flows=($(jq -r '.[].flow' ${snapshot_json_filename}))
    git_commits=($(jq -r '.[].git_commit' ${snapshot_json_filename}))
    fingerprints=($(jq -r '.[].fingerprint' ${snapshot_json_filename}))
    names=($(jq -r '.[].artifact' ${snapshot_json_filename}))
    # Process info, one artifact at a time
    for i in ${!flows[@]}
    do
        FLOW="${flows[$i]}"
        GIT_COMMIT="${git_commits[$i]}"
        FINGERPRINT="${fingerprints[$i]}"
        NAME="${names[$i]}"
        report_any_new_snyk_vulnerability_to_kosli
    done
}

report_any_new_snyk_vulnerability_to_kosli()
{
    local -r artifact_json_filename=artifact.json
    local -r snyk_output_json_filename=snyk.json

    # Get the artifact's current compliance from its Kosli flow.
    # Note: The compliance state of an artifact is not in the snapshot json.
    kosli get artifact "${FLOW}@${FINGERPRINT}" --output=json > "${artifact_json_filename}"
    current_compliance=($(jq -r '.state' ${artifact_json_filename}))

    run_snyk_scan "${snyk_output_json_filename}"
    # Snyk exit codes:
    #   0: success (scan completed), no vulnerabilities found
    #   1: action_needed (scan completed), vulnerabilities found
    #   2: failure, try to re-run command
    #   3: failure, no supported projects detected

    echo "current-compliance==${current_compliance}"
    echo "snyk_exit_code=${SNYK_EXIT_CODE}"
    if [[ "${current_compliance}" == "COMPLIANT" ]] && [[ "${SNYK_EXIT_CODE}" == "1" ]]
    then
        kosli report evidence artifact snyk "${NAME}" \
            --fingerprint="${FINGERPRINT}"  \
            --flow="${FLOW}"                \
            --name=snyk-scan                \
            --scan-results="${snyk_output_json_filename}"
    fi
}

run_snyk_scan()
{
    local -r snyk_output_json_filename="${1}"
    # Use fingerprint in image name for absolute certainty of image's identity.
    local -r image_name="cyberdojo/${FLOW}@sha256:${FINGERPRINT}"
    local -f snyk_policy_filename=.snyk

    # All cyber-dojo microservice repos hold a .snyk policy file.
    # This is an empty file when no vulnerabilities are turned-off.
    # Ensure we get the .snyk file for the given artifact's git commit.
    curl "https://raw.githubusercontent.com/cyber-dojo/${FLOW}/${GIT_COMMIT}/.snyk"  > "${snyk_policy_filename}"

    # The nginx base image has many low-severity vulnerabilities, which
    # can't be easily ignored in the .snyk file, so we're ignoring them
    # by bumping nginx to medium threshold.
    if [[ "${FLOW}" == "nginx" ]]; then
      severity_threshold=--severity-threshold=medium
    else
      severity_threshold=
    fi

    set +e
    snyk container test "${image_name}" \
        --json-file-output="${snyk_output_json_filename}" \
        ${severity_threshold  } \
        --policy-path="${snyk_policy_filename}"
    SNYK_EXIT_CODE=$?
    set -e
}

snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
