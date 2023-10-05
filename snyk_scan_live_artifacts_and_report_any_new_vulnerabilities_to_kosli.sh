#!/usr/bin/env bash
set -Eeu

root_dir() { git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

export KOSLI_ORG=cyber-dojo
export KOSLI_HOST="${1:-https://app.kosli.com}"
export CYBER_DOJO_ENVIRONMENT="${2:-aws-prod}"

# Global variables
FLOW=
GIT_COMMIT=
FINGERPRINT=
NAME=

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

    if [ "${FLOW}" == "" ]; then
      return  # The artifact has no provenance
    fi

    run_snyk_scan "${snyk_output_json_filename}"

    kosli report evidence artifact snyk "${NAME}" \
        --fingerprint="${FINGERPRINT}"  \
        --flow="${FLOW}"                \
        --name=snyk-scan                \
        --scan-results="${snyk_output_json_filename}"
}

run_snyk_scan()
{
    local -r snyk_output_json_filename="${1}"
    # Use fingerprint in image name for absolute certainty of image's identity.
    local -r image_name="cyberdojo/${FLOW}@sha256:${FINGERPRINT}"
    local -r snyk_policy_filename=.snyk

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
        ${severity_threshold} \
        --policy-path="${snyk_policy_filename}"
    set -e
}

exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
