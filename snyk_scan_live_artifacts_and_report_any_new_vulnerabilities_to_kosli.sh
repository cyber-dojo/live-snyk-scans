#!/usr/bin/env bash
set -Eeu

root_dir() { git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

# KOSLI_API_TOKEN is set in CI
export KOSLI_ORG=cyber-dojo
export KOSLI_HOST="${1:-https://app.kosli.com}"
export CYBER_DOJO_ENVIRONMENT="${2:-aws-prod}"

# Global variables
FLOW=
GIT_COMMIT=
FINGERPRINT=
IMAGE_NAME=

snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli()
{
    local -r snapshot_json_filename=snapshot.json
    # Use Kosli CLI to get info on what artifacts are currently running in production
    kosli get snapshot "${CYBER_DOJO_ENVIRONMENT}" --output=json > "${snapshot_json_filename}"
    # Process info, one artifact at a time
    artifacts_length=$(jq '.artifacts | length' ${snapshot_json_filename})
    for i in $(seq 0 $(( ${artifacts_length} - 1 )));
    do
        annotation_type=$(jq -r ".artifacts[$i].annotation.type" ${snapshot_json_filename})
        if [ "${annotation_type}" != "exited" ]; then
          FLOW=$(jq -r ".artifacts[$i].flow_name" ${snapshot_json_filename})
          GIT_COMMIT=$(jq -r ".artifacts[$i].git_commit" ${snapshot_json_filename})
          FINGERPRINT=$(jq -r ".artifacts[$i].fingerprint" ${snapshot_json_filename})
          IMAGE_NAME=$(jq -r ".artifacts[$i].name" ${snapshot_json_filename})
          report_any_new_snyk_vulnerability_to_kosli
       fi
    done
}

report_any_new_snyk_vulnerability_to_kosli()
{
    local -r snyk_output_json_filename=snyk.json

    if [ "${FLOW}" == "" ]; then
      return  # The artifact has no provenance
    fi

    run_snyk_scan "${snyk_output_json_filename}"

    kosli report evidence artifact snyk \
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

    set +e
    snyk container test "${image_name}" \
        --json-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium \
        --policy-path="${snyk_policy_filename}"
    set -e
}

exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
