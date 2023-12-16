#!/usr/bin/env bash
set -Eeu

root_dir() { git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

# KOSLI_API_TOKEN is set in CI
export KOSLI_HOST="${1}"
export KOSLI_ORG="${2}"
export KOSLI_ENVIRONMENT="${3}"

# Global variables
FLOW=             # eg differ
GIT_COMMIT=       # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
FINGERPRINT=      # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e
ARTIFACT_NAME=    # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27

snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli()
{
    local -r snapshot_json_filename=snapshot.json
    # Use Kosli CLI to get info on what artifacts are currently running in production
    # (docs/snapshot.json contains an example json file)
    kosli get snapshot "${KOSLI_ENVIRONMENT}" --output=json > "${snapshot_json_filename}"
    # Process info, one artifact at a time
    artifacts_length=$(jq '.artifacts | length' ${snapshot_json_filename})
    for i in $(seq 0 $(( ${artifacts_length} - 1 )));
    do
        annotation_type=$(jq -r ".artifacts[$i].annotation.type" ${snapshot_json_filename})
        if [ "${annotation_type}" != "exited" ]; then
          FLOW=$(jq -r ".artifacts[$i].flow_name" ${snapshot_json_filename})
          GIT_COMMIT=$(jq -r ".artifacts[$i].git_commit" ${snapshot_json_filename})
          FINGERPRINT=$(jq -r ".artifacts[$i].fingerprint" ${snapshot_json_filename})
          ARTIFACT_NAME=$(jq -r ".artifacts[$i].name" ${snapshot_json_filename})
          report_snyk_vulnerabilities_to_kosli
       fi
    done
}

report_snyk_vulnerabilities_to_kosli()
{
    local -r snyk_output_json_filename=snyk.json
    # Use fingerprint in image name for absolute certainty of image's identity.
    local -r image_name="${ARTIFACT_NAME}@sha256:${FINGERPRINT}"
    local -r snyk_policy_filename=.snyk

    if [ "${FLOW}" == "" ]; then
      return  # The artifact has no provenance
    fi

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

    kosli report evidence artifact snyk \
        --fingerprint="${FINGERPRINT}"  \
        --flow="${FLOW}"                \
        --name=snyk-scan                \
        --scan-results="${snyk_output_json_filename}"
}

exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
