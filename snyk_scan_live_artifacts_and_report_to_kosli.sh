#!/usr/bin/env bash
set -Eeu

root_dir() { git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

export KOSLI_ENVIRONMENT="${1}"
export KOSLI_FLOW=regular-snyk-scan
# KOSLI_HOST      # Set in CI
# KOSLI_ORG       # Set in CI
# KOSLI_API_TOKEN # Set in CI

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
          flow=$(jq -r ".artifacts[$i].flow_name" ${snapshot_json_filename})
          git_commit=$(jq -r ".artifacts[$i].git_commit" ${snapshot_json_filename})
          fingerprint=$(jq -r ".artifacts[$i].fingerprint" ${snapshot_json_filename})
          artifact_name=$(jq -r ".artifacts[$i].name" ${snapshot_json_filename})
          report_snyk_vulnerabilities_to_kosli "${flow}" "${git_commit}" "${fingerprint}" "${artifact_name}"
       fi
    done
}

report_snyk_vulnerabilities_to_kosli()
{
    local -r flow="${1}"           # eg differ
    local -r git_commit="${2}"     # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
    local -r fingerprint="${3}"    # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e
    local -r artifact_name="${4}"  # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27

    local -r snyk_output_json_filename=snyk.json
    # Use fingerprint in image name for absolute certainty of image's identity.
    local -r image_name="${artifact_name}@sha256:${fingerprint}"
    local -r snyk_policy_filename=.snyk

    if [ "${flow}" == "" ]; then
      return  # The artifact has no provenance
    fi

    # All cyber-dojo microservice repos hold a .snyk policy file.
    # This is an empty file when no vulnerabilities are turned-off.
    # Ensure we get the .snyk file for the given artifact's git commit.
    curl "https://raw.githubusercontent.com/cyber-dojo/${flow}/${git_commit}/.snyk"  > "${snyk_policy_filename}"

    set +e
    snyk container test "${image_name}" \
        --json-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium \
        --policy-path="${snyk_policy_filename}"
    set -e

    kosli create flow "${KOSLI_FLOW}" \
      --description="Scan of deployed Artifacts running in their Environment" \
      --template=artifact,snyk-scan

    kosli report artifact "${image_name}" \
      --artifact-type=docker

    kosli report evidence artifact snyk \
      --fingerprint="${fingerprint}" \
      --name=snyk-scan \
      --scan-results="${snyk_output_json_filename}"
}

exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
