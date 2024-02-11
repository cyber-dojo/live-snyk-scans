#!/usr/bin/env bash
set -Eeu

root_dir() { git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

export KOSLI_FLOW=regular-snyk-scan
export KOSLI_HOST="${1}"
export KOSLI_API_TOKEN="${2}"
export KOSLI_ENVIRONMENT="${3}"
# KOSLI_ORG # Set in CI


snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli()
{
    local -r snapshot_json_filename=snapshot.json

    # Use Kosli CLI to get info on what artifacts are currently running in the given environment
    # (docs/snapshot.json contains an example json file)
    kosli get snapshot "${KOSLI_ENVIRONMENT}" --output=json > "${snapshot_json_filename}"
    # Process info, one artifact at a time
    artifacts_length=$(jq '.artifacts | length' ${snapshot_json_filename})
    for i in $(seq 0 $(( ${artifacts_length} - 1 )));
    do
        annotation_type=$(jq -r ".artifacts[$i].annotation.type" ${snapshot_json_filename})
        if [ "${annotation_type}" != "exited" ]; then
          flow=$(jq -r ".artifacts[$i].flow_name" ${snapshot_json_filename})
          artifact_name=$(jq -r ".artifacts[$i].name" ${snapshot_json_filename})
          if [ "${flow}" == "" ]; then
            echo "Artifact ${artifact_name} in Environment ${KOSLI_ENVIRONMENT} has no provenance in ${KOSLI_HOST}"
          else
            git_commit=$(jq -r ".artifacts[$i].git_commit" ${snapshot_json_filename})
            fingerprint=$(jq -r ".artifacts[$i].fingerprint" ${snapshot_json_filename})
            report_snyk_vulnerabilities_to_kosli "${flow}" "${git_commit}" "${artifact_name}" "${fingerprint}"
          fi
       fi
    done
}

report_snyk_vulnerabilities_to_kosli()
{
    local -r flow="${1}"          # eg differ
    local -r git_commit="${2}"    # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
    local -r artifact_name="${3}" # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27
    local -r fingerprint="${4}"   # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e

    if [ "${flow}" == "languages-start-points" ]; then
      # For one micro-service only, experiment with reporting to dedicated flow
      report_snyk_vulnerabilities_to_kosli_in_dedicated_flow "${flow}" "${git_commit}" "${artifact_name}" "${fingerprint}"
    fi

    local -r snyk_output_json_filename=snyk.json
    local -r snyk_policy_filename=.snyk

    echo "==============================="
    echo "Flow=${flow}"

    # All cyber-dojo microservice repos hold a .snyk policy file.
    # This is an empty file when no vulnerabilities are turned-off.
    # Ensure we get the .snyk file for the given artifact's git commit.
    echo "-------------------------------"
    rm "${snyk_policy_filename}" || true
    if [ "${flow}" = "creator" ]; then
      curl "https://gitlab.com/cyber-dojo/creator/-/raw/${git_commit}/.snyk" > "${snyk_policy_filename}"
    else
      curl "https://raw.githubusercontent.com/cyber-dojo/${flow}/${git_commit}/.snyk" > "${snyk_policy_filename}"
    fi
    cat "${snyk_policy_filename}"

    echo "-------------------------------"
    echo snyk container test "${artifact_name}@sha256:${fingerprint}"

    set +e
    snyk container test "${artifact_name}@sha256:${fingerprint}" \
        --json-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium \
        --policy-path="${snyk_policy_filename}"
    set -e

    echo "-------------------------------"
    echo kosli report evidence artifact snyk

    set +e
    kosli report evidence artifact snyk \
      --fingerprint="${fingerprint}" \
      --flow="${flow}" \
      --name=snyk-scan \
      --scan-results="${snyk_output_json_filename}" 2>&1 | tee /tmp/kosli.snyk.log
    STATUS=${PIPESTATUS[0]}
    # Error: The data value transmitted exceeds the capacity limit.
    set -e

    if [ "${STATUS}" != "0" ] ; then
      echo "-------------------------------"
      echo ERROR: kosli report evidence artifact snyk
      cat /tmp/kosli.snyk.log
    fi
}

report_snyk_vulnerabilities_to_kosli_in_dedicated_flow()
{
    local -r flow="${1}"          # eg differ
    local -r git_commit="${2}"    # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
    local -r artifact_name="${3}" # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27
    local -r fingerprint="${4}"   # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e

    local -r snyk_output_json_filename=snyk.json
    local -r snyk_policy_filename=.snyk

    # All cyber-dojo microservice repos hold a .snyk policy file.
    # This is an empty file when no vulnerabilities are turned-off.
    # Ensure we get the .snyk file for the given artifact's git commit.
    rm "${snyk_policy_filename}" || true
    if [ "${flow}" = "creator" ]; then
      curl "https://gitlab.com/cyber-dojo/creator/-/raw/${git_commit}/.snyk" > "${snyk_policy_filename}"
    else
      curl "https://raw.githubusercontent.com/cyber-dojo/${flow}/${git_commit}/.snyk" > "${snyk_policy_filename}"
    fi
    cat "${snyk_policy_filename}"

    set +e
    snyk container test "${artifact_name}@sha256:${fingerprint}" \
        --json-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium \
        --policy-path="${snyk_policy_filename}"
    set -e

    kosli create flow "${KOSLI_FLOW}" \
      --description="Scan of deployed Artifacts running in their Environment" \
      --template=artifact,snyk-scan

    kosli report artifact "${artifact_name}" \
      --fingerprint="${fingerprint}"

    kosli report evidence artifact snyk "${artifact_name}" \
      --fingerprint="${fingerprint}" \
      --name=snyk-scan \
      --scan-results="${snyk_output_json_filename}"
}


exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_report_any_new_vulnerabilities_to_kosli
