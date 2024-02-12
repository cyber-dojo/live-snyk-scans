#!/usr/bin/env bash
set -Eeu

repo_root() { git rev-parse --show-toplevel; }
source "$(repo_root)/scripts/exit_non_zero_unless_installed.sh"

# KOSLI_ORG          # Set in CI, cyber-dojo
# KOSLI_FLOW         # Set in CI, eg aws-prod-snyk-scan
# KOSLI_TRAIL        # Set in CI, eg 2024-02-11-T-12-06-59
# KOSLI_ENVIRONMENT  # Set in CI, eg aws-prod

export KOSLI_HOST="${1}"
export KOSLI_API_TOKEN="${2}"

kosli_begin_trail()
{
    kosli create flow "${KOSLI_FLOW}" \
      --description="Scan of Artifacts running in ${KOSLI_ENVIRONMENT}" \
      --template-file="$(repo_root)/.kosli.yml" \
      --visibility=public

    kosli begin trail "${KOSLI_TRAIL}"
}

snyk_scan_live_artifacts_and_attest_to_kosli_trail()
{
    local -r snapshot_json_filename=snapshot.json

    # Use Kosli CLI to get info on what artifacts are currently running in the given environment
    # (docs/snapshot.json contains an example json file)
    kosli get snapshot "${KOSLI_ENVIRONMENT}" --output=json > "${snapshot_json_filename}"

    # Process info, one artifact at a time
    artifacts_length=$(jq '.artifacts | length' ${snapshot_json_filename})
    for i in $(seq 0 $(( ${artifacts_length} - 1 )))
    do
        annotation_type=$(jq -r ".artifacts[$i].annotation.type" ${snapshot_json_filename})
        if [ "${annotation_type}" != "exited" ] ; then
          flow=$(jq -r ".artifacts[$i].flow_name" ${snapshot_json_filename})
          artifact_name=$(jq -r ".artifacts[$i].name" ${snapshot_json_filename})
          if [ "${flow}" == "" ] ; then
            echo "Artifact ${artifact_name} in Environment ${KOSLI_ENVIRONMENT} has no provenance in ${KOSLI_HOST}"
          else
            git_commit=$(jq -r ".artifacts[$i].git_commit" ${snapshot_json_filename})
            fingerprint=$(jq -r ".artifacts[$i].fingerprint" ${snapshot_json_filename})
            attest_snyk_scan_to_kosli_trail "${flow}" "${git_commit}" "${artifact_name}" "${fingerprint}"
          fi
       fi
    done
}

attest_snyk_scan_to_kosli_trail()
{
    local -r flow="${1}"          # eg differ-ci
    local -r git_commit="${2}"    # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
    local -r artifact_name="${3}" # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27
    local -r fingerprint="${4}"   # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e

    local -r repo="${flow::-3}"   # eg differ

    #echo "==============================="
    #echo "         flow=${flow}"
    #echo "   git-commit=${git_commit}"
    #echo "artifact_name=${artifact_name}"
    #echo "  fingerprint=${fingerprint}"
    #echo "         repo=${repo}"

    if [ "${repo}" == "runner" ] ; then
      # runner's snyk report currently exceeds the request size limit
      return 0
    fi

    local -r snyk_output_json_filename=snyk.json
    local -r snyk_policy_filename=.snyk

    # All cyber-dojo microservice repos hold a .snyk policy file.
    # This is an empty file when no vulnerabilities are turned-off.
    # Ensure we get the .snyk file for the given artifact's git commit.
    rm "${snyk_policy_filename}" || true
    if [ "${repo}" == "creator" ] ; then
      curl "https://gitlab.com/cyber-dojo/creator/-/raw/${git_commit}/.snyk" > "${snyk_policy_filename}"
    else
      curl "https://raw.githubusercontent.com/cyber-dojo/${repo}/${git_commit}/.snyk" > "${snyk_policy_filename}"
    fi
    cat "${snyk_policy_filename}"

    set +e
    # In CI we have already performed these actions:
    #   aws-actions/configure-aws-credentials@v4
    #   aws-actions/amazon-ecr-login@v2
    #   snyk/actions/setup@master
    snyk container test "${artifact_name}@sha256:${fingerprint}" \
        --json-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium \
        --policy-path="${snyk_policy_filename}"
    set -e

    set +e
    kosli attest snyk \
      --description="artifact=${artifact_name}, fingerprint=${fingerprint}" \
      --name="${repo}" \
      --scan-results="${snyk_output_json_filename}" 2>&1 | tee /tmp/kosli.snyk.log
    STATUS=${PIPESTATUS[0]}
    set -e

    if [ "${STATUS}" != "0" ] ; then
      echo "-------------------------------"
      echo ERROR: kosli attest snyk
      cat /tmp/kosli.snyk.log
    fi
}

exit_non_zero_unless_installed kosli snyk jq
kosli_begin_trail
snyk_scan_live_artifacts_and_attest_to_kosli_trail
