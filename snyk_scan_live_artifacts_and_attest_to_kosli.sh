#!/usr/bin/env bash
set -Eeu

repo_root() { git rev-parse --show-toplevel; }
source "$(repo_root)/scripts/exit_non_zero_unless_installed.sh"

# KOSLI_HOST         # Set in workflow
# KOSLI_API_TOKEN    # Set in workflow
# KOSLI_ORG          # Set in workflow, cyber-dojo

export KOSLI_ENVIRONMENT="${1}"  # eg aws-prod
export KOSLI_FLOW=aws-snyk-scan
export KOSLI_DRY_RUN=true

snyk_scan_live_artifacts_and_attest_to_kosli_trail()
{
    # Use Kosli CLI to get info on what artifacts are currently running in the given environment
    # The file docs/snapshot.json contains an example json file.
    local -r snapshot="$(kosli get snapshot "${KOSLI_ENVIRONMENT}" --output=json)"
    # ...one artifact at a time
    local -r snapshot_index=$(echo "${snapshot}" | jq -r '.index')
    local -r artifacts_length=$(echo "${snapshot}" | jq -r '.artifacts | length')
    for a in $(seq 0 $(( ${artifacts_length} - 1 )))
    do
        artifact="$(echo "${snapshot}" | jq -r '.artifacts[$a]')"
        annotation_type=$(echo "${artifact}" | jq -r ".annotation.type")
        if [ "${annotation_type}" != "exited" ] ; then
          artifact_name=$(echo "${artifact}" | jq -r ".name")
          # ...one flow at a time
          flows_length=$(echo "${artifact}" | jq -r '.flows | length')
          for f in $(seq 0 $(( ${flows_length} - 1 )))
          do
            flow="$(echo "${artifact}" | jq -r '.flows[$f]')"
            flow_name=$(echo "${flow}" |  jq -r '.flow_name')  # eg runner-ci
            if [ "${flow_name}" != "${KOSLI_FLOW}" ] ; then
              git_commit=$(echo "${flow}" | jq -r ".git_commit")
              fingerprint=$(echo "${flow}" | jq -r ".fingerprint")
              repo_name="${flow_name::-3}"  # eg runner
              attest_snyk_scan_to_one_kosli_trail "${repo_name}" "${git_commit}" "${artifact_name}" "${fingerprint}" "${snapshot_index}"
            fi
          done
       fi
    done
}

attest_snyk_scan_to_one_kosli_trail()
{
    # If an Artifact (eg runner) fails a live snyk scan...
    # I want
    #   - the runner Artifact in the next snapshot to become red.
    #   - to have a Trail showing _all_ the live-snyk-scans for a given Artifact over time.
    # I DONT want
    #   - all Artifacts in the snapshot to become red - eg because the live snyk scans for all the Artifacts are in the same Trail.
    #   - the live snyk-scan Trail compliance of the current runner Artifact to be tied to the live snyk-scan compliance of any previous runner Artifact.
    #   - to make an attestation to the original CI Trail where the Artifact was built.
    #
    # So name the live snyk-scan Trail based on the repo and the fingerprint.
    # Do attestation at the Artifact level, by fingerprint, to make
    # the live-snyk scan appear as a 2nd Flow for each Artifact in the Environment snapshots.

    local -r repo="${1}"              # eg runner
    local -r git_commit="${2}"        # eg 44e6c271b46a56acd07f3b426c6cbca393442bb4
    local -r artifact_name="${3}"     # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/runner:44e6c27
    local -r fingerprint="${4}"       # eg c6cd1a5b122d88aaeb41c1fdd015ad88c2bea95ae85f63eb5544fb707254847e
    local -r snapshot_index="${5}"    # eg 2843

    export KOSLI_TRAIL="${repo}-${fingerprint}"
    export KOSLI_FINGERPRINT="${fingerprint}"

    local -r snyk_policy_filename=.snyk
    local -r snyk_output_json_filename=snyk.json

    # All cyber-dojo microservice repos hold a .snyk policy file. This is an empty file when no
    # vulnerabilities are turned-off. Ensure we get the .snyk file for the given artifact's git commit.
    rm "${snyk_policy_filename}" || true
    rm "${snyk_output_json_filename}" || true
    curl "https://raw.githubusercontent.com/cyber-dojo/${repo}/${git_commit}/.snyk" > "${snyk_policy_filename}"

    set +e
    snyk container test "${artifact_name}@sha256:${fingerprint}" \
        -d \
        --policy-path="${snyk_policy_filename}" \
        --sarif \
        --sarif-file-output="${snyk_output_json_filename}" \
        --severity-threshold=medium
    set -e

    kosli attest artifact "${artifact_name}" \
      --name="${repo}" \
      --annotate=snapshot_url="https://app.kosli.com/${KOSLI_ORG}/environments/${KOSLI_ENVIRONMENT}/snapshots/${snapshot_index}?fingerprint=${fingerprint}"

    # There is a Policy requiring a snyk attestation called snyk-container-scan
    kosli attest snyk "${artifact_name}" \
      --name="${repo}.snyk-container-scan" \
      --attachments="${snyk_policy_filename}" \
      --scan-results="${snyk_output_json_filename}"
}

exit_non_zero_unless_installed kosli snyk jq
snyk_scan_live_artifacts_and_attest_to_kosli_trail
