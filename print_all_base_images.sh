#!/usr/bin/env bash
set -Eeu

# Script to print hierarchy of base image names for all cyber-dojo services.
# Useful when tracking down the origin of new snyk vulnerabilities.
# Example output is in docs/base_images.json

repo_root() {   git rev-parse --show-toplevel; }
source "$(repo_root)/scripts/exit_non_zero_unless_installed.sh"
exit_non_zero_unless_installed kosli docker

export KOSLI_API_TOKEN=4e5899bea7af0c86dde4eb48fe54ab9debcccd76  # fake
export KOSLI_ORG=cyber-dojo
export KOSLI_HOST="${1:-https://app.kosli.com}"
export KOSLI_ENVIRONMENT="${2:-aws-prod}"

snapshot_json_filename=snapshot.json

kosli get snapshot "${KOSLI_ENVIRONMENT}" --output=json > "$(repo_root)/tmp/${snapshot_json_filename}"

docker run \
  --rm \
  -it \
  --volume "$(repo_root)/tmp/${snapshot_json_filename}:/tmp/${snapshot_json_filename}:ro" \
  --volume "$(repo_root)/scripts:/scripts:ro" \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  cyberdojo/docker-base:4e5899b \
    ruby /scripts/print_all_base_images.rb "/tmp/${snapshot_json_filename}"
