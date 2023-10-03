#!/usr/bin/env bash
set -Eeu

root_dir() {   git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

export KOSLI_API_TOKEN=4e5899bea7af0c86dde4eb48fe54ab9debcccd76  # fake
export KOSLI_ORG=cyber-dojo
export KOSLI_HOST="${1:-https://app.kosli.com}"
export CYBER_DOJO_ENVIRONMENT="${2:-aws-prod}"

exit_non_zero_unless_installed kosli docker

snapshot_json_filename=snapshot.json

kosli get snapshot "${CYBER_DOJO_ENVIRONMENT}" --output=json > "$(root_dir)/tmp/${snapshot_json_filename}"

docker run \
  --rm \
  -it \
  --volume "$(root_dir)/tmp/${snapshot_json_filename}:/tmp/${snapshot_json_filename}:ro" \
  --volume "$(root_dir)/scripts:/scripts:ro" \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  cyberdojo/docker-base:4e5899b \
    ruby /scripts/print_all_base_images.rb "/tmp/${snapshot_json_filename}"
