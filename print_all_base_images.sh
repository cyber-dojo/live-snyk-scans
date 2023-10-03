#!/usr/bin/env bash
set -Eeu

root_dir() {   git rev-parse --show-toplevel; }
source "$(root_dir)/scripts/exit_non_zero_unless_installed.sh"

exit_non_zero_unless_installed docker

docker run \
  --rm \
  -it \
  --volume "$(root_dir)/scripts/print_all_base_images.rb":/tmp/print_all_base_images.rb \
  cyberdojo/docker-base:4e5899b \
    ruby /tmp/print_all_base_images.rb