#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

test_SUCCESS_json_artifacts_written_to_stdout() { :; }

xtest___SUCCESS_no_artifacts()
{
  local -r filename="0.json"
  get_artifacts "${filename}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/expected/${filename}")"
  assert_stderr_equals ""
}

test___SUCCESS_aws_prod()
{
  local -r filename="aws-prod.json"
  get_artifacts "${filename}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/expected/${filename}")"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_FAILURE_with_diagnostic_on_stderr() { :; }

test___FAILURE_unknown_ci_system()
{
  local -r filename="unknown-ci-system"
  get_artifacts "${filename}.json"
  assert_status_not_equals 0
  assert_stdout_equals ""
  assert_stderr_equals "$(cat "${my_dir}/expected/${filename}.txt")"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

get_artifacts()
{
  local -r filename="${1}"
  cat ${my_dir}/get-snapshot/${filename} | python3 ${my_dir}/../bin/artifacts.py >${stdoutF} 2>${stderrF}
  status=$?
  echo ${status} >${statusF}
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2

