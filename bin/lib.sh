
exit_non_zero_unless_installed()
{
  for dependent in "$@"
  do
    if ! installed "${dependent}" ; then
      stderr "${dependent} is not installed"
      exit 42
    fi
  done
}

installed()
{
  local -r dependent="${1}"
  if hash "${dependent}" 2> /dev/null; then
    true
  else
    false
  fi
}

exit_non_zero_unless_file_exists()
{
  local -r filename="${1}"
  if [ ! -f "${filename}" ]; then
    stderr "${filename} does not exist"
    exit 42
  fi
}

stderr()
{
  >&2 echo "ERROR: $@"
}

assertEqual()
{
  local -r lhs="${1}"
  local -r rhs="${2}"
  if [ "${lhs}" != "${rhs}" ]; then
    stderr assertEquals lhs rhs Failed
    stderr "lhs=${lhs}"
    stderr "rhs=${rhs}"
    exit 42
  fi
}
