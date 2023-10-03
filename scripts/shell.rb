# frozen_string_literal: true

require_relative 'utf8_clean'
require 'open3'


def shell(*commands)
  stdout, stderr, r = Open3.capture3("sh -c #{quoted(commands.join(' && '))}")
  stdout = utf8_clean(stdout)
  stderr = utf8_clean(stderr)
  exit_status = r.exitstatus
  unless success?(exit_status)
    diagnostic = {
      stdout: stdout,
      stderr: stderr,
      exit_status: exit_status
    }
    raise diagnostic.to_json
  end
  stdout
end


def success?(status)
  status.zero?
end

def quoted(arg)
  "\"#{arg}\""
end

