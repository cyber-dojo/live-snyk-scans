require_relative 'shell'
require 'json'

json_filename=ARGV[0]
snapshot = JSON.parse(IO.read(json_filename))

puts(JSON.pretty_generate(snapshot))