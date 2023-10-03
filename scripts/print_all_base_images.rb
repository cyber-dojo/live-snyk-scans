require_relative 'shell'
require 'json'

json_filename=ARGV[0]
snapshot = JSON.parse(IO.read(json_filename))

# snapshot = [
#   {
#     "artifact": "274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27"
#   }
# ]

base_images = {}

snapshot.each do |image|
   artifact = image["artifact"]              # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27
   name = artifact.split('/')[-1]            # eg differ:44e6c27
   if name.start_with?("nginx")  # TODO
     next
   end
   public_image_name = "cyberdojo/#{name}"   # eg cyberdojo/differ:44e6c27
   shell("docker pull #{public_image_name}")
   stdout = shell("docker run --rm --entrypoint='' #{public_image_name} printenv BASE_IMAGE")
   base_images[public_image_name] = stdout.strip
   puts("#{public_image_name} => #{stdout.strip}")
end

# TODO: recurse though base images,
#    eg sinatra-base => rack-base
#       rack-base => ruby-base
#       docker-base => docker:24.0.6-alpine3.18
puts(JSON.pretty_generate(base_images))
