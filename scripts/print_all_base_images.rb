require_relative 'shell'
require 'json'
require 'set'

json_filename=ARGV[0]
$snapshot = JSON.parse(IO.read(json_filename))
# $snapshot = [{ "artifact" => "274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27" }]

def dot
  print('.')
  $stdout.flush
end

def top_level_image_names()
  names = []
  $snapshot["artifacts"].each do |artifact|
    artifact_name = artifact["name"]           # eg 274425519734.dkr.ecr.eu-central-1.amazonaws.com/differ:44e6c27
    tagged_name = artifact_name.split('/')[-1] # eg differ:44e6c27
    names.append("cyberdojo/#{tagged_name}")   # eg cyberdojo/differ:44e6c27
  end
  names
end

def base_image(public_image_name)
   dot
   shell("docker pull #{public_image_name}")
   stdout = shell("docker run --rm --entrypoint='' #{public_image_name} printenv BASE_IMAGE || true")
   # This will print something like
   #    cyberdojo/sinatra-base:6b753be
   # If you want the full commit of this base image, you can then do
   #    docker run --rm --entrypoint="" cyberdojo/sinatra-base:6b753be printenv COMMIT_SHA
   #    6b753bea38aea5b30ab40f7c99580f5137a2158d
   # It is conceivable that at some point Kosli will want the evidence for a base-image
   # to be part of the evidence for the derived image.
   # This full-sha would be the name of the Kosli trail that built this sinatra-base image.
   stdout.strip
end

def add_base_images(base_images, image_names)
  added = Set.new
  image_names.each do |image_name|
    if !base_images.has_key?(image_name)
       base = base_image(image_name)
       if base != ""
         base_images[image_name] = base
         added << base
       end
    end
  end
  added
end

base_images = {}
image_names = top_level_image_names
loop do
  image_names = add_base_images(base_images, image_names)
  if image_names.size() == 0
    break
  end
end

puts
puts(JSON.pretty_generate(base_images))
