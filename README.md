A CI workflow to run snyk scans of the Docker images running in cyber-dojo's 
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/events/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/events/) runtime environments.  
Reports newly found snyk vulnerabilities to a dedicated [Kosli Flow](https://app.kosli.com/cyber-dojo/flows/).  
Run's weekly at 09:00 on Saturday and on git pushes to main.

When new vulnerabilities are found you can use the script/print_all_base_images.sh
script to help locate where, in the base image hierarchy, the vulnerabilities
have been found.
