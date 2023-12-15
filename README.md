A CI workflow to run snyk scans of the Docker images running in cyber-dojo's aws-beta and aws-prod 
runtime environments.  
Reports newly found snyk vulnerabilities to the appropriate [Kosli Flows](https://app.kosli.com/cyber-dojo/flows/).  
Run's weekly at 09:00 on Saturday.

When new vulnerabilities are found you can use the script/print_all_base_images.sh
script to help locate where, in the base image hierarchy, the vulnerabilities
have been found.
