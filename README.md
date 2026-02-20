A CI workflow to run snyk container tests on the Docker images running in cyber-dojo's 
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/events/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/events/) runtime environments.  

Reports newly found snyk vulnerabilities to a dedicated [Kosli Flow](https://app.kosli.com/cyber-dojo/flows/aws-snyk-scan/trails/).

Uses the `.snyk` policy file from the repo's git commit whose CI workflow
built the deployed image. This means `ignore` entries in the `.snyk` file 
_will_ be used and only new vulnerabilties (or vulnerabilities now past their 
`expires` date) will cause a non-compliance.

Run's daily at 09:00.
