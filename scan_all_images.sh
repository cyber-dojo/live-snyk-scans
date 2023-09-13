#!/usr/bin/env bash

# Currently we are not permanently saving any json files - either the snapshot/artifact from Kosli or the 
# snyk jsons. Not sure if we want to have these saved somewhere.

export KOSLI_ORG=cyber-dojo

kosli_fetch_snapshot()
{
    kosli get snapshot aws-prod -o json > snapshot.json

    flows=($(jq -r '.[].flow' snapshot.json))
    gits=($(jq -r '.[].git_commit' snapshot.json))
    fingerprints=($(jq -r '.[].fingerprint' snapshot.json))
    artifacts=($(jq -r '.[].artifact' snapshot.json))

    rm "snapshot.json"
}

kosli_get_build()
{
    kosli get artifact "$flow@$fingerprint" -o json > artifact.json
    build=($(jq -r '.build_url' artifact.json))
    current_compliance=($(jq -r '.state' artifact.json))
    rm "artifact.json"
    
}

run_snyk_scan()
{
    snyk container test ${name}:${tag} \
            --json-file-output="$flow.json"

    new_compliance="$?"
}

send_to_kosli()
{
    kosli report evidence artifact snyk "$artifact" \
            --build-url "$build" \
            --flow "$flow" \
            --name snyk-scan \
            --scan-results "$flow.json" \
            --fingerprint "$fingerprint" \
}

kosli_fetch_snapshot

for i in ${!flows[@]}; do 
    flow=${flows[$i]}
    name="cyberdojo/${flow}"
    tag=${gits[$i]:0:7}
    fingerprint=${fingerprints[$i]}
    artifact=${artifacts[$i]}

    kosli_get_build


    #Only run for the creator service right now
    if [ $flow == "creator" ]; then

        run_snyk_scan

        if [ "$current_compliance" == "COMPLIANT" ] && [ "$new_compliance" == "1" ]; then
            send_to_kosli
        fi

        rm "$flow.json"

    fi

done

            