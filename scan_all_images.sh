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
    kosli get artifact "$FLOW@$FINGERPRINT" -o json > build.json
    build=($(jq -r '.build_url' build.json))
    rm "build.json"
    echo $build
}

run_snyk_scan()
{
    snyk container test ${NAME}:${TAG} \
            --json-file-output="$FLOW.json"

    return 0
}

send_to_kosli()
{
    kosli report evidence artifact snyk "$ARTIFACT" \
            --build-url "$BUILD" \
            --flow "$FLOW" \
            --name snyk-scan \
            --scan-results "$FLOW.json" \
            --fingerprint "$FINGERPRINT" \
            #--dry-run
}

kosli_fetch_snapshot

for i in ${!flows[@]}; do 
    FLOW=${flows[$i]}
    NAME="cyberdojo/${FLOW}"
    TAG=${gits[$i]:0:7}
    FINGERPRINT=${fingerprints[$i]}
    ARTIFACT=${artifacts[$i]}

    BUILD=$(kosli_get_build)

    #Only run for the creator service right now
    if [ $FLOW == "creator" ]; then

        run_snyk_scan
        send_to_kosli
        rm "$FLOW.json"

    fi
done

            