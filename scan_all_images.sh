#!/usr/bin/env bash

set -Eeu

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

#To get info from the flows which do not have runtime environments
# kosli_fetch_all_flows()
# {
#     kosli list flows -o json > flows.json

#     flows_nr=($(jq -r '.[].name' flows.json))

#     rm "flows.json"
# }

# kosli_get_latest_artifact()
# {
#     kosli list artifacts -f ${flow} -o json > arts.json

#     fingerprint=($(jq -r '.[0].fingerprint' arts.json))
#     artifact=($(jq -r '.[0].filename' arts.json))
#     git=($(jq -r '.[0].git_commit' arts.json))
#     build=($(jq -r '.[0].build_url' arts.json))
#     current_compliance=($(jq -r '.[0].state' arts.json))

#     rm "arts.json"
    
# }

get_snyk_policy_file()
{
    curl https://raw.githubusercontent.com/cyber-dojo/$flow/main/.snyk  > .snyk

}

run_snyk_scan()
{
    get_snyk_policy_file

    set +e

    snyk container test $image \
            --json-file-output="$flow.json" \
            --policy-path=".snyk"
    
    new_compliance="$?"
    set -e

    rm ".snyk"
}

kosli_get_build()
{
    kosli get artifact "$flow@$fingerprint" -o json > artifact.json
    build=($(jq -r '.build_url' artifact.json))
    current_compliance=($(jq -r '.state' artifact.json))
    rm "artifact.json"
}


send_to_kosli()
{
    if [[ "$current_compliance" == "COMPLIANT" ]] && [[ "$new_compliance" == "1" ]]; then
        kosli report evidence artifact snyk "$artifact" \
                --build-url "$build" \
                --flow "$flow" \
                --name snyk-scan \
                --scan-results "$flow.json" \
                --fingerprint "$fingerprint" \
                --dry-run
    fi
}

scan_images_in_prod()
{
    for i in ${!flows[@]}; do 
        flow=${flows[$i]}
        name="cyberdojo/${flow}"
        tag=${gits[$i]:0:7}
        fingerprint=${fingerprints[$i]}
        artifact=$name:$tag
        image=$name@sha256:$fingerprint

        #Skip nginx for the time being
        if [[ ! $flow == "nginx" ]]; then

            run_snyk_scan
            kosli_get_build
            send_to_kosli

            rm "$flow.json"
        fi

    done

}

# scan_non_runtime_images()
# {
#     kosli_fetch_all_flows

#     for i in ${!flows_nr[@]}; do
#         flow=${flows_nr[$i]}
#         if [[ ! "${flows[*]}" =~ "$flow" ]]; then

#             kosli_get_latest_artifact
            
#             if [[ ! "$artifact" == "null" ]] && [[ ! "$flow" == "repler" ]]; then
#                 echo $flow
#                 run_snyk_scan
#                 send_to_kosli
#                 rm "$flow.json"
#             fi
#         fi

#     done
# }


kosli_fetch_snapshot
scan_images_in_prod
