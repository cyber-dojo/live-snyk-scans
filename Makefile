
demo:
	@cat ${PWD}/tests/get-snapshot/aws-prod.json | python3 ${PWD}/bin/artifacts.py

run_tests:
	@${PWD}/tests/run_tests.sh

artifacts:
	@${PWD}/bin/get_snapshot_json.sh | python3 ${PWD}/bin/artifacts.py



