Snyk expiry alert response guide
=================================

When you receive a Slack alert from the check-expiry-and-notify workflow,
check the GitHub step summary (linked in the message) to see which vulns
are approaching expiry and which mechanism applies.


Mechanism: explicit_expiry
--------------------------
The .snyk ignore entry for this vuln is about to expire.

Options:
- Fix the underlying dependency (removes the vuln entirely)
- Extend the expiry date in .snyk (if fixing is not yet feasible)

Relevant file: .snyk


Mechanism: rego_limit
----------------------
The vuln has been open long enough to approach the policy age limit
defined in the rego params for that environment.

Options:
- Fix the underlying dependency (removes the vuln entirely)
- Add an explicit .snyk ignore entry (shifts it to explicit_expiry
  and buys more time)

Relevant files:
  rego.params.aws-beta.json
  rego.params.aws-prod.json
