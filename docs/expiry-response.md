Snyk expiry alert response guide
=================================

When you receive a Slack alert from the check-expiry-and-notify workflow,
check the GitHub step summary (linked in the message) to see which vulns
are approaching expiry and which mechanism applies.


Mechanism: rego_limit
----------------------
The vuln has been open long enough to approach the policy age limit
defined in the rego params for that environment.

Example step summary entry:

  | Level | Days remaining | Mechanism  | Vuln ID |
  |-------|----------------|------------|---------|
  | high  | 1              | rego_limit | [SNYK-GOLANG-GITHUBCOMMOBYSPDYSTREAMSPDY-16304822](https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMMOBYSPDYSTREAMSPDY-16304822) |

  There is no .snyk ignore entry. The vuln has been open for 1 day
  against a 2-day limit for high severity in aws-beta (2 - 1 = 1
  day remaining).

The rego expiry days cannot be extended. The countdown is based on
when the vuln first appeared in the environment for the relevant repo,
not on any configurable date.

Options:
- Fix the underlying dependency (removes the vuln entirely)
- Add an explicit .snyk ignore entry (shifts it to dot_snyk_expiry
  and buys more time)

Relevant files:
  [rego.params.aws-beta.json](../rego.params.aws-beta.json)
  [rego.params.aws-prod.json](../rego.params.aws-prod.json)


Mechanism: dot_snyk_expiry
--------------------------
The .snyk ignore entry for this vuln is about to expire.

Example step summary entry:

  | Level | Days remaining | Mechanism       | Vuln ID |
  |-------|----------------|-----------------|---------|
  | high  | 3              | dot_snyk_expiry | [SNYK-ALPINE322-ZLIB-16078399](https://security.snyk.io/vuln/SNYK-ALPINE322-ZLIB-16078399) |

  The .snyk file contains an ignore entry for this vuln whose expiry
  date is 3 days away.

Options:
- Fix the underlying dependency (removes the vuln entirely)
- Extend the expiry date in .snyk (if fixing is not yet feasible; at most 30 days,
  as set by max_ignore_expiry_days in the rego params files above)

Relevant file: .snyk (in the relevant repo)
