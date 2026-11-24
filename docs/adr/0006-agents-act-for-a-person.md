# 0006. Agents act for a person, never with a standing key

## Decision
An agent exchanges the person's ID token and its own client credentials for a token (RFC 8693) that names both, is
limited to scopes the agent is allowed and the person has, is bound to one tenant, lives ten minutes, and is
re-checked against the person's current access on every use.

## Evidence
A standing builder key let operators' requests edit apps and let leavers' scheduled jobs run for weeks: 2,857
actions the person was not allowed. The identity plane allowed 2, both inside the IdP's own lag.
