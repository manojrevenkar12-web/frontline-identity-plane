# 0003. The tenant comes from a credential

## Decision
SCIM: the bearer token names the tenant. SAML: the tenant's own issuer and key. OIDC: the flow the state names, and
the `iss` parameter must match it (RFC 9207). Agents: the token's audience. A tenant in a URL selects an endpoint and
never widens what a credential may see.

## Consequences
The in-house build that takes the tenant from the path hands one customer's users to another's IdP token, in every
attempt.
