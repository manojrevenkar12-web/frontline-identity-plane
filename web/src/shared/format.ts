export const num = (x: number | null | undefined, d = 0): string =>
  x === null || x === undefined ? "–" : x.toLocaleString("en-GB", { minimumFractionDigits: d, maximumFractionDigits: d });

export const NAMES: Record<string, string> = {
  status_quo: "Today's provisioning",
  naive_build: "A first in-house build",
  platform: "The identity plane",
};

export const FAMILIES: [string, string][] = [
  ["saml", "SAML sign-in"],
  ["oidc", "OpenID Connect sign-in"],
  ["jwt", "Tokens an agent presents"],
  ["scim", "Provisioning (SCIM)"],
  ["agent", "AI agents acting for a person"],
  ["station", "Shared stations"],
];

export const ATTACKS: Record<string, string> = {
  "saml.unsigned": "An unsigned assertion",
  "saml.signature_wrapping": "A forged assertion wrapped around a signed one",
  "saml.comment_truncation": "A comment that cuts the NameID short",
  "saml.replay": "A captured response posted again",
  "saml.wrong_audience": "An assertion meant for another service",
  "saml.expired": "An expired assertion",
  "saml.unsolicited_login_csrf": "A response nobody asked for (login CSRF)",
  "saml.other_tenants_idp": "Another tenant's IdP vouching for this tenant's admin",
  "saml.key_in_message": "A key shipped inside the message",
  "saml.dtd": "A DTD in the XML",
  "oidc.login_csrf": "A callback with no login in progress",
  "oidc.code_injection": "A stolen code in someone else's flow",
  "oidc.mix_up": "A code from another tenant's IdP",
  "jwt.alg_none": "A token with alg none",
  "jwt.hmac_with_public_key": "A token signed with the public key as an HMAC secret",
  "jwt.expired": "A day-old token",
  "jwt.other_audience": "A token issued to another app",
  "scim.other_tenant_by_path": "Another tenant's SCIM token, this tenant's URL",
  "agent.scope_escalation": "An operator asking the assistant to edit an app",
  "agent.token_at_other_tenant": "An agent token used at another tenant",
  "station.leaver_badge": "A leaver's badge at a station",
};
