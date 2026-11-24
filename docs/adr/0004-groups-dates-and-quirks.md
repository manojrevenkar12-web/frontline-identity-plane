# 0004. Sync groups, honour dates, accept the IdPs' dialects

## Decision
- Groups are synced and turned into roles by rules; nothing about access is set by hand unless an admin adds it.
- The start and end dates the IdP sends (hire date, contract end) bound access even when the IdP's deactivation
  arrives hours later.
- SCIM accepts `"op": "Replace"`, booleans as strings and member removal by filter, because Entra and ADFS-era
  connectors send them; anything else gets a 400 the IdP can act on.

## Evidence (development customers)
A spec-strict parser lost 179 IdP changes, among them deactivations, and left 18,505 person-hours of access HR did
not intend; ignoring dates left 5,161. Users-only provisioning with roles by ticket left 22,102 and 123 blocked shift
starts.
