# Repeatable tasks

## Add an attack to the catalogue
1. Write it in `src/fip/sim/attacks.py` as a real message (a SAML response, an OIDC callback, a JWT, a SCIM call,
   a badge tap) and `record("family.name", fn)`; `fn` returns True only if the design was fooled.
2. Add a unit test in the protocol's test file that the platform refuses it and that it works with the one check off.
3. `python -m fip.cli run dev && python -m fip.cli report`.

## Support a new identity provider's quirks
1. Describe how it pushes in `config/world.yml: idp` (cycle, failure rate, capitalised ops, booleans as strings,
   PUT or PATCH for users).
2. If it sends something new, accept it in `src/fip/protocols/scim.py` behind `lenient_ops` and add a test in
   `tests/test_scim.py` with the exact payload.
3. Watch "IdP changes the service refused and lost" in the README table: it must stay 0.

## Onboard a customer's groups
1. The model proposes; `src/fip/onboarding.py` decides. Thresholds in `config/platform.yml: onboarding`.
2. Never lower `member_agreement` without the ablation row "applies the model's mapping without checking the members"
   showing 0 wrong grants.

## Change a safeguard
1. Change it in `config/platform.yml`.
2. Add a variant in `config/designs.yml` with `set:` and list it under `ablations`.
3. Run dev, gate, report.

## Run the service
`python -m fip.cli serve` (a demo tenant; the SCIM token is printed), then point an IdP's SCIM client at
`/scim/v2`, sign in at `/t/demo/saml/acs` or `/t/demo/oidc/callback`, exchange tokens at `/oauth/token` and ask
`/t/demo/authorize` before every agent action.

## Run the held-out customers
Only once, after the gates are set: `python -m fip.cli run heldout && python -m fip.cli report`.
