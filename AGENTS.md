# Working on this repository

## Fast feedback

- `pytest -q` runs in a few seconds: tiny simulated customers, real SAML, OIDC, JWT and SCIM messages.
- `ruff check . && ruff format --check . && mypy src` for lint and types.
- `python -m fip.cli run dev && python -m fip.cli gate dev && python -m fip.cli report` runs every design on the
  development customers and regenerates REPORT.md, the README block and the console data.
- `cd web && npm test && npm run typecheck && npm run lint` for the console.

## Invariants

Each one has a test or a CI step.

- **The truth stays in the world.** Designs see what a product sees: SCIM calls from the customer's IdP, signed
  assertions and ID tokens, badge taps, agent requests. Who should have access at each moment (HR's intent), the
  hidden quality of the group-naming model and the attackers' plans live in `world/` and are read only by `sim/`.
  Test: `tests/test_boundaries.py`.
- **The world does not read the platform's settings or code.** `world/` loads `world.yml`; it talks to the platform
  only through SCIM calls and protocol messages. `authz/`, `protocols/`, `service/` and `onboarding.py` never import
  `world`, `sim` or `lab`. Test: `tests/test_boundaries.py`.
- **Same luck for every design.** Every coin is keyed by (seed, purpose, id) in `rng.py`. Test:
  `tests/test_world_and_run.py`.
- **The tenant comes from a credential, never from a URL.** SCIM: the bearer token. SAML: the issuer and the
  tenant's key. OIDC: the flow the state names. Agents: the token's audience. Tests: `tests/test_scim.py`,
  `tests/test_service.py`, `tests/test_authz.py`.
- **Read what was verified.** The SAML consumer reads the assertion the signature covers and nothing else; a NameID is
  read whole; algorithms are fixed per issuer; the key comes from configuration. Tests: `tests/test_saml.py`,
  `tests/test_oidc_jose.py`.
- **The model reads and code decides.** The onboarding model only proposes group mappings. Privileged roles always go
  to a person, and a name never decides alone: the group's members must fit. Test: `tests/test_onboarding.py`.
- **An agent never gets more than the person, and never outlives their access.** Token exchange down-scopes; every
  use re-checks the person. Test: `tests/test_authz.py`.
- **Settings live in `config/`**, by owner: the world in `world.yml`; the platform in `platform.yml`; designs in
  `designs.yml`; seeds in `seeds.yml`; thresholds in `gates.yml`.
- **Reports are generated, never edited.** CI regenerates REPORT.md, the README block and
  `web/public/data/report.json` and fails on a diff.

## Held-out customers

- `config/seeds.yml` lists them; they run in the held-out world (`world.yml: heldout`).
- `python -m fip.cli run heldout` writes `reports/heldout.lock` before it runs; if the lock exists it exits with code 3.
  CI checks the lock was committed exactly once.
- Gates were set from the development customers before the held-out run. Never loosen a gate after it.

## Data

Everything about the customers is simulated. Company names are invented; town names are real places.
