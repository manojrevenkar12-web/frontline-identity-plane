# 0005. The model proposes group mappings; code decides

## Decision
A model reads IdP group names and proposes (plant, role) with a confidence. Code applies a proposal only if the role
is not privileged (approver, admin), the confidence is at least 0.8, and at least 95% of the group's members work at
that plant in a department that fits the role. Everything else goes to a person.

## Evidence
At 80% agreement a single-plant customer's "All-Staff" group, mostly operators, became an operators group. At 95%
no wrong rule was applied; without the member check, 9 were, giving 397,538 person-hours of unintended access.
