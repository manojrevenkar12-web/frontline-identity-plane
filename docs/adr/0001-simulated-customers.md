# 0001. Simulated customers, real protocol code

## Context
Access control is judged by what it does over weeks of joiners, leavers and transfers, through IdPs that each push
SCIM their own way, and by what attackers can do with crafted messages. No real customer data can be used.

## Decision
Customers, people, HR changes, IdP behaviour and attackers are simulated with a hidden truth (who should be able to do
what, at every moment). The platform sees only what a product sees: SCIM calls, signed assertions, ID tokens, badge
taps, agent requests. The protocol code is real: XML signatures, JWTs and SCIM payloads are built and checked by the
same code the service runs, and every attack is a real message.

## Consequences
The access numbers are simulated and labelled so; the attack results are not a model of the code, they are the code.
