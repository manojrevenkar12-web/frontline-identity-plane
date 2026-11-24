# Results

Generated from `reports/*.json` by `python -m fip.cli report`.

## Development customers: seeds 11, 12, 13

### Every design, every metric

| metric | status_quo | naive_build | platform | strict_scim | name_decides | no_hr_dates | no_live_check | no_down_scope | no_idle_lock | no_wrapping_defence |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| people | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 | 2,379.00 |
| over_privileged_h | 22,102.24 | 51,675.74 | 418.33 | 18,505.16 | 397,537.52 | 5,161.25 | 418.33 | 418.33 | 418.33 | 418.33 |
| over_idp_h | 20,245.06 | 47,447.20 | 15.38 | 18,130.60 | 397,204.34 | 34.89 | 15.38 | 15.38 | 15.38 | 15.38 |
| under_privileged_h | 4,159.74 | 14,338.05 | 245.97 | 14,338.05 | 14,673.24 | 245.97 | 245.97 | 245.97 | 245.97 | 245.97 |
| leavers | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 | 192.00 |
| leaver_h_after_idp_p95 | 0.57 | 815.18 | 0.17 | 533.64 | 0.17 | 0.57 | 0.17 | 0.17 | 0.17 | 0.17 |
| leaver_h_after_idp_mean | 0.14 | 217.04 | 0.04 | 64.91 | 0.04 | 0.14 | 0.04 | 0.04 | 0.04 | 0.04 |
| leaver_h_after_hr_p95 | 28.34 | 825.10 | 5.33 | 539.88 | 5.33 | 28.34 | 5.33 | 5.33 | 5.33 | 5.33 |
| shift_starts | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 | 67,702.00 |
| blocked_shift_starts | 123.00 | 408.00 | 7.00 | 408.00 | 436.00 | 7.00 | 7.00 | 7.00 | 7.00 | 7.00 |
| tickets | 111.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| admin_hours_onboarding | 77.47 | 24.30 | 18.90 | 18.90 | 16.35 | 18.90 | 18.90 | 18.90 | 18.90 | 18.90 |
| admin_hours_per_week | 3.70 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| lost_work_hours | 51.25 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| groups | 0.00 | 0.00 | 162.00 | 162.00 | 162.00 | 162.00 | 162.00 | 162.00 | 162.00 | 162.00 |
| groups_auto_mapped | 0.00 | 0.00 | 36.00 | 36.00 | 53.00 | 36.00 | 36.00 | 36.00 | 36.00 | 36.00 |
| wrong_auto_grants | 0.00 | 0.00 | 0.00 | 0.00 | 9.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| agent_requests | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 | 10,844.00 |
| agent_overreach | 2,857.00 | 3,603.00 | 2.00 | 2.00 | 39.00 | 28.00 | 2.00 | 2.00 | 2.00 | 2.00 |
| agent_overreach_idp | 2,856.00 | 3,575.00 | 0.00 | 0.00 | 37.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| agent_refused_allowed | 1,857.00 | 33.00 | 3.00 | 48.00 | 10.00 | 3.00 | 3.00 | 0.00 | 3.00 | 3.00 |
| leaver_agent_actions | 1,339.00 | 1,084.00 | 2.00 | 2.00 | 2.00 | 28.00 | 2.00 | 2.00 | 2.00 | 2.00 |
| station_actions | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 |
| wrong_identity_actions | 89.00 | 6,684.00 | 89.00 | 89.00 | 89.00 | 89.00 | 89.00 | 89.00 | 6,717.00 | 89.00 |
| signatures | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 | 29,160.00 |
| wrong_identity_signatures | 0.00 | 3,070.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| signatures_without_second_factor | 0.00 | 22,151.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| scim_changes_dropped | 0.00 | 179.00 | 0.00 | 179.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| attack_attempts | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 | 189.00 |
| attack_successes | 9.00 | 117.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 9.00 |
| cross_tenant_successes | 0.00 | 9.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| legit_logins | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 | 360.00 |
| legit_login_rejections | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

### Attacks

| Attack (attempts per design) | Today's provisioning | A first in-house build | The identity plane | strict_scim | name_decides | no_hr_dates | no_live_check | no_down_scope | no_idle_lock | no_wrapping_defence |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `agent.scope_escalation` (9) | **9 in** | **9 in** | held | held | held | held | held | held | held | held |
| `agent.token_at_other_tenant` (9) | held | held | held | held | held | held | held | held | held | held |
| `jwt.alg_none` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `jwt.expired` (9) | held | held | held | held | held | held | held | held | held | held |
| `jwt.hmac_with_public_key` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `jwt.other_audience` (9) | held | held | held | held | held | held | held | held | held | held |
| `oidc.code_injection` (9) | held | held | held | held | held | held | held | held | held | held |
| `oidc.login_csrf` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `oidc.mix_up` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.comment_truncation` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.dtd` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.expired` (9) | held | held | held | held | held | held | held | held | held | held |
| `saml.key_in_message` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.other_tenants_idp` (9) | held | held | held | held | held | held | held | held | held | held |
| `saml.replay` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.signature_wrapping` (9) | held | **9 in** | held | held | held | held | held | held | held | **9 in** |
| `saml.unsigned` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.unsolicited_login_csrf` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `saml.wrong_audience` (9) | held | held | held | held | held | held | held | held | held | held |
| `scim.other_tenant_by_path` (9) | held | **9 in** | held | held | held | held | held | held | held | held |
| `station.leaver_badge` (9) | held | held | held | held | held | held | held | held | held | held |

### Gates

| Gate | Value | Limit | |
|---|---:|---:|---|
| Attacks that got in | 0.000 | ≤ 0 | pass |
| Cross-tenant access | 0.000 | ≤ 0 | pass |
| Hours from IdP deactivation to the last access path closed, p95 | 0.170 | ≤ 1.0 | pass |
| Over-privileged person-hours, ratio to today | 0.019 | ≤ 0.25 | pass |
| Blocked shift starts, ratio to today | 0.057 | ≤ 0.25 | pass |
| Legitimate logins turned away, share | 0.000 | ≤ 0.005 | pass |
| Wrong grants applied from the model's mapping | 0.000 | ≤ 0 | pass |
| AI-assistant actions the IdP did not allow, ratio to today | 0.000 | ≤ 0.02 | pass |
| Signatures recorded under someone else's identity | 0.000 | ≤ 0 | pass |

