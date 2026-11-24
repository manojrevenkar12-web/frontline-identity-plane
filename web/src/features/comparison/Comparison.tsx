import { NAMES, num } from "../../shared/format";
import { n, type Split } from "../../shared/data/report";
import t from "../../shared/ui/table.module.css";

const ROWS: [string, string, number][] = [
  ["Hours from the IdP's deactivation to every access path closed, p95", "leaver_h_after_idp_p95", 2],
  ["Person-hours with more access than the IdP gives", "over_idp_h", 0],
  ["Person-hours with more access than HR intends", "over_privileged_h", 0],
  ["Shift starts where someone could not do their job", "blocked_shift_starts", 0],
  ["Access tickets to plant admins", "tickets", 0],
  ["Admin hours to connect the customers", "admin_hours_onboarding", 1],
  ["AI-assistant actions the person was not allowed", "agent_overreach", 0],
  ["AI-assistant requests refused although allowed", "agent_refused_allowed", 0],
  ["Station records under someone else's name", "wrong_identity_actions", 0],
  ["Signatures under someone else's identity", "wrong_identity_signatures", 0],
  ["IdP changes the service refused and lost", "scim_changes_dropped", 0],
  ["Legitimate logins turned away", "legit_login_rejections", 0],
];

export function Comparison({ split }: { split: Split }) {
  return (
    <div className={t.wrap}>
      <table className={t.table}>
        <thead>
          <tr>
            <th scope="col">
              {split.seeds.length} sets of customers, {split.site.weeks} weeks each
            </th>
            {split.main.map((d) => (
              <th key={d} scope="col" className={d === "platform" ? t.us : undefined}>
                {NAMES[d] ?? d}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {ROWS.map(([label, key, dp]) => (
            <tr key={key}>
              <th scope="row">{label}</th>
              {split.main.map((d) => (
                <td key={d} className={d === "platform" ? t.us : undefined}>
                  {num(n(split.designs[d] as never, key), dp)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
