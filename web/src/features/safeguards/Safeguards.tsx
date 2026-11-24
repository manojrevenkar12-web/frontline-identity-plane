import { num } from "../../shared/format";
import { n, type Split } from "../../shared/data/report";
import t from "../../shared/ui/table.module.css";

export function Safeguards({ split }: { split: Split }) {
  return (
    <div className={t.wrap}>
      <table className={t.table}>
        <thead>
          <tr>
            <th scope="col">One safeguard changed at a time</th>
            <th scope="col">Attacks in</th>
            <th scope="col">IdP changes lost</th>
            <th scope="col">Person-hours over HR's intent</th>
            <th scope="col">Wrong grants from the mapping</th>
            <th scope="col">Station records under another name</th>
          </tr>
        </thead>
        <tbody>
          {["platform", ...split.ablations].map((k) => {
            const d = split.designs[k];
            if (!d) return null;
            return (
              <tr key={k} className={k === "platform" ? t.us : undefined}>
                <th scope="row">{k === "platform" ? "The identity plane" : split.labels[k]}</th>
                <td>{num(n(d, "attack_successes"))}</td>
                <td>{num(n(d, "scim_changes_dropped"))}</td>
                <td>{num(n(d, "over_privileged_h"))}</td>
                <td>{num(n(d, "wrong_auto_grants"))}</td>
                <td>{num(n(d, "wrong_identity_actions"))}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Onboarding({ split }: { split: Split }) {
  const p = split.designs.platform;
  const nb = split.designs.naive_build;
  const sq = split.designs.status_quo;
  if (!p || !nb || !sq) return null;
  return (
    <p>
      A model read {num(n(p, "groups"))} IdP group names. Code accepted {num(n(p, "groups_auto_mapped"))} of its proposals as rules ({num(n(p, "wrong_auto_grants"))} wrong) and sent the rest
      to a person: {num(n(p, "admin_hours_onboarding"), 1)} admin hours, against {num(n(nb, "admin_hours_onboarding"), 1)} mapping every group by hand and {num(n(sq, "admin_hours_onboarding"), 1)} setting
      roles person by person.
    </p>
  );
}
