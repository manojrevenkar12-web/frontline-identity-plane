import { motion, useReducedMotion } from "framer-motion";
import { ATTACKS, FAMILIES, NAMES, num } from "../../shared/format";
import type { Split } from "../../shared/data/report";
import styles from "./attacks.module.css";

export function AttackBoard({ split }: { split: Split }) {
  const reduce = useReducedMotion();
  const kinds = Object.keys(split.designs.platform?.attacks ?? {});
  const designs = split.main;
  const total = (d: string) => Object.values(split.designs[d]?.attacks ?? {}).reduce((a, x) => a + x.successes, 0);
  const attempts = Object.values(split.designs.platform?.attacks ?? {}).reduce((a, x) => a + x.attempts, 0);
  return (
    <div className={styles.board}>
      <div className={styles.head} role="row">
        <span />
        {designs.map((d) => (
          <span key={d} className={`${styles.col} ${d === "platform" ? styles.us : ""}`}>
            <span className={styles.colName}>{NAMES[d] ?? d}</span>
            <span className={total(d) ? styles.countBad : styles.countOk}>
              {num(total(d))} of {num(attempts)} got in
            </span>
          </span>
        ))}
      </div>
      {FAMILIES.map(([fam, label]) => {
        const rows = kinds.filter((k) => k.startsWith(`${fam}.`));
        if (!rows.length) return null;
        return (
          <section key={fam} className={styles.family} aria-label={label}>
            <h3 className={styles.famName}>{label}</h3>
            {rows.map((k, i) => (
              <div key={k} className={styles.row}>
                <span className={styles.attack}>
                  {ATTACKS[k] ?? k}
                  <code>{k}</code>
                </span>
                {designs.map((d, j) => {
                  const r = split.designs[d]?.attacks[k] ?? { attempts: 0, successes: 0 };
                  const bad = r.successes > 0;
                  return (
                    <motion.span
                      key={d}
                      className={`${styles.cell} ${bad ? styles.breach : styles.held} ${d === "platform" ? styles.us : ""}`}
                      initial={reduce ? false : { opacity: 0, scale: 0.6 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: reduce ? 0 : j * 0.18 + i * 0.015, duration: 0.2 }}
                      aria-label={`${NAMES[d] ?? d}: ${bad ? `${r.successes} of ${r.attempts} got in` : "held"}`}
                    >
                      {bad ? `${r.successes}/${r.attempts}` : "held"}
                    </motion.span>
                  );
                })}
              </div>
            ))}
          </section>
        );
      })}
    </div>
  );
}
