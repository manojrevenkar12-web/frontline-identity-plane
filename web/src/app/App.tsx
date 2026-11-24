import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useState } from "react";
import { AttackBoard } from "../features/attacks/AttackBoard";
import { Comparison } from "../features/comparison/Comparison";
import { Gates } from "../features/gates/Gates";
import { Onboarding, Safeguards } from "../features/safeguards/Safeguards";
import { type Report, type Split, useReport } from "../shared/data/report";
import { num } from "../shared/format";
import { Section } from "../shared/ui/Section";
import { EmptyState, ErrorState, Skeleton } from "../shared/ui/States";
import styles from "./App.module.css";

export function App() {
  const { load, retry } = useReport();
  return (
    <main className={styles.page}>
      <header className={styles.masthead}>
        <h1>Who can sign in, as whom, and to which plant</h1>
        <p>
          SAML, OpenID Connect and SCIM for manufacturers whose identity providers each do it their own way, identities for AI agents acting for a person, and shared stations on the
          shop floor. Every number below comes from simulated customers with a known truth; every attack is a real message through the code.
        </p>
      </header>
      {load.state === "loading" && <Skeleton lines={7} label="Loading the report" />}
      {load.state === "error" && <ErrorState message={load.message} onRetry={retry} />}
      {load.state === "ready" && <Console report={load.report} />}
    </main>
  );
}

function Console({ report }: { report: Report }) {
  const [which, setWhich] = useState<"dev" | "heldout">("dev");
  const reduce = useReducedMotion();
  const split = which === "heldout" && report.heldout ? report.heldout : report.dev;
  return (
    <>
      <div className={styles.tabs} role="tablist" aria-label="Which customers">
        <button type="button" role="tab" aria-selected={which === "dev"} onClick={() => setWhich("dev")}>
          Development customers
        </button>
        <button type="button" role="tab" aria-selected={which === "heldout"} onClick={() => setWhich("heldout")} disabled={!report.heldout}>
          Held-out customers, run once
        </button>
        {!report.heldout && <span className={styles.note}>The held-out customers have not been run yet.</span>}
      </div>
      <AnimatePresence mode="wait">
        <motion.div key={which} initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} exit={reduce ? undefined : { opacity: 0 }} transition={{ duration: 0.15 }}>
          <SplitView split={split} />
        </motion.div>
      </AnimatePresence>
      <footer className={styles.footer}>
        <p>Customers, people and attacks are simulated. The protocol code is real: XML signatures, JWTs and SCIM payloads are built and checked with the same code the service runs.</p>
      </footer>
    </>
  );
}

function SplitView({ split }: { split: Split }) {
  const s = split.site;
  if (!split.designs.platform) {
    return <EmptyState title="This report has no results for the identity plane">Run python -m fip.cli run dev and python -m fip.cli report.</EmptyState>;
  }
  return (
    <>
      <p className={styles.scope}>
        {num(s.tenants)} manufacturers, {num(s.plants)} plants, {num(s.people)} people and {num(s.hr_changes)} HR changes arriving through {s.idps.join(", ")}.
      </p>
      <Section id="attacks" title="Known attacks, one message each" lead="Each cell is a crafted SAML response, OIDC callback, token, SCIM call or badge tap sent through that design's code.">
        <AttackBoard split={split} />
      </Section>
      <Section id="access" title="Access over the weeks" lead="Joiners, leavers, transfers and promotions, as HR intends them, as the IdP pushes them, and as each design lets people act.">
        <Comparison split={split} />
      </Section>
      <Section id="safeguards" title="What each safeguard is worth">
        <Onboarding split={split} />
        <Safeguards split={split} />
      </Section>
      <Section id="gates" title="Release gates">
        <Gates split={split} />
      </Section>
    </>
  );
}
