import { useCallback, useEffect, useState } from "react";

export type AttackCount = { attempts: number; successes: number };
export type Metrics = Record<string, number> & { attacks?: never };
export interface Design extends Record<string, unknown> {
  attacks: Record<string, AttackCount>;
}

export interface Gate {
  gate: string;
  value: number;
  limit: number;
  kind: "max" | "min";
  pass: boolean;
}

export interface Split {
  split: string;
  seeds: number[];
  designs: Record<string, Design>;
  labels: Record<string, string>;
  main: string[];
  ablations: string[];
  site: { tenants: number; plants: number; people: number; weeks: number; hr_changes: number; idps: string[] };
  gates: { platform: Gate[]; platform_pass: boolean };
}

export interface Report {
  dev: Split;
  heldout: Split | null;
}

export type Load = { state: "loading" } | { state: "error"; message: string } | { state: "ready"; report: Report };

export function isReport(x: unknown): x is Report {
  if (typeof x !== "object" || x === null || !("dev" in x)) return false;
  const dev = (x as { dev: unknown }).dev;
  return typeof dev === "object" && dev !== null && "designs" in dev && "gates" in dev;
}

export const n = (d: Design, k: string): number => (typeof d[k] === "number" ? (d[k] as number) : 0);

export function useReport(url = "data/report.json"): { load: Load; retry: () => void } {
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => setAttempt((a) => a + 1), []);
  useEffect(() => {
    let live = true;
    setLoad({ state: "loading" });
    fetch(url)
      .then((r) => {
        if (!r.ok) throw new Error(`The report did not load (HTTP ${r.status}). Run python -m fip.cli report to generate it.`);
        return r.json();
      })
      .then((j: unknown) => {
        if (!live) return;
        if (!isReport(j)) throw new Error("The report file is not in the expected shape. Regenerate it with python -m fip.cli report.");
        setLoad({ state: "ready", report: j });
      })
      .catch((e: Error) => live && setLoad({ state: "error", message: e.message }));
    return () => {
      live = false;
    };
  }, [url, attempt]);
  return { load, retry };
}
