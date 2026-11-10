import type { Check, PanelKey, Verdict } from "./types";

/** Share of the Trust Rating contributed by each panel. Sums to 1. */
export const PANEL_WEIGHTS: Record<PanelKey, number> = {
  url: 0.25,
  tls: 0.3,
  headers: 0.15,
  threat: 0.3,
};

/** Hard ceilings: a single critical signal limits the overall rating regardless of the rest. */
export const TRUST_CAPS: { panel: PanelKey; checkId?: string; max: number; reason: string }[] = [
  { panel: "threat", max: 20, reason: "Listed by a threat-intelligence source" },
  {
    panel: "tls",
    checkId: "https-handshake",
    max: 40,
    reason: "A verified secure connection could not be made",
  },
  { panel: "url", checkId: "brand", max: 55, reason: "Brand name used outside its official domain" },
  { panel: "url", checkId: "ip-host", max: 55, reason: "Site is addressed by a raw IP" },
  { panel: "url", checkId: "domain-age", max: 60, reason: "Domain registered within the last 30 days" },
];

export function penaltyFor(check: Check): number {
  if (check.status === "fail") return check.weight;
  if (check.status === "warn") return Math.ceil(check.weight / 2);
  return 0;
}

export function scorePanel(checks: Check[]): number {
  const total = checks.reduce((sum, c) => sum + penaltyFor(c), 0);
  return Math.max(0, Math.min(100, 100 - total));
}

export function computeTrust(
  panels: Record<PanelKey, { score: number; checks: Check[] }>,
): { trust: number; caps: string[] } {
  let trust = Math.round(
    (Object.keys(PANEL_WEIGHTS) as PanelKey[]).reduce(
      (sum, key) => sum + panels[key].score * PANEL_WEIGHTS[key],
      0,
    ),
  );
  const caps: string[] = [];
  for (const cap of TRUST_CAPS) {
    const hit = panels[cap.panel].checks.some(
      (c) => c.status === "fail" && (cap.checkId === undefined || c.id === cap.checkId),
    );
    if (hit && trust > cap.max) {
      trust = cap.max;
      caps.push(cap.reason);
    } else if (hit) {
      caps.push(cap.reason);
    }
  }
  return { trust, caps };
}

export function verdictFor(trust: number): Verdict {
  if (trust >= 75) return "safe";
  if (trust >= 50) return "caution";
  return "danger";
}
