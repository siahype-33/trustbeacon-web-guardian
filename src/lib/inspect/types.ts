export type CheckStatus = "pass" | "warn" | "fail" | "info";

export type PanelKey = "url" | "tls" | "headers" | "threat";

export interface Check {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  /** Points deducted from the panel score on fail (half on warn). */
  weight: number;
  /** Where the signal came from (used by the threat log). */
  source?: string;
}

export interface Fact {
  label: string;
  value: string;
}

export interface PanelResult {
  key: PanelKey;
  score: number;
  checks: Check[];
  facts: Fact[];
}

export type Verdict = "safe" | "caution" | "danger";

export interface InspectionReport {
  input: string;
  url: string;
  hostname: string;
  registrableDomain: string | null;
  finalUrl: string | null;
  inspectedAt: string;
  trust: number;
  verdict: Verdict;
  caps: string[];
  panels: Record<PanelKey, PanelResult>;
}
