import type { Check, Deduction, Verdict } from "./types";

/**
 * Trust Rating rules. The rating starts at 100 and each rule, when triggered,
 * deducts a fixed number of points. No randomness, no weighting, no live
 * reputation data — the same evidence always yields the same score.
 */
export const DEDUCTION_POINTS = {
  http: 35,
  tls: 40,
  phishing: 15,
  headers: 10,
} as const;

export type DeductionId = keyof typeof DEDUCTION_POINTS;

/** Hostname markers that always count as a failed certificate check. */
export const TLS_FAILURE_MARKERS = ["expired", "self-signed", "untrusted", "wrong.host"] as const;

/** Words commonly used in phishing links. Matched anywhere in the URL (host, path, query). */
export const PHISHING_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "verification",
  "update",
  "kyc",
  "secure",
  "account",
  "confirm",
  "wallet",
  "banking",
  "password",
  "unlock",
  "recover",
  "suspended",
] as const;

/** Headers a strictly configured site must send. */
export const STRICT_HEADERS = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
] as const;

export function tlsMarkersIn(hostname: string): string[] {
  const h = hostname.toLowerCase();
  return TLS_FAILURE_MARKERS.filter((m) => h.includes(m));
}

export function phishingKeywordsIn(url: URL): string[] {
  let text = `${url.hostname}${url.pathname}${url.search}`.toLowerCase();
  try {
    text = decodeURIComponent(text);
  } catch {
    /* keep raw text */
  }
  // "verification" already implies "verify"-style intent; report each word once.
  return PHISHING_KEYWORDS.filter((w) => text.includes(w));
}

/** Returns the strict headers that are absent. A missing response means all are missing. */
export function missingStrictHeaders(headers: Headers | null): string[] {
  if (!headers) return [...STRICT_HEADERS];
  const csp = headers.get("content-security-policy") ?? "";
  const missing: string[] = [];
  if (!headers.get("strict-transport-security")) missing.push("Strict-Transport-Security");
  if (!csp) missing.push("Content-Security-Policy");
  if (!headers.get("x-frame-options") && !/frame-ancestors/i.test(csp)) {
    missing.push("X-Frame-Options");
  }
  if (!/nosniff/i.test(headers.get("x-content-type-options") ?? "")) {
    missing.push("X-Content-Type-Options");
  }
  return missing;
}

export interface TrustEvidence {
  url: URL;
  /** Why the secure connection failed validation, or null when it verified. */
  tlsFailure: string | null;
  /** Strict headers that were not sent. */
  missingHeaders: string[];
}

export function computeTrust(evidence: TrustEvidence): { trust: number; deductions: Deduction[] } {
  const { url, tlsFailure, missingHeaders } = evidence;
  const markers = tlsMarkersIn(url.hostname);
  const keywords = phishingKeywordsIn(url);
  const usesHttp = url.protocol === "http:";

  const deductions: Deduction[] = [
    {
      id: "http",
      label: "Unencrypted http:// link",
      points: DEDUCTION_POINTS.http,
      applied: usesHttp,
      reason: usesHttp ? "The address uses plain http://." : "The address uses https://.",
    },
    {
      id: "tls",
      label: "Certificate / TLS validation",
      points: DEDUCTION_POINTS.tls,
      applied: markers.length > 0 || tlsFailure !== null,
      reason:
        markers.length > 0
          ? `Hostname contains a certificate-failure marker: ${markers.join(", ")}.`
          : tlsFailure ?? "The certificate verified against trusted roots.",
    },
    {
      id: "phishing",
      label: "Phishing keywords in URL",
      points: DEDUCTION_POINTS.phishing,
      applied: keywords.length > 0,
      reason: keywords.length
        ? `Found: ${keywords.join(", ")}.`
        : "No phishing keywords in the address.",
    },
    {
      id: "headers",
      label: "Strict security headers",
      points: DEDUCTION_POINTS.headers,
      applied: missingHeaders.length > 0,
      reason: missingHeaders.length
        ? `Missing: ${missingHeaders.join(", ")}.`
        : "All strict security headers are present.",
    },
  ];

  const total = deductions.reduce((sum, d) => sum + (d.applied ? d.points : 0), 0);
  return { trust: Math.max(0, 100 - total), deductions };
}

/* ---------- Per-panel diagnostic scores (shown on each panel, not part of the Trust Rating) ---------- */

export function penaltyFor(check: Check): number {
  if (check.status === "fail") return check.weight;
  if (check.status === "warn") return Math.ceil(check.weight / 2);
  return 0;
}

export function scorePanel(checks: Check[]): number {
  const total = checks.reduce((sum, c) => sum + penaltyFor(c), 0);
  return Math.max(0, Math.min(100, 100 - total));
}

export function verdictFor(trust: number): Verdict {
  if (trust >= 75) return "safe";
  if (trust >= 50) return "caution";
  return "danger";
}
