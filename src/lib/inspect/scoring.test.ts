import { describe, expect, it } from "vitest";
import { computeTrust, missingStrictHeaders, verdictFor } from "./scoring";
import { domainAgeCheck, isBlockedHost, normalizeTarget, analyzeUrl } from "./signals";

const strictHeaders = new Headers({
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
});

function score(input: string, opts: { tlsFailure?: string | null; headers?: Headers | null } = {}) {
  const { url } = normalizeTarget(input);
  return computeTrust({
    url,
    tlsFailure: opts.tlsFailure ?? null,
    missingHeaders: missingStrictHeaders(opts.headers === undefined ? strictHeaders : opts.headers),
  }).trust;
}

describe("trust rating", () => {
  it("is 100 for a clean https site with strict headers", () => {
    expect(score("github.com")).toBe(100);
  });

  it("deducts 35 for an unencrypted http:// link", () => {
    expect(score("http://github.com")).toBe(65);
  });

  it("deducts 40 when TLS validation fails", () => {
    expect(score("github.com", { tlsFailure: "The certificate was rejected." })).toBe(60);
  });

  it.each(["expired.badssl.com", "self-signed.badssl.com", "untrusted-root.badssl.com", "wrong.host.badssl.com"])(
    "deducts 40 for certificate-failure hostname %s",
    (host) => {
      expect(score(host)).toBe(60);
    },
  );

  it.each(["login", "verify", "update", "kyc", "secure"])("deducts 15 for the keyword %s", (word) => {
    expect(score(`example.org/${word}`)).toBe(85);
  });

  it("deducts 10 when a strict security header is missing", () => {
    const h = new Headers(strictHeaders);
    h.delete("content-security-policy");
    expect(score("github.com", { headers: h })).toBe(90);
  });

  it("deducts 10 when no response was received", () => {
    expect(score("github.com", { headers: null })).toBe(90);
  });

  it("stacks all four deductions to 0", () => {
    expect(score("http://expired.secure-login.com", { headers: null })).toBe(0);
  });

  it("gives the same score for the same URL every time", () => {
    const runs = Array.from({ length: 50 }, () => score("http://kyc-update.example.com"));
    expect(new Set(runs)).toEqual(new Set([50]));
  });

  it("maps 75+ to safe, 50–74 to caution, below 50 to danger", () => {
    expect(verdictFor(75)).toBe("safe");
    expect(verdictFor(74)).toBe("caution");
    expect(verdictFor(50)).toBe("caution");
    expect(verdictFor(49)).toBe("danger");
  });
});

describe("signals", () => {
  it("flags a 10-day-old domain as failing the age check", () => {
    const now = new Date("2026-11-10T00:00:00Z");
    expect(domainAgeCheck("2026-10-31T00:00:00Z", now).status).toBe("fail");
  });

  it("flags brand names outside their official domain", () => {
    const { url } = normalizeTarget("paypal.com.secure-check.net");
    expect(analyzeUrl(url, { explicitHttp: false }).find((c) => c.id === "brand")?.status).toBe("fail");
  });

  it("does not flag the brand's own domain", () => {
    const { url } = normalizeTarget("www.paypal.com");
    expect(analyzeUrl(url, { explicitHttp: false }).find((c) => c.id === "brand")?.status).toBe("pass");
  });

  it("refuses private and local addresses", () => {
    expect(isBlockedHost("localhost")).toBe(true);
    expect(isBlockedHost("192.168.1.1")).toBe(true);
    expect(() => normalizeTarget("http://127.0.0.1")).toThrow();
    expect(isBlockedHost("github.com")).toBe(false);
  });
});
