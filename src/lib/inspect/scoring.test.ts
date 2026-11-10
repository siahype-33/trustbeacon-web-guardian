import { describe, expect, it } from "vitest";
import { computeTrust, scorePanel, verdictFor } from "./scoring";
import { domainAgeCheck, isBlockedHost, normalizeTarget, analyzeUrl } from "./signals";
import type { Check, PanelKey } from "./types";

const pass = (id: string, weight = 20): Check => ({ id, label: id, status: "pass", weight, detail: "" });
const fail = (id: string, weight = 20): Check => ({ id, label: id, status: "fail", weight, detail: "" });

function panels(overrides: Partial<Record<PanelKey, Check[]>> = {}) {
  const keys: PanelKey[] = ["url", "tls", "headers", "threat"];
  return Object.fromEntries(
    keys.map((k) => {
      const checks = overrides[k] ?? [pass(`${k}-ok`)];
      return [k, { score: scorePanel(checks), checks }];
    }),
  ) as Record<PanelKey, { score: number; checks: Check[] }>;
}

describe("trust rating", () => {
  it("is 100 when every panel passes", () => {
    expect(computeTrust(panels()).trust).toBe(100);
  });

  it("warnings cost half the check weight", () => {
    expect(scorePanel([{ ...pass("x", 20), status: "warn" }])).toBe(90);
  });

  it("is capped at 20 when a threat source flags the host", () => {
    expect(computeTrust(panels({ threat: [fail("cloudflare-dns", 1)] })).trust).toBe(20);
  });

  it("is capped at 40 when the HTTPS handshake fails", () => {
    expect(computeTrust(panels({ tls: [fail("https-handshake", 1)] })).trust).toBe(40);
  });

  it("is capped at 60 for domains registered under 30 days ago", () => {
    expect(computeTrust(panels({ url: [fail("domain-age", 1)] })).trust).toBe(60);
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
