import {
  analyzeCertificate,
  analyzeHeaders,
  analyzeUrl,
  domainAgeCheck,
  isBlockedHost,
  normalizeTarget,
  parseHost,
  type CtIssuance,
} from "./signals";
import { computeTrust, scorePanel, verdictFor } from "./scoring";
import type { Check, Fact, InspectionReport, PanelKey, PanelResult } from "./types";

const UA = "Mozilla/5.0 (compatible; NetVeritas/1.0; website trust inspector)";
const TIMEOUT_MS = 8000;

interface ChainResult {
  response: Response;
  finalUrl: URL;
  hops: number;
}

async function fetchChain(start: URL, maxHops = 5): Promise<ChainResult> {
  let current = start;
  for (let hop = 0; hop <= maxHops; hop++) {
    if (isBlockedHost(current.hostname)) throw new Error("Redirected to a private address");
    const res = await fetch(current.toString(), {
      method: "GET",
      redirect: "manual",
      headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const location = res.headers.get("location");
    await res.body?.cancel().catch(() => undefined);
    if (res.status >= 300 && res.status < 400 && location) {
      current = new URL(location, current);
      continue;
    }
    return { response: res, finalUrl: current, hops: hop };
  }
  throw new Error("Too many redirects");
}

function describeFetchError(err: unknown): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  const code = e?.cause?.code ?? "";
  const msg = `${e?.message ?? ""} ${e?.cause?.message ?? ""}`;
  if (e?.name === "TimeoutError" || e?.name === "AbortError") {
    return "The server did not respond within 8 seconds.";
  }
  if (/CERT|SSL|TLS|self.signed|altname|certificate/i.test(`${code} ${msg}`)) {
    return `The certificate was rejected (${code || msg.trim()}).`;
  }
  if (/ENOTFOUND|EAI_AGAIN|resolve/i.test(`${code} ${msg}`)) {
    return "The domain does not resolve to a server.";
  }
  return `Connection failed (${code || msg.trim() || "unknown error"}).`;
}

async function lookupRdap(domain: string) {
  const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: "application/rdap+json, application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  const json = (await res.json()) as {
    events?: { eventAction?: string; eventDate?: string }[];
    entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, string][]] }[];
  };
  const registeredAt =
    json.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null;
  const registrarEntity = json.entities?.find((e) => e.roles?.includes("registrar"));
  const registrar =
    registrarEntity?.vcardArray?.[1]?.find((f) => f[0] === "fn")?.[3]?.toString() ?? null;
  return { registeredAt, registrar };
}

async function lookupCertificates(host: string): Promise<CtIssuance[] | null> {
  const res = await fetch(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&expand=dns_names&expand=issuer`,
    { headers: { "user-agent": UA }, signal: AbortSignal.timeout(TIMEOUT_MS) },
  );
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    return null;
  }
  return (await res.json()) as CtIssuance[];
}

async function lookupSecurityDns(host: string) {
  const res = await fetch(
    `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
    { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(TIMEOUT_MS) },
  );
  if (!res.ok) throw new Error(`Resolver returned ${res.status}`);
  const json = (await res.json()) as { Status: number; Answer?: { type: number; data: string }[] };
  const ips = (json.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
  if (ips.includes("0.0.0.0")) return { state: "blocked" as const, ips };
  if (json.Status === 3) return { state: "nxdomain" as const, ips };
  return { state: "ok" as const, ips };
}

let phishFeed: { at: number; urls: string[] } | null = null;
async function getPhishFeed(): Promise<string[]> {
  if (phishFeed && Date.now() - phishFeed.at < 15 * 60_000) return phishFeed.urls;
  const res = await fetch(
    "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    { signal: AbortSignal.timeout(TIMEOUT_MS) },
  );
  if (!res.ok) throw new Error(`Feed returned ${res.status}`);
  const urls = (await res.text())
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  phishFeed = { at: Date.now(), urls };
  return urls;
}

function hostOf(raw: string): string | null {
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function runInspection(input: string): Promise<InspectionReport> {
  const { url, explicitHttp } = normalizeTarget(input);
  const host = url.hostname.toLowerCase();
  const parsed = parseHost(host);
  const registrable = parsed.domain ?? null;
  const now = new Date();

  const httpsUrl = new URL(url.toString());
  httpsUrl.protocol = "https:";
  if (httpsUrl.port === "80") httpsUrl.port = "";

  // Six independent lookups — the server allows six outbound requests in flight at once.
  const [httpsRes, httpRes, rdapRes, ctRes, dnsRes, feedRes] = await Promise.allSettled([
    fetchChain(httpsUrl),
    fetch(`http://${url.host}/`, {
      redirect: "manual",
      headers: { "user-agent": UA },
      signal: AbortSignal.timeout(6000),
    }).then(async (r) => {
      await r.body?.cancel().catch(() => undefined);
      return { status: r.status, location: r.headers.get("location") };
    }),
    registrable && !parsed.isIp ? lookupRdap(registrable) : Promise.resolve(null),
    lookupCertificates(host),
    parsed.isIp ? Promise.resolve(null) : lookupSecurityDns(host),
    getPhishFeed(),
  ]);

  const chain = httpsRes.status === "fulfilled" ? httpsRes.value : null;

  /* URL & phishing signals */
  const urlChecks: Check[] = analyzeUrl(url, { explicitHttp });
  const rdap = rdapRes.status === "fulfilled" ? rdapRes.value : null;
  if (!parsed.isIp) urlChecks.push(domainAgeCheck(rdap?.registeredAt ?? null, now));
  if (chain) {
    const finalDomain = parseHost(chain.finalUrl.hostname).domain;
    const crossDomain = finalDomain && registrable && finalDomain !== registrable;
    urlChecks.push({
      id: "redirect",
      label: "Redirect destination",
      status: crossDomain ? "warn" : "pass",
      weight: 16,
      detail: crossDomain
        ? `Sends visitors to a different domain: ${chain.finalUrl.hostname}.`
        : chain.hops > 0
          ? `Redirects ${chain.hops}× but stays on ${registrable ?? host}.`
          : "Serves content directly without redirects.",
    });
  }
  const urlFacts: Fact[] = [
    { label: "Hostname", value: host },
    ...(registrable ? [{ label: "Registered domain", value: registrable }] : []),
    ...(parsed.publicSuffix ? [{ label: "Public suffix", value: `.${parsed.publicSuffix}` }] : []),
    ...(rdap?.registrar ? [{ label: "Registrar", value: rdap.registrar }] : []),
    ...(rdap?.registeredAt
      ? [{ label: "Registered on", value: rdap.registeredAt.slice(0, 10) }]
      : []),
  ];

  /* TLS certificate & issuer */
  const tlsChecks: Check[] = [
    chain
      ? {
          id: "https-handshake",
          label: "Verified HTTPS connection",
          status: "pass",
          weight: 60,
          detail: "The TLS handshake completed and the certificate chain verified against trusted roots.",
        }
      : {
          id: "https-handshake",
          label: "Verified HTTPS connection",
          status: "fail",
          weight: 60,
          detail: describeFetchError(httpsRes.status === "rejected" ? httpsRes.reason : null),
        },
  ];
  if (httpRes.status === "fulfilled") {
    const loc = httpRes.value.location ?? "";
    const upgrades = /^https:\/\//i.test(loc);
    tlsChecks.push({
      id: "http-upgrade",
      label: "HTTP → HTTPS upgrade",
      status: upgrades ? "pass" : "warn",
      weight: 16,
      detail: upgrades
        ? "Plain HTTP visits are redirected to HTTPS."
        : "Plain HTTP is served without forcing visitors onto HTTPS.",
    });
  } else {
    tlsChecks.push({
      id: "http-upgrade",
      label: "HTTP → HTTPS upgrade",
      status: "info",
      weight: 16,
      detail: "No plain-HTTP entry point is reachable.",
    });
  }
  const cert = analyzeCertificate(ctRes.status === "fulfilled" ? ctRes.value : null, host, now);
  tlsChecks.push(...cert.checks);

  /* HTTP security headers */
  let headerChecks: Check[];
  let headerFacts: Fact[] = [];
  if (chain) {
    const h = chain.response.headers;
    const cookies =
      typeof h.getSetCookie === "function"
        ? h.getSetCookie()
        : (h.get("set-cookie")?.split(/,(?=\s*[^;,=\s]+=)/) ?? []);
    const analysis = analyzeHeaders(h, cookies);
    headerChecks = analysis.checks;
    headerFacts = [
      { label: "Analyzed", value: `${chain.response.status} ${chain.finalUrl.toString()}` },
      ...analysis.facts,
    ];
  } else {
    headerChecks = [
      {
        id: "reachable",
        label: "Response received",
        status: "fail",
        weight: 100,
        detail: "No secure response was received, so no protective headers could be confirmed.",
      },
    ];
  }

  /* Community threat log */
  const threatChecks: Check[] = [];
  if (dnsRes.status === "fulfilled" && dnsRes.value) {
    const d = dnsRes.value;
    threatChecks.push({
      id: "cloudflare-dns",
      source: "Cloudflare Security DNS",
      label: "Malware & phishing resolver",
      status: d.state === "blocked" ? "fail" : d.state === "nxdomain" ? "warn" : "pass",
      weight: d.state === "blocked" ? 100 : 30,
      detail:
        d.state === "blocked"
          ? "Classified as malware or phishing — resolution is blocked for protected users."
          : d.state === "nxdomain"
            ? "The domain does not exist in public DNS."
            : `No threat classification. Resolves to ${d.ips.slice(0, 3).join(", ") || "an alias"}.`,
    });
  } else if (!parsed.isIp) {
    threatChecks.push({
      id: "cloudflare-dns",
      source: "Cloudflare Security DNS",
      label: "Malware & phishing resolver",
      status: "info",
      weight: 0,
      detail: "Resolver could not be reached for this lookup.",
    });
  }

  if (feedRes.status === "fulfilled") {
    const feed = feedRes.value;
    const exact = feed.filter((u) => hostOf(u) === host);
    const sameDomain = registrable
      ? feed.filter((u) => {
          const h = hostOf(u);
          return h !== host && h && parseHost(h).domain === registrable;
        })
      : [];
    threatChecks.push({
      id: "openphish",
      source: "OpenPhish community feed",
      label: "Reported phishing URLs",
      status: exact.length ? "fail" : sameDomain.length ? "info" : "pass",
      weight: 100,
      detail: exact.length
        ? `${exact.length} active phishing URL${exact.length === 1 ? "" : "s"} on this host have been reported.`
        : sameDomain.length
          ? `This host is clean, but ${sameDomain.length} reported URL${sameDomain.length === 1 ? "" : "s"} live elsewhere on ${registrable}.`
          : `Not among ${feed.length} currently active reported phishing URLs.`,
    });
  } else {
    threatChecks.push({
      id: "openphish",
      source: "OpenPhish community feed",
      label: "Reported phishing URLs",
      status: "info",
      weight: 0,
      detail: "The community feed could not be loaded for this lookup.",
    });
  }

  threatChecks.push({
    id: "ct-presence",
    source: "Certificate Transparency",
    label: "Public issuance record",
    status: cert.checks[0]?.status === "pass" ? "pass" : "info",
    weight: 0,
    detail:
      cert.checks[0]?.status === "pass"
        ? "Certificate issuance for this host is publicly auditable."
        : "No auditable issuance record for this host.",
  });

  const build = (key: PanelKey, checks: Check[], facts: Fact[]): PanelResult => ({
    key,
    checks,
    facts,
    score: scorePanel(checks),
  });

  const panels: Record<PanelKey, PanelResult> = {
    url: build("url", urlChecks, urlFacts),
    tls: build("tls", tlsChecks, cert.facts),
    headers: build("headers", headerChecks, headerFacts),
    threat: build("threat", threatChecks, []),
  };
  const { trust, caps } = computeTrust(panels);

  return {
    input,
    url: url.toString(),
    hostname: host,
    registrableDomain: registrable,
    finalUrl: chain?.finalUrl.toString() ?? null,
    inspectedAt: now.toISOString(),
    trust,
    verdict: verdictFor(trust),
    caps,
    panels,
  };
}
