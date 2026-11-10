import { parse } from "tldts";
import { phishingKeywordsIn } from "./scoring";
import type { Check, Fact } from "./types";

/* ---------- Target normalisation & safety ---------- */

export class InspectionInputError extends Error {}

export function isBlockedHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".lan") ||
    h.endsWith(".home.arpa")
  ) {
    return true;
  }
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (h.includes(":")) {
    return (
      h === "::1" ||
      h === "::" ||
      h.startsWith("fc") ||
      h.startsWith("fd") ||
      h.startsWith("fe80") ||
      h.startsWith("::ffff:")
    );
  }
  return !h.includes(".");
}

export function normalizeTarget(raw: string): { url: URL; explicitHttp: boolean } {
  const input = raw.trim();
  if (!input) throw new InspectionInputError("Enter a website address to inspect.");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new InspectionInputError("That doesn't look like a valid website address.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new InspectionInputError("Only http:// and https:// addresses can be inspected.");
  }
  if (isBlockedHost(url.hostname)) {
    throw new InspectionInputError("Private, local or incomplete addresses can't be inspected.");
  }
  return { url, explicitHttp: url.protocol === "http:" };
}

export function parseHost(hostname: string) {
  return parse(hostname.toLowerCase(), { allowPrivateDomains: true });
}

/* ---------- URL & phishing signals ---------- */


const BRANDS = [
  "paypal",
  "apple",
  "icloud",
  "microsoft",
  "office365",
  "outlook",
  "amazon",
  "google",
  "gmail",
  "netflix",
  "facebook",
  "instagram",
  "whatsapp",
  "coinbase",
  "binance",
  "metamask",
  "chase",
  "wellsfargo",
  "bankofamerica",
  "dhl",
  "fedex",
  "usps",
];

const OFFICIAL_DOMAINS = new Set([
  "microsoftonline.com",
  "office.com",
  "live.com",
  "amazonaws.com",
  "googleusercontent.com",
  "googleapis.com",
  "googlevideo.com",
  "fbcdn.net",
]);

const RISKY_TLDS = new Set([
  "zip",
  "mov",
  "top",
  "xyz",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "icu",
  "cyou",
  "rest",
  "click",
  "country",
  "kim",
  "work",
  "loan",
  "gdn",
  "bid",
  "win",
  "men",
  "review",
  "stream",
  "download",
  "cam",
  "quest",
  "sbs",
  "cfd",
]);

function brandMentioned(text: string, brand: string): boolean {
  const tokens = text.split(/[^a-z0-9]+/).filter(Boolean);
  if (tokens.includes(brand)) return true;
  return brand.length >= 7 && text.includes(brand);
}

export function analyzeUrl(url: URL, opts: { explicitHttp: boolean }): Check[] {
  const host = url.hostname.toLowerCase();
  const p = parseHost(host);
  const label = (p.domainWithoutSuffix ?? "").toLowerCase();
  const sub = (p.subdomain ?? "").toLowerCase();
  const checks: Check[] = [];

  checks.push(
    opts.explicitHttp
      ? {
          id: "scheme",
          label: "Encrypted link",
          status: "warn",
          weight: 16,
          detail: "The link uses plain http://, so traffic can be read or altered in transit.",
        }
      : {
          id: "scheme",
          label: "Encrypted link",
          status: "pass",
          weight: 16,
          detail: "The link uses https://.",
        },
  );

  checks.push(
    p.isIp
      ? {
          id: "ip-host",
          label: "Named host",
          status: "fail",
          weight: 35,
          detail: "The host is a raw IP address. Legitimate brands almost always use a domain name.",
        }
      : {
          id: "ip-host",
          label: "Named host",
          status: "pass",
          weight: 35,
          detail: "The host is a registered domain name.",
        },
  );

  const puny = host.split(".").some((l) => l.startsWith("xn--"));
  checks.push({
    id: "punycode",
    label: "Look-alike characters",
    status: puny ? "warn" : "pass",
    weight: 24,
    detail: puny
      ? "Internationalised (punycode) labels can imitate familiar names with look-alike letters."
      : "No internationalised look-alike characters.",
  });

  const hasCreds = Boolean(url.username || url.password);
  checks.push({
    id: "credentials",
    label: "Disguised destination",
    status: hasCreds ? "fail" : "pass",
    weight: 30,
    detail: hasCreds
      ? `Text before "@" (${decodeURIComponent(url.username)}) hides the real destination: ${host}.`
      : "No text is disguising the real destination.",
  });

  if (!p.isIp) {
    const registrable = (p.domain ?? "").toLowerCase();
    const brand = BRANDS.find((b) => {
      if (label === b || OFFICIAL_DOMAINS.has(registrable)) return false;
      return brandMentioned(sub, b) || brandMentioned(label, b);
    });
    checks.push({
      id: "brand",
      label: "Brand impersonation",
      status: brand ? "fail" : "pass",
      weight: 30,
      detail: brand
        ? `Mentions “${brand}” but the registered domain is ${registrable}, not an official ${brand} domain.`
        : "No well-known brand names appear outside their official domain.",
    });

    const lures = phishingKeywordsIn(url);
    checks.push({
      id: "lure-words",
      label: "Urgency & credential lures",
      status: lures.length ? "warn" : "pass",
      weight: lures.length > 1 ? 20 : 10,
      detail: lures.length
        ? `Address contains words often used in phishing: ${lures.join(", ")}.`
        : "No credential or urgency lure words in the address.",
    });

    const tld = (p.publicSuffix ?? "").split(".").pop() ?? "";
    const risky = RISKY_TLDS.has(tld);
    checks.push({
      id: "tld",
      label: "Domain extension",
      status: risky ? "warn" : "pass",
      weight: 16,
      detail: risky
        ? `.${tld} is disproportionately used for abuse and throwaway sites.`
        : `.${p.publicSuffix ?? tld} has no elevated abuse profile.`,
    });

    const depth = sub ? sub.split(".").length : 0;
    const hyphens = (label.match(/-/g) ?? []).length;
    const odd = depth >= 3 || host.length > 45 || hyphens >= 2;
    const reasons = [
      depth >= 3 ? `${depth} subdomain levels` : null,
      host.length > 45 ? `${host.length}-character hostname` : null,
      hyphens >= 2 ? `${hyphens} hyphens in the domain` : null,
    ].filter(Boolean);
    checks.push({
      id: "shape",
      label: "Hostname structure",
      status: odd ? "warn" : "pass",
      weight: 16,
      detail: odd
        ? `Unusual structure (${reasons.join(", ")}) can push the real domain out of view.`
        : "Short, conventional hostname structure.",
    });
  }

  if (url.port && url.port !== "80" && url.port !== "443") {
    checks.push({
      id: "port",
      label: "Non-standard port",
      status: "warn",
      weight: 16,
      detail: `Served on port ${url.port}, which public websites rarely use.`,
    });
  }

  return checks;
}

export function domainAgeCheck(registeredAt: string | null, now: Date): Check {
  if (!registeredAt) {
    return {
      id: "domain-age",
      label: "Domain age",
      status: "info",
      weight: 30,
      detail: "This registry does not publish a registration date.",
    };
  }
  const days = Math.floor((now.getTime() - new Date(registeredAt).getTime()) / 86_400_000);
  if (days < 30) {
    return {
      id: "domain-age",
      label: "Domain age",
      status: "fail",
      weight: 30,
      detail: `Registered only ${Math.max(days, 0)} day${days === 1 ? "" : "s"} ago. Most phishing domains are under a month old.`,
    };
  }
  if (days < 180) {
    return {
      id: "domain-age",
      label: "Domain age",
      status: "warn",
      weight: 20,
      detail: `Registered ${Math.round(days / 30)} months ago — relatively new.`,
    };
  }
  const years = days / 365.25;
  return {
    id: "domain-age",
    label: "Domain age",
    status: "pass",
    weight: 30,
    detail:
      years >= 1
        ? `Established ${Math.floor(years)} year${Math.floor(years) === 1 ? "" : "s"} ago.`
        : `Registered ${Math.round(days / 30)} months ago.`,
  };
}

/* ---------- HTTP security headers ---------- */

export function analyzeHeaders(
  headers: Headers,
  cookies: string[],
): { checks: Check[]; facts: Fact[] } {
  const checks: Check[] = [];
  const get = (n: string) => headers.get(n);

  const hsts = get("strict-transport-security");
  const maxAge = Number(hsts?.match(/max-age=(\d+)/i)?.[1] ?? 0);
  checks.push(
    !hsts
      ? {
          id: "hsts",
          label: "Strict-Transport-Security",
          status: "fail",
          weight: 20,
          detail: "Browsers aren't told to insist on HTTPS, leaving room for downgrade attacks.",
        }
      : maxAge < 15_552_000
        ? {
            id: "hsts",
            label: "Strict-Transport-Security",
            status: "warn",
            weight: 20,
            detail: `HTTPS is enforced for only ${Math.round(maxAge / 86400)} days; 180+ is recommended.`,
          }
        : {
            id: "hsts",
            label: "Strict-Transport-Security",
            status: "pass",
            weight: 20,
            detail: `HTTPS enforced for ${Math.round(maxAge / 86400)} days${/includesubdomains/i.test(hsts) ? ", including subdomains" : ""}.`,
          },
  );

  const csp = get("content-security-policy");
  const cspRo = get("content-security-policy-report-only");
  checks.push({
    id: "csp",
    label: "Content-Security-Policy",
    status: csp ? "pass" : cspRo ? "warn" : "fail",
    weight: 20,
    detail: csp
      ? "A content policy restricts where scripts and resources may load from."
      : cspRo
        ? "A content policy exists but only reports violations without blocking them."
        : "No content policy — injected scripts would run unrestricted.",
  });

  const xfo = get("x-frame-options");
  const frameAncestors = /frame-ancestors/i.test(csp ?? "");
  checks.push({
    id: "framing",
    label: "Clickjacking protection",
    status: xfo || frameAncestors ? "pass" : "fail",
    weight: 12,
    detail: xfo
      ? `X-Frame-Options: ${xfo}.`
      : frameAncestors
        ? "Framing restricted via CSP frame-ancestors."
        : "The site can be embedded invisibly inside other pages.",
  });

  const nosniff = /nosniff/i.test(get("x-content-type-options") ?? "");
  checks.push({
    id: "nosniff",
    label: "X-Content-Type-Options",
    status: nosniff ? "pass" : "fail",
    weight: 10,
    detail: nosniff
      ? "MIME sniffing disabled (nosniff)."
      : "Browsers may guess file types, which can turn uploads into scripts.",
  });

  const referrer = get("referrer-policy");
  checks.push({
    id: "referrer",
    label: "Referrer-Policy",
    status: referrer ? "pass" : "warn",
    weight: 10,
    detail: referrer
      ? `Referrer data limited: ${referrer}.`
      : "No explicit policy; browser defaults decide what URLs leak to other sites.",
  });

  const permissions = get("permissions-policy");
  checks.push({
    id: "permissions",
    label: "Permissions-Policy",
    status: permissions ? "pass" : "warn",
    weight: 10,
    detail: permissions
      ? "Camera, microphone and other powerful features are explicitly governed."
      : "Access to powerful browser features is not explicitly restricted.",
  });

  const server = get("server");
  const powered = get("x-powered-by");
  const leaks = [server && /\d/.test(server) ? `Server: ${server}` : null, powered ? `X-Powered-By: ${powered}` : null].filter(Boolean);
  checks.push({
    id: "disclosure",
    label: "Software disclosure",
    status: leaks.length ? "warn" : "pass",
    weight: 10,
    detail: leaks.length
      ? `Reveals stack details useful to attackers (${leaks.join("; ")}).`
      : "No software versions are advertised.",
  });

  if (cookies.length) {
    const insecure = cookies.filter((c) => !/;\s*secure/i.test(c)).length;
    checks.push({
      id: "cookies",
      label: "Cookie flags",
      status: insecure ? "warn" : "pass",
      weight: 12,
      detail: insecure
        ? `${insecure} of ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} can travel over unencrypted connections (missing Secure).`
        : `All ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} marked Secure.`,
    });
  }

  const shown = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
  ];
  const facts: Fact[] = shown
    .map((name) => ({ label: name, value: get(name) }))
    .filter((f): f is Fact => Boolean(f.value))
    .map((f) => ({ ...f, value: f.value.length > 140 ? `${f.value.slice(0, 140)}…` : f.value }));

  return { checks, facts };
}

/* ---------- Certificate transparency ---------- */

export interface CtIssuance {
  dns_names?: string[];
  not_before: string;
  not_after: string;
  revoked?: boolean;
  cert_sha256?: string;
  issuer?: { friendly_name?: string; name?: string };
}

export function certCoversHost(name: string, host: string): boolean {
  const n = name.toLowerCase();
  const h = host.toLowerCase();
  if (n === h) return true;
  if (n.startsWith("*.")) {
    const suffix = n.slice(1);
    return h.endsWith(suffix) && h.split(".").length === n.split(".").length;
  }
  return false;
}

export function analyzeCertificate(
  issuances: CtIssuance[] | null,
  host: string,
  now: Date,
): { checks: Check[]; facts: Fact[] } {
  if (issuances === null) {
    return {
      checks: [
        {
          id: "ct",
          label: "Certificate Transparency",
          status: "info",
          weight: 25,
          detail: "Public certificate logs could not be reached right now.",
        },
      ],
      facts: [],
    };
  }

  const current = issuances
    .filter((i) => (i.dns_names ?? []).some((n) => certCoversHost(n, host)))
    .filter((i) => new Date(i.not_after).getTime() > now.getTime() - 30 * 86_400_000)
    .sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());
  const cert = current[0];

  if (!cert) {
    return {
      checks: [
        {
          id: "ct",
          label: "Certificate Transparency",
          status: "warn",
          weight: 25,
          detail: "No current certificate for this hostname appears in public certificate logs.",
        },
      ],
      facts: [],
    };
  }

  const days = Math.floor((new Date(cert.not_after).getTime() - now.getTime()) / 86_400_000);
  const issuer = cert.issuer?.friendly_name || cert.issuer?.name || "Unknown issuer";
  const checks: Check[] = [
    {
      id: "ct",
      label: "Certificate Transparency",
      status: "pass",
      weight: 25,
      detail: `Certificate is publicly logged and issued by ${issuer}, a publicly trusted authority.`,
    },
    days < 0
      ? {
          id: "expiry",
          label: "Validity window",
          status: "fail",
          weight: 40,
          detail: `Expired ${Math.abs(days)} days ago.`,
        }
      : days < 14
        ? {
            id: "expiry",
            label: "Validity window",
            status: "warn",
            weight: 20,
            detail: `Expires in ${days} day${days === 1 ? "" : "s"}.`,
          }
        : {
            id: "expiry",
            label: "Validity window",
            status: "pass",
            weight: 20,
            detail: `Valid for another ${days} days.`,
          },
    {
      id: "revocation",
      label: "Revocation status",
      status: cert.revoked ? "fail" : "pass",
      weight: 50,
      detail: cert.revoked
        ? "The issuing authority has revoked this certificate."
        : "Not revoked by the issuing authority.",
    },
  ];

  const names = cert.dns_names ?? [];
  const facts: Fact[] = [
    { label: "Issuer", value: issuer },
    ...(cert.issuer?.name ? [{ label: "Issuer DN", value: cert.issuer.name }] : []),
    { label: "Valid from", value: cert.not_before.slice(0, 10) },
    { label: "Valid until", value: cert.not_after.slice(0, 10) },
    {
      label: "Covers",
      value: names.slice(0, 5).join(", ") + (names.length > 5 ? ` +${names.length - 5} more` : ""),
    },
    ...(cert.cert_sha256
      ? [{ label: "SHA-256", value: `${cert.cert_sha256.slice(0, 32)}…` }]
      : []),
  ];

  return { checks, facts };
}
