/* Browser-safe address cleanup shared by the input bar and the server. */

export const INVALID_URL_MESSAGE = "Please enter a valid URL starting with http:// or https://";

export type CleanedTarget =
  | { ok: true; url: string; corrected: { from: string; to: string } | null }
  | { ok: false; message: string };

// Misspelled scheme at the start, e.g. "https.//", "https//", "https:/", "htps://", "https:///".
const SCHEME_TYPO = /^(h{0,2}t{1,3}p{1,2}(s{0,2}))((?::+[;.,]*|[;.,]*:+|[;.,]*)[\/\\]*)/i;
const OTHER_SCHEME = /^[a-z][a-z0-9+.-]*:(?!\d)/i;
const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

function isValidHost(host: string): boolean {
  if (host.startsWith("[") && host.endsWith("]")) return host.length > 2;
  if (IPV4.test(host)) return true;
  const labels = host.replace(/\.$/, "").split(".");
  if (labels.length < 2) return false;
  return labels.every((l) => LABEL.test(l)) && TLD.test(labels[labels.length - 1]);
}

export function cleanUrlInput(raw: string): CleanedTarget {
  const input = raw.trim();
  if (!input || /\s/.test(input)) return { ok: false, message: INVALID_URL_MESSAGE };

  let candidate = input;
  let corrected: { from: string; to: string } | null = null;

  const typo = input.match(SCHEME_TYPO);
  if (typo) {
    const [prefix, , s, sep] = typo;
    // Only treat it as a scheme when a colon or slash follows (so "http.cat" stays a domain).
    if (/[:\/\\]/.test(sep)) {
      const fixed = s ? "https://" : "http://";
      candidate = fixed + input.slice(prefix.length);
      if (prefix.toLowerCase() !== fixed) corrected = { from: prefix, to: fixed };
    }
  }

  if (!/^https?:\/\//i.test(candidate)) {
    if (OTHER_SCHEME.test(candidate) || candidate.includes("://")) {
      return { ok: false, message: INVALID_URL_MESSAGE };
    }
    candidate = `https://${candidate}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, message: INVALID_URL_MESSAGE };
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || !isValidHost(url.hostname)) {
    return { ok: false, message: INVALID_URL_MESSAGE };
  }
  return { ok: true, url: url.toString(), corrected };
}
