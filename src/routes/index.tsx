import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { ArrowRight, Globe, OctagonAlert } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { z } from "zod";
import { Report, ReportSkeleton } from "@/components/netveritas/Report";
import { Button } from "@/components/ui/button";
import { inspectDomain } from "@/lib/inspect/inspect.functions";

const searchSchema = z.object({ q: z.string().max(2048).optional() });

export const Route = createFileRoute("/")({
  validateSearch: (search) => searchSchema.parse(search),
  head: () => ({
    meta: [
      { title: "NetVeritas — Website Safety & Certificate Trust Inspector" },
      {
        name: "description",
        content:
          "Inspect any domain for phishing signals, TLS certificate trust, HTTP security headers and community threat reports. Get a Trust Rating out of 100.",
      },
      { property: "og:title", content: "NetVeritas — Website Safety & Certificate Trust" },
      {
        property: "og:description",
        content: "One URL in, a Trust Rating out of 100 with four transparent analytical panels.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const EXAMPLES = [
  { label: "github.com", value: "github.com" },
  { label: "example.com", value: "example.com" },
  { label: "malware test domain", value: "malware.testcategory.com" },
];

function Index() {
  const { q } = Route.useSearch();
  const navigate = useNavigate({ from: "/" });
  const [value, setValue] = useState(q ?? "");
  const inspect = useServerFn(inspectDomain);

  useEffect(() => {
    setValue(q ?? "");
  }, [q]);

  const query = useQuery({
    queryKey: ["inspect", q],
    queryFn: () => inspect({ data: { url: q! } }),
    enabled: Boolean(q),
    staleTime: 5 * 60_000,
    retry: false,
  });

  const submit = (target: string) => {
    const t = target.trim();
    if (!t) return;
    if (t === q) {
      void query.refetch();
      return;
    }
    void navigate({ search: { q: t } });
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit(value);
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="relative border-b border-border">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" aria-hidden />
        <div className="relative mx-auto max-w-6xl px-4 pb-8 pt-6 sm:px-6">
          <div className="flex items-center justify-between">
            <a href="/" className="flex items-center gap-2.5">
              <span className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden>
                  <path d="M4 5l8 14 8-14" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
              <span className="text-lg font-semibold tracking-tight text-foreground">
                Net<span className="text-primary">Veritas</span>
              </span>
            </a>
            <span className="hidden font-mono text-xs text-muted-foreground sm:block">
              Website safety &amp; certificate trust
            </span>
          </div>

          <form onSubmit={onSubmit} className="mt-8">
            <label htmlFor="target" className="sr-only">
              Website address
            </label>
            <div className="flex flex-col gap-2 rounded-lg border border-input bg-inset p-2 transition-colors focus-within:border-primary sm:flex-row">
              <div className="flex flex-1 items-center gap-3 px-3">
                <Globe className="size-5 shrink-0 text-muted-foreground" />
                <input
                  id="target"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="Paste a link or domain — e.g. https://example.com/login"
                  autoComplete="off"
                  spellCheck={false}
                  maxLength={2048}
                  className="h-12 w-full bg-transparent font-mono text-base text-foreground outline-none placeholder:text-muted-foreground"
                />
              </div>
              <Button type="submit" className="h-12 px-6 text-sm font-semibold" disabled={query.isFetching}>
                {query.isFetching ? "Inspecting…" : "Inspect Domain"}
                <ArrowRight />
              </Button>
            </div>
          </form>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted-foreground">Try</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.value}
                type="button"
                onClick={() => {
                  setValue(ex.value);
                  submit(ex.value);
                }}
                className="rounded-md border border-border px-2.5 py-1 font-mono text-muted-foreground transition-colors hover:border-primary hover:text-foreground"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
        {!q && <EmptyState />}
        {q && query.isFetching && <ReportSkeleton target={q} />}
        {q && !query.isFetching && query.isError && (
          <div className="animate-rise flex items-start gap-3 rounded-lg border border-danger/40 bg-card p-5">
            <OctagonAlert className="mt-0.5 size-5 shrink-0 text-danger" />
            <div>
              <div className="font-semibold text-foreground">Inspection could not run</div>
              <p className="mt-1 text-sm text-muted-foreground">
                {(query.error as Error)?.message || "Something went wrong. Try again."}
              </p>
            </div>
          </div>
        )}
        {q && !query.isFetching && query.data && <Report report={query.data} />}
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto max-w-6xl px-4 py-5 text-xs text-muted-foreground sm:px-6">
          Live data from the site itself, public Certificate Transparency logs, RDAP registries,
          Cloudflare Security DNS and the OpenPhish community feed. Ratings are guidance, not a
          guarantee.
        </div>
      </footer>
    </div>
  );
}

function EmptyState() {
  const items = [
    ["01", "URL & Phishing Signals", "Look-alike characters, brand impersonation, lure words and domain age."],
    ["02", "TLS Certificate & Issuer", "Verified handshake, issuing authority, transparency logs and expiry."],
    ["03", "HTTP Security Headers", "HSTS, content policy, clickjacking and cookie protections."],
    ["04", "Community Threat Log", "Live checks against shared malware and phishing intelligence."],
  ];
  return (
    <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
      {items.map(([n, t, d]) => (
        <div key={n} className="bg-background p-5">
          <div className="font-mono text-[11px] tracking-[0.18em] text-primary">{n}</div>
          <div className="mt-2 text-sm font-semibold text-foreground">{t}</div>
          <p className="mt-1 text-sm leading-snug text-muted-foreground">{d}</p>
        </div>
      ))}
    </div>
  );
}
