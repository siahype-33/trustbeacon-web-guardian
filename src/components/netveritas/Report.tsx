import { Check, FileLock2, Fingerprint, Radar, ShieldHalf, TriangleAlert } from "lucide-react";
import type { InspectionReport, PanelKey } from "@/lib/inspect/types";
import { cn } from "@/lib/utils";
import { CheckList, FactTable, PanelShell, ThreatLog } from "./Panels";
import { TrustGauge } from "./TrustGauge";
import { toneFromVerdict, toneText } from "./tone";

const PANEL_META: Record<PanelKey, { title: string; subtitle: string }> = {
  url: { title: "URL & Phishing Signals", subtitle: "Structure, impersonation and domain age" },
  tls: { title: "TLS Certificate & Issuer Check", subtitle: "Handshake, transparency logs, validity" },
  headers: { title: "HTTP Security Headers", subtitle: "Browser-side protections sent by the server" },
  threat: { title: "Community Threat Log", subtitle: "Shared blocklists and phishing reports" },
};

const ORDER: PanelKey[] = ["url", "tls", "headers", "threat"];

const verdictSentence = {
  safe: "No significant risk signals. This site behaves like an established, well-configured domain.",
  caution: "Some protections are missing or signals are unusual. Verify before entering personal data.",
  danger: "Serious risk signals detected. Avoid entering credentials or payment details here.",
};

export function Report({ report }: { report: InspectionReport }) {
  const tone = toneFromVerdict[report.verdict];
  const { panels } = report;

  return (
    <div className="space-y-4">
      <section className="animate-rise grid gap-6 rounded-lg border border-border bg-card p-6 md:grid-cols-[220px_1fr] md:gap-10">
        <TrustGauge score={report.trust} verdict={report.verdict} />
        <div className="flex min-w-0 flex-col justify-center">
          <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
            Inspected {new Date(report.inspectedAt).toLocaleString()}
          </div>
          <h2 className="mt-1 break-all font-mono text-2xl font-semibold text-foreground md:text-3xl">
            {report.hostname}
          </h2>
          {report.finalUrl && report.finalUrl !== report.url && (
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">
              → {report.finalUrl}
            </p>
          )}
          <p className={cn("mt-3 max-w-xl text-sm", toneText[tone])}>
            {verdictSentence[report.verdict]}
          </p>

          <div className="mt-5">
            <div className="flex items-baseline justify-between font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
              <span>Score breakdown</span>
              <span className="tabular">Starts at 100</span>
            </div>
            <ul className="mt-2 divide-y divide-border rounded-md border border-border">
              {report.deductions.map((d) => (
                <li key={d.id} className="flex items-start gap-3 px-3 py-2">
                  {d.applied ? (
                    <TriangleAlert className="mt-0.5 size-4 shrink-0 text-danger" />
                  ) : (
                    <Check className="mt-0.5 size-4 shrink-0 text-safe" />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="text-sm text-foreground">{d.label}</div>
                    <div className="break-words text-xs text-muted-foreground">{d.reason}</div>
                  </div>
                  <span
                    className={cn(
                      "tabular shrink-0 font-mono text-sm",
                      d.applied ? "text-danger" : "text-muted-foreground",
                    )}
                  >
                    {d.applied ? `−${d.points}` : "0"}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <PanelShell index="01" icon={Fingerprint} score={panels.url.score} delay={60} {...PANEL_META.url}>
          <CheckList checks={panels.url.checks} />
          <FactTable facts={panels.url.facts} />
        </PanelShell>
        <PanelShell index="02" icon={FileLock2} score={panels.tls.score} delay={120} {...PANEL_META.tls}>
          <CheckList checks={panels.tls.checks} />
          <FactTable facts={panels.tls.facts} />
        </PanelShell>
        <PanelShell index="03" icon={ShieldHalf} score={panels.headers.score} delay={180} {...PANEL_META.headers}>
          <CheckList checks={panels.headers.checks} />
          <FactTable facts={panels.headers.facts} />
        </PanelShell>
        <PanelShell index="04" icon={Radar} score={panels.threat.score} delay={240} {...PANEL_META.threat}>
          <ThreatLog panel={panels.threat} inspectedAt={report.inspectedAt} />
        </PanelShell>
      </div>
    </div>
  );
}

export function ReportSkeleton({ target }: { target: string }) {
  const steps = [
    "Resolving host via security DNS",
    "Negotiating TLS handshake",
    "Querying certificate transparency logs",
    "Collecting response headers",
    "Cross-checking community phishing feed",
  ];
  return (
    <div className="space-y-4" aria-live="polite">
      <section className="relative overflow-hidden rounded-lg border border-border bg-card p-6">
        <div className="absolute inset-x-0 top-0 h-px overflow-hidden">
          <div className="animate-scan h-px w-1/3 bg-primary" />
        </div>
        <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
          Inspecting
        </div>
        <div className="mt-1 break-all font-mono text-2xl font-semibold text-foreground">{target}</div>
        <ol className="mt-5 space-y-2 font-mono text-xs text-muted-foreground">
          {steps.map((s, i) => (
            <li
              key={s}
              className="animate-rise flex items-center gap-3"
              style={{ animationDelay: `${i * 180}ms` }}
            >
              <span className="size-1.5 animate-pulse rounded-full bg-primary" />
              {s}
            </li>
          ))}
        </ol>
      </section>
      <div className="grid gap-4 lg:grid-cols-2">
        {ORDER.map((k) => (
          <div key={k} className="h-64 animate-pulse rounded-lg border border-border bg-card" />
        ))}
      </div>
    </div>
  );
}
