import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import type { Check, Fact, PanelResult } from "@/lib/inspect/types";
import { cn } from "@/lib/utils";
import { StatusIcon, statusText, statusWord, toneChip, toneForScore } from "./tone";

export function ScoreChip({ score }: { score: number }) {
  return (
    <span
      className={cn(
        "tabular inline-flex items-baseline gap-0.5 rounded-md border px-2 py-1 font-mono text-sm font-semibold",
        toneChip[toneForScore(score)],
      )}
    >
      {score}
      <span className="text-[10px] font-normal opacity-70">/100</span>
    </span>
  );
}

export function PanelShell({
  index,
  title,
  subtitle,
  icon: Icon,
  score,
  children,
  delay = 0,
}: {
  index: string;
  title: string;
  subtitle: string;
  icon: LucideIcon;
  score: number;
  children: ReactNode;
  delay?: number;
}) {
  return (
    <section
      className="animate-rise flex flex-col rounded-lg border border-border bg-card"
      style={{ animationDelay: `${delay}ms` }}
    >
      <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex size-8 items-center justify-center rounded-md border border-border bg-inset text-muted-foreground">
            <Icon className="size-4" />
          </span>
          <div>
            <div className="font-mono text-[11px] tracking-[0.18em] text-muted-foreground">
              {index}
            </div>
            <h2 className="text-base font-semibold leading-tight text-foreground">{title}</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
          </div>
        </div>
        <ScoreChip score={score} />
      </header>
      <div className="flex flex-1 flex-col">{children}</div>
    </section>
  );
}

export function CheckList({ checks }: { checks: Check[] }) {
  return (
    <ul className="divide-y divide-border">
      {checks.map((c) => (
        <li key={c.id} className="flex gap-3 px-5 py-3">
          <StatusIcon status={c.status} className="mt-0.5" />
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground">{c.label}</div>
            <p className="text-sm leading-snug text-muted-foreground">{c.detail}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function FactTable({ facts }: { facts: Fact[] }) {
  if (!facts.length) return null;
  return (
    <dl className="mt-auto grid grid-cols-[minmax(0,9rem)_1fr] gap-x-4 gap-y-1.5 border-t border-border bg-inset px-5 py-4 font-mono text-xs">
      {facts.map((f) => (
        <div key={f.label} className="contents">
          <dt className="truncate text-muted-foreground">{f.label}</dt>
          <dd className="break-all text-foreground">{f.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ThreatLog({ panel, inspectedAt }: { panel: PanelResult; inspectedAt: string }) {
  const time = new Date(inspectedAt).toISOString().slice(11, 19);
  return (
    <div className="flex flex-1 flex-col">
      <ol className="m-4 flex-1 space-y-px overflow-hidden rounded-md border border-border bg-inset font-mono text-xs">
        {panel.checks.map((c) => (
          <li key={c.id} className="border-b border-border px-4 py-3 last:border-b-0">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="text-muted-foreground">{time}Z</span>
              <span className="text-foreground">{c.source}</span>
              <span className={cn("ml-auto font-semibold tracking-wider", statusText[c.status])}>
                {statusWord[c.status]}
              </span>
            </div>
            <p className="mt-1.5 font-sans text-sm leading-snug text-muted-foreground">
              {c.detail}
            </p>
          </li>
        ))}
      </ol>
      <p className="px-5 pb-4 text-xs text-muted-foreground">
        Live lookups against shared threat intelligence. A clean log means no source currently
        flags this host — not a guarantee of safety.
      </p>
    </div>
  );
}
