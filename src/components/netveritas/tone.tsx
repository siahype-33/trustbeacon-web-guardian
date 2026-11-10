import { Check, Info, TriangleAlert, X } from "lucide-react";
import type { CheckStatus, Verdict } from "@/lib/inspect/types";
import { cn } from "@/lib/utils";

export type Tone = "safe" | "warn" | "danger";

export function toneForScore(score: number): Tone {
  if (score >= 75) return "safe";
  if (score >= 50) return "warn";
  return "danger";
}

export const toneFromVerdict: Record<Verdict, Tone> = {
  safe: "safe",
  caution: "warn",
  danger: "danger",
};

export const toneText: Record<Tone, string> = {
  safe: "text-safe",
  warn: "text-warn",
  danger: "text-danger",
};

export const toneStroke: Record<Tone, string> = {
  safe: "stroke-safe",
  warn: "stroke-warn",
  danger: "stroke-danger",
};

export const toneBar: Record<Tone, string> = {
  safe: "bg-safe",
  warn: "bg-warn",
  danger: "bg-danger",
};

export const toneChip: Record<Tone, string> = {
  safe: "border-safe/30 bg-safe/10 text-safe",
  warn: "border-warn/30 bg-warn/10 text-warn",
  danger: "border-danger/30 bg-danger/10 text-danger",
};

const statusStyles: Record<CheckStatus, { cls: string; Icon: typeof Check; label: string }> = {
  pass: { cls: "border-safe/30 bg-safe/10 text-safe", Icon: Check, label: "Pass" },
  warn: { cls: "border-warn/30 bg-warn/10 text-warn", Icon: TriangleAlert, label: "Warning" },
  fail: { cls: "border-danger/30 bg-danger/10 text-danger", Icon: X, label: "Fail" },
  info: { cls: "border-border bg-muted text-muted-foreground", Icon: Info, label: "Info" },
};

export function StatusIcon({ status, className }: { status: CheckStatus; className?: string }) {
  const { cls, Icon, label } = statusStyles[status];
  return (
    <span
      aria-label={label}
      className={cn(
        "inline-flex size-6 shrink-0 items-center justify-center rounded-md border",
        cls,
        className,
      )}
    >
      <Icon className="size-3.5" strokeWidth={2.5} />
    </span>
  );
}

export const statusWord: Record<CheckStatus, string> = {
  pass: "CLEAR",
  warn: "WARN",
  fail: "FLAGGED",
  info: "N/A",
};

export const statusText: Record<CheckStatus, string> = {
  pass: "text-safe",
  warn: "text-warn",
  fail: "text-danger",
  info: "text-muted-foreground",
};
