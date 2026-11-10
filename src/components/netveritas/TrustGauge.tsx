import { useEffect, useState } from "react";
import type { Verdict } from "@/lib/inspect/types";
import { cn } from "@/lib/utils";
import { toneFromVerdict, toneStroke, toneText } from "./tone";

const verdictLabel: Record<Verdict, string> = {
  safe: "Trusted",
  caution: "Use caution",
  danger: "High risk",
};

export function TrustGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  const tone = toneFromVerdict[verdict];
  const r = 84;
  const c = 2 * Math.PI * r;
  const arc = c * 0.75;
  const offset = arc - (arc * shown) / 100;

  return (
    <div className="relative mx-auto size-[200px]">
      <svg viewBox="0 0 200 200" className="size-full rotate-[135deg]" aria-hidden>
        <circle
          cx="100"
          cy="100"
          r={r}
          fill="none"
          strokeWidth="12"
          strokeLinecap="round"
          className="stroke-muted"
          strokeDasharray={`${arc} ${c}`}
        />
        <circle
          cx="100"
          cy="100"
          r={r}
          fill="none"
          strokeWidth="12"
          strokeLinecap="round"
          className={cn(toneStroke[tone], "transition-[stroke-dashoffset] duration-1000 ease-out")}
          strokeDasharray={`${arc} ${c}`}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
          Trust rating
        </span>
        <span className="tabular mt-1 font-mono text-6xl font-semibold leading-none text-foreground">
          {score}
        </span>
        <span className="mt-1 font-mono text-xs text-muted-foreground">/ 100</span>
      </div>
      <div
        className={cn(
          "absolute inset-x-0 bottom-1 text-center text-sm font-semibold uppercase tracking-wider",
          toneText[tone],
        )}
      >
        {verdictLabel[verdict]}
      </div>
    </div>
  );
}
