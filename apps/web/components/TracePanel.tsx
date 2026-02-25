"use client";

import { StepTrace } from "@/lib/types";

type TracePanelProps = {
  trace: StepTrace[];
};

export function TracePanel({ trace }: TracePanelProps) {
  if (!trace.length) {
    return <p className="subtle-text">No trace available.</p>;
  }

  return (
    <div className="space-y-2">
      {trace.map((step, index) => (
        <details
          key={`${step.step}-${index}`}
          className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950/70"
          open={index === 0}
        >
          <summary className="cursor-pointer text-sm font-medium text-slate-800 dark:text-slate-100">
            {index + 1}. {step.step}
          </summary>
          <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">{step.what_it_does}</p>
          <div className="mt-3 space-y-2 text-xs">
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Prompt preview</p>
              <pre className="code-block">{step.prompt_preview}</pre>
            </div>
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Input summary</p>
              <pre className="code-block">{step.input_summary}</pre>
            </div>
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Output summary</p>
              <pre className="code-block">{step.output_summary}</pre>
            </div>
          </div>
        </details>
      ))}
    </div>
  );
}
