"use client";

import { StepTrace } from "@/lib/types";

type TracePanelProps = {
  trace: StepTrace[];
};

export function TracePanel({ trace }: TracePanelProps) {
  if (!trace.length) {
    return <p className="text-sm text-slate-600 dark:text-slate-400">No trace available.</p>;
  }

  return (
    <div className="space-y-2">
      {trace.map((step, index) => (
        <details
          key={`${step.step}-${index}`}
          className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 dark:border-slate-800 dark:bg-slate-950/70"
          open={index === 0}
        >
          <summary className="cursor-pointer text-sm font-medium">
            {index + 1}. {step.step}
          </summary>
          <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">{step.what_it_does}</p>
          <div className="mt-3 space-y-2 text-xs">
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Prompt preview</p>
              <pre className="overflow-x-auto rounded-md bg-white p-2 text-slate-700 dark:bg-slate-900 dark:text-slate-300">{step.prompt_preview}</pre>
            </div>
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Input summary</p>
              <pre className="overflow-x-auto rounded-md bg-white p-2 text-slate-700 dark:bg-slate-900 dark:text-slate-300">{step.input_summary}</pre>
            </div>
            <div>
              <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Output summary</p>
              <pre className="overflow-x-auto rounded-md bg-white p-2 text-slate-700 dark:bg-slate-900 dark:text-slate-300">{step.output_summary}</pre>
            </div>
          </div>
        </details>
      ))}
    </div>
  );
}
