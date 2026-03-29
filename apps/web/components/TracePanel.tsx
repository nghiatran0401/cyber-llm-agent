"use client";

import { StepTrace } from "@/lib/types";

type TracePanelProps = {
  trace: StepTrace[];
};

type SummaryPairs = Record<string, string>;

function parseSummaryPairs(text: string): SummaryPairs {
  return String(text || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce<SummaryPairs>((acc, part) => {
      const [key, ...rest] = part.split("=");
      if (!key || !rest.length) {
        return acc;
      }
      acc[key.trim()] = rest.join("=").trim();
      return acc;
    }, {});
}

function prettyLabel(raw: string): string {
  return raw
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderSummaryGrid(summary: SummaryPairs) {
  const entries = Object.entries(summary);
  if (!entries.length) {
    return null;
  }

  return (
    <div className="mt-3 grid gap-2 md:grid-cols-2">
      {entries.map(([key, value]) => (
        <div
          key={key}
          className="rounded-md border border-slate-200 bg-white/80 px-3 py-2 text-[11px] text-slate-700 dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-200"
        >
          <p className="font-semibold text-slate-600 dark:text-slate-300">{prettyLabel(key)}</p>
          <p className="mt-1 break-all">{value}</p>
        </div>
      ))}
    </div>
  );
}

function renderMetadata(step: StepTrace) {
  if (!step.run_id && !step.step_id && !step.tool_call_id) {
    return null;
  }

  return (
    <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-500 dark:text-slate-400">
      {step.run_id ? <span className="rounded-full bg-slate-200 px-2 py-1 dark:bg-slate-800">Run: {step.run_id}</span> : null}
      {step.step_id ? <span className="rounded-full bg-slate-200 px-2 py-1 dark:bg-slate-800">Step: {step.step_id}</span> : null}
      {step.tool_call_id ? <span className="rounded-full bg-cyan-100 px-2 py-1 text-cyan-900 dark:bg-cyan-950/50 dark:text-cyan-100">Tool Call: {step.tool_call_id}</span> : null}
    </div>
  );
}

export function TracePanel({ trace }: TracePanelProps) {
  if (!trace.length) {
    return <p className="subtle-text">No trace available.</p>;
  }

  return (
    <div className="space-y-2">
      {trace.map((step, index) => {
        const parsedInputSummary = parseSummaryPairs(step.input_summary);
        const parsedOutputSummary = parseSummaryPairs(step.output_summary);
        const isStructuredSummaryStep = step.step === "RunControl" || step.step === "PolicyGuard" || step.step === "RubricEvaluation";

        return (
          <details
            key={`${step.step}-${index}`}
            className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950/70"
            open={index === 0}
          >
            <summary className="cursor-pointer text-sm font-medium text-slate-800 dark:text-slate-100">
              {index + 1}. {step.step}
            </summary>
            <p className="mt-2 text-xs text-slate-600 dark:text-slate-400">{step.what_it_does}</p>
            {renderMetadata(step)}

            <div className="mt-3 space-y-2 text-xs">
              <div>
                <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Prompt preview</p>
                <pre className="code-block">{step.prompt_preview}</pre>
              </div>

              {isStructuredSummaryStep ? (
                <>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Input summary</p>
                    {renderSummaryGrid(parsedInputSummary) ?? <pre className="code-block">{step.input_summary}</pre>}
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Output summary</p>
                    {renderSummaryGrid(parsedOutputSummary) ?? <pre className="code-block">{step.output_summary}</pre>}
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Input summary</p>
                    <pre className="code-block">{step.input_summary}</pre>
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Output summary</p>
                    <pre className="code-block">{step.output_summary}</pre>
                  </div>
                </>
              )}
            </div>
          </details>
        );
      })}
    </div>
  );
}
