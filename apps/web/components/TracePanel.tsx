"use client";

import { traceStepLabel } from "@/lib/trace-labels";
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
    <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-slate-400 dark:text-slate-500">
      {step.run_id ? <span className="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">Run {step.run_id.slice(0, 8)}…</span> : null}
      {step.step_id ? <span className="rounded bg-slate-100 px-1.5 py-0.5 dark:bg-slate-800">Step {step.step_id.slice(-8)}</span> : null}
      {step.tool_call_id ? (
        <span className="rounded bg-cyan-100 px-1.5 py-0.5 text-cyan-900 dark:bg-cyan-950/50 dark:text-cyan-100">Tool</span>
      ) : null}
    </div>
  );
}

function stepLabel(step: StepTrace): string {
  return traceStepLabel(step.step);
}

export function TracePanel({ trace }: TracePanelProps) {
  if (!trace.length) {
    return <p className="subtle-text">No trace available.</p>;
  }

  const defaultOpenIndex = trace.findIndex((s) => s.step === "Analysis");
  const openIndex = defaultOpenIndex >= 0 ? defaultOpenIndex : trace.length - 1;

  return (
    <div className="space-y-2">
      {trace.map((step, index) => {
        const parsedInputSummary = parseSummaryPairs(step.input_summary);
        const parsedOutputSummary = parseSummaryPairs(step.output_summary);
        const useDetailGrid =
          step.step === "ExecutionSummary" ||
          step.step === "OutputReview" ||
          step.step === "RunControl" ||
          step.step === "PolicyGuard" ||
          step.step === "RubricEvaluation";
        const hasContext = Boolean(step.prompt_preview?.trim());

        return (
          <details
            key={`${step.step}-${index}`}
            className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 shadow-sm dark:border-slate-800 dark:bg-slate-950/70"
            open={index === openIndex}
          >
            <summary className="cursor-pointer list-none text-sm font-medium text-slate-800 dark:text-slate-100 [&::-webkit-details-marker]:hidden">
              <span className="mr-2 inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-slate-200 text-[11px] text-slate-700 dark:bg-slate-700 dark:text-slate-200">
                {index + 1}
              </span>
              {stepLabel(step)}
            </summary>
            <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-400">{step.what_it_does}</p>
            {renderMetadata(step)}

            <div className="mt-3 space-y-3 text-xs">
              {hasContext ? (
                <div>
                  <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Context</p>
                  <pre className="code-block text-[11px]">{step.prompt_preview}</pre>
                </div>
              ) : null}

              {useDetailGrid ? (
                <>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Details in</p>
                    {renderSummaryGrid(parsedInputSummary) ?? <pre className="code-block text-[11px]">{step.input_summary}</pre>}
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Details out</p>
                    {renderSummaryGrid(parsedOutputSummary) ?? <pre className="code-block text-[11px]">{step.output_summary}</pre>}
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">In</p>
                    <pre className="code-block text-[11px]">{step.input_summary}</pre>
                  </div>
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-500">Out</p>
                    <pre className="code-block text-[11px]">{step.output_summary}</pre>
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
