"use client";

import { AgentMode } from "@/lib/types";
import { MonitorDerivedState, PhaseStatus } from "@/lib/monitor-state";

function getPhaseBadge(status: PhaseStatus): { label: string; className: string } {
  if (status === "completed") {
    return {
      label: "Done",
      className: "status-badge bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300",
    };
  }
  if (status === "running") {
    return {
      label: "Active",
      className: "status-badge bg-cyan-100 text-cyan-800 dark:bg-cyan-950/50 dark:text-cyan-200",
    };
  }
  if (status === "error") {
    return {
      label: "Error",
      className: "status-badge bg-rose-100 text-rose-800 dark:bg-rose-950/50 dark:text-rose-300",
    };
  }
  if (status === "skipped") {
    return {
      label: "Stopped early",
      className: "status-badge bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300",
    };
  }
  return {
    label: "Waiting",
    className: "status-badge bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  };
}

const PHASE_INDEX: Record<string, number> = { collect: 1, reason: 2, respond: 3 };

type LiveMonitorPanelProps = {
  mode: AgentMode;
  monitor: MonitorDerivedState;
  liveStatus: string;
  runInFlight: boolean;
  phaseLayout?: "stack" | "grid";
  heading?: "h2" | "h3";
  className?: string;
  /** When false, omit the cyan “Current activity” box (e.g. sandbox shows status next to the run button). */
  showActivityCallout?: boolean;
};

export function LiveMonitorPanel({
  mode,
  monitor,
  liveStatus,
  runInFlight,
  phaseLayout = "stack",
  heading = "h2",
  className = "",
  showActivityCallout = true,
}: LiveMonitorPanelProps) {
  const HeadingTag = heading;
  const subtitle =
    mode === "g1"
      ? "Same milestones as Technical Trace: five steps, shown here in three phases."
      : "Multi-agent pipeline phases; use Technical Trace below for each step.";

  const phaseListClass =
    phaseLayout === "grid" ? "grid gap-2 md:grid-cols-3" : "space-y-2";

  return (
    <div className={className}>
      <HeadingTag className={heading === "h2" ? "mb-1 text-base font-semibold" : "section-title mb-1"}>
        Live Monitor
      </HeadingTag>
      <p className="mb-3 text-xs text-slate-600 dark:text-slate-400">{subtitle}</p>

      <div className="mb-3 rounded-md border border-slate-300 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-950/60">
        <div className="mb-2 flex items-center justify-between text-xs">
          <p className="font-medium text-slate-700 dark:text-slate-300">Trace milestones</p>
          <p className="tabular-nums text-slate-600 dark:text-slate-400">
            {monitor.requiredCompletedCount}/{monitor.requiredTotalCount} complete
          </p>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-slate-300 dark:bg-slate-800">
          <div
            className="h-full rounded-full bg-cyan-500 transition-all"
            style={{
              width: `${Math.min(100, Math.max(monitor.percentage, runInFlight ? 6 : 0))}%`,
            }}
          />
        </div>
      </div>

      <div className={phaseListClass}>
        {monitor.phases.map((phase) => {
          const badge = getPhaseBadge(phase.status);
          const n = PHASE_INDEX[phase.id] ?? 0;
          return (
            <div
              key={phase.id}
              className={`rounded-md border p-3 ${
                phase.status === "completed"
                  ? "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30"
                  : phase.status === "running"
                    ? "border-cyan-300 bg-cyan-50 dark:border-cyan-900 dark:bg-cyan-950/30"
                    : phase.status === "error"
                      ? "border-rose-300 bg-rose-50 dark:border-rose-900 dark:bg-rose-950/30"
                      : phase.status === "skipped"
                        ? "border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/30"
                        : "border-slate-300 bg-white dark:border-slate-700 dark:bg-slate-900"
              }`}
            >
              <div className="mb-1 flex items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="inline-flex h-6 min-w-[1.5rem] shrink-0 items-center justify-center rounded-full bg-slate-200 text-[11px] font-medium text-slate-700 dark:bg-slate-700 dark:text-slate-200">
                    {n}
                  </span>
                  <p className="truncate text-xs font-semibold text-slate-800 dark:text-slate-100">{phase.title}</p>
                </div>
                <span className={badge.className}>{badge.label}</span>
              </div>
              <p className="text-[11px] leading-snug text-slate-600 dark:text-slate-400">{phase.desc}</p>
              <p className="mt-1.5 text-[10px] text-slate-500 dark:text-slate-500">
                Phase steps: {phase.doneCount}/{phase.total}
              </p>
            </div>
          );
        })}
      </div>

      {showActivityCallout ? (
        <div className="mt-3 rounded-md border border-cyan-300 bg-cyan-50 p-3 text-xs text-cyan-900 dark:border-cyan-800 dark:bg-cyan-950/30 dark:text-cyan-100">
          <p className="font-semibold">Current activity</p>
          <p className="mt-1">{liveStatus}</p>
        </div>
      ) : null}

      {monitor.unknownSteps.length > 0 ? (
        <p className="mt-2 rounded-md border border-amber-300 bg-amber-50 px-2 py-1.5 text-[11px] text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
          Unrecognized trace steps (older client?): {monitor.unknownSteps.join(", ")}
        </p>
      ) : null}
    </div>
  );
}
