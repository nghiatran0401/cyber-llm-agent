import { describe, expect, it } from "vitest";

import { deriveMonitorState } from "@/lib/monitor-state";
import { StepTrace } from "@/lib/types";

function asTrace(step: string): StepTrace {
  return {
    step,
    what_it_does: `${step} details`,
    prompt_preview: "",
    input_summary: "",
    output_summary: "",
  };
}

describe("deriveMonitorState", () => {
  it("counts required G1 steps (matches API StepTrace keys)", () => {
    const trace = [
      asTrace("SafetyCheck"),
      asTrace("ModelRouting"),
      asTrace("Analysis"),
      asTrace("OutputReview"),
      asTrace("ExecutionSummary"),
    ];

    const state = deriveMonitorState({
      mode: "g1",
      trace,
      currentStep: "",
      runStatus: "completed",
    });

    expect(state.requiredCompletedCount).toBe(state.requiredTotalCount);
    expect(state.percentage).toBe(100);
    expect(state.phases.every((phase) => phase.status === "completed")).toBe(true);
  });

  it("marks incomplete phases as skipped on completed run", () => {
    const trace = [asTrace("SafetyCheck")];
    const state = deriveMonitorState({
      mode: "g1",
      trace,
      currentStep: "",
      runStatus: "completed",
    });

    expect(state.phases[0].status).toBe("skipped");
    expect(state.phases[1].status).toBe("skipped");
    expect(state.phases[2].status).toBe("skipped");
  });

  it("captures unknown backend steps for diagnostics", () => {
    const trace = [asTrace("LogAnalyzer"), asTrace("UnknownStepV2")];
    const state = deriveMonitorState({
      mode: "g2",
      trace,
      currentStep: "UnknownStepV2",
      runStatus: "running",
    });

    expect(state.unknownSteps).toEqual(["UnknownStepV2"]);
  });
});
