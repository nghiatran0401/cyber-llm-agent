/** Short UI labels for trace steps — keep in sync with Technical Trace panel. */
export const TRACE_STEP_LABEL: Record<string, string> = {
  SafetyCheck: "Safety",
  ModelRouting: "Model",
  Analysis: "Analysis",
  OutputReview: "Review",
  ExecutionSummary: "Run summary",
};

export function traceStepLabel(stepKey: string): string {
  return TRACE_STEP_LABEL[stepKey] ?? stepKey.replace(/([A-Z])/g, " $1").trim();
}
