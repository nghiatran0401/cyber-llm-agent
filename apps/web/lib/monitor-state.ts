import { getMonitorContract, MonitorPhaseId } from "@/lib/monitor-contract";
import { AgentMode, StepTrace } from "@/lib/types";

export type RunStatus = "idle" | "running" | "completed" | "error";
export type PhaseStatus = "completed" | "running" | "pending" | "skipped" | "error";

export type MonitorPhaseState = {
  id: MonitorPhaseId;
  title: string;
  desc: string;
  doneCount: number;
  total: number;
  ratio: number;
  status: PhaseStatus;
  isDone: boolean;
  isActive: boolean;
};

export type MonitorDerivedState = {
  requiredCompletedCount: number;
  requiredTotalCount: number;
  percentage: number;
  phases: MonitorPhaseState[];
  unknownSteps: string[];
};

export function deriveMonitorState({
  mode,
  trace,
  currentStep,
  runStatus,
}: {
  mode: AgentMode;
  trace: StepTrace[];
  currentStep: string;
  runStatus: RunStatus;
}): MonitorDerivedState {
  const contract = getMonitorContract(mode);
  const completedStepNames = new Set(trace.map((step) => step.step));
  const knownStepNames = new Set(contract.steps.map((step) => step.key));
  const unknownStepNames = Array.from(completedStepNames).filter((step) => !knownStepNames.has(step));
  const requiredSteps = contract.steps.filter((step) => step.required !== false);
  const requiredTotalCount = requiredSteps.length;
  const requiredCompletedCount = requiredSteps.filter((step) => completedStepNames.has(step.key)).length;

  const phases = contract.phases.map((phase) => {
    const phaseAllSteps = contract.steps.filter((step) => step.phaseId === phase.id);
    const phaseRequiredSteps = phaseAllSteps.filter((step) => step.required !== false);
    const phaseRequiredTotal = phaseRequiredSteps.length;
    const doneCount = phaseRequiredSteps.filter((step) => completedStepNames.has(step.key)).length;
    const total = phaseRequiredTotal || phaseAllSteps.length || 1;
    const ratio = doneCount / total;
    const hasCurrent = phaseAllSteps.some((step) => step.key === currentStep);

    let status: PhaseStatus = "pending";
    if (ratio >= 1) {
      status = "completed";
    } else if (runStatus === "error" && (hasCurrent || doneCount > 0)) {
      status = "error";
    } else if (hasCurrent || (runStatus === "running" && doneCount > 0)) {
      status = "running";
    } else if (runStatus === "completed" && doneCount < total) {
      status = "skipped";
    }

    return {
      id: phase.id,
      title: phase.title,
      desc: phase.desc,
      doneCount,
      total,
      ratio,
      status,
      isDone: status === "completed",
      isActive: status === "running",
    };
  });

  return {
    requiredCompletedCount,
    requiredTotalCount,
    percentage: requiredTotalCount > 0 ? (requiredCompletedCount / requiredTotalCount) * 100 : 0,
    phases,
    unknownSteps: unknownStepNames,
  };
}
