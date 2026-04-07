import { AgentMode } from "@/lib/types";
import { TRACE_STEP_LABEL } from "@/lib/trace-labels";

export type MonitorPhaseId = "collect" | "reason" | "respond";

export type MonitorStepDefinition = {
  key: string;
  title: string;
  whatItDoes: string;
  phaseId: MonitorPhaseId;
  required?: boolean;
};

export type MonitorPhaseDefinition = {
  id: MonitorPhaseId;
  title: string;
  desc: string;
};

export type MonitorContract = {
  phases: MonitorPhaseDefinition[];
  steps: MonitorStepDefinition[];
};

const G1_PHASES: MonitorPhaseDefinition[] = [
  {
    id: "collect",
    title: "Safety & model",
    desc: "Input safety checks and model selection (Technical Trace: Safety, Model).",
  },
  {
    id: "reason",
    title: "Analysis",
    desc: "Agent loop and tools (Technical Trace: Analysis).",
  },
  {
    id: "respond",
    title: "Review & run summary",
    desc: "Critic, policy, and run stats (Technical Trace: Review, Run summary).",
  },
];

const G2_PHASES: MonitorPhaseDefinition[] = [
  {
    id: "collect",
    title: "Intake",
    desc: "Prompt safety checks and model routing before multi-agent execution.",
  },
  {
    id: "reason",
    title: "Deep dive",
    desc: "Runs the multi-agent analysis pipeline.",
  },
  {
    id: "respond",
    title: "Wrap-up",
    desc: "Output review and execution summary (budgets, stop reason).",
  },
];

const G1_STEPS: MonitorStepDefinition[] = [
  {
    key: "SafetyCheck",
    title: TRACE_STEP_LABEL.SafetyCheck,
    whatItDoes: "Prompt-injection and unsafe-input checks.",
    phaseId: "collect",
  },
  {
    key: "ModelRouting",
    title: TRACE_STEP_LABEL.ModelRouting,
    whatItDoes: "Selects fast vs strong model for this request.",
    phaseId: "collect",
  },
  {
    key: "Analysis",
    title: TRACE_STEP_LABEL.Analysis,
    whatItDoes: "Agent execution with tools and template-backed prompt.",
    phaseId: "reason",
  },
  {
    key: "OutputReview",
    title: TRACE_STEP_LABEL.OutputReview,
    whatItDoes: "Critic and output policy outcome.",
    phaseId: "respond",
  },
  {
    key: "ExecutionSummary",
    title: TRACE_STEP_LABEL.ExecutionSummary,
    whatItDoes: "Steps, tools, budgets, and stop reason.",
    phaseId: "respond",
  },
];

const G2_STEPS: MonitorStepDefinition[] = [
  {
    key: "SafetyCheck",
    title: TRACE_STEP_LABEL.SafetyCheck,
    whatItDoes: "Prompt-injection and unsafe-input checks.",
    phaseId: "collect",
  },
  {
    key: "ModelRouting",
    title: TRACE_STEP_LABEL.ModelRouting,
    whatItDoes: "Selects fast vs strong model for this request.",
    phaseId: "collect",
  },
  {
    key: "Analysis",
    title: TRACE_STEP_LABEL.Analysis,
    whatItDoes: "Runs the multi-agent workflow and composes the report.",
    phaseId: "reason",
  },
  {
    key: "OutputReview",
    title: TRACE_STEP_LABEL.OutputReview,
    whatItDoes: "Validates evidence coverage and safety policy outcome.",
    phaseId: "respond",
  },
  {
    key: "ExecutionSummary",
    title: TRACE_STEP_LABEL.ExecutionSummary,
    whatItDoes: "Steps, tools, budgets, and stop reason.",
    phaseId: "respond",
  },
];

const MONITOR_CONTRACT_BY_MODE: Record<AgentMode, MonitorContract> = {
  g1: {
    phases: G1_PHASES,
    steps: G1_STEPS,
  },
  g2: {
    phases: G2_PHASES,
    steps: G2_STEPS,
  },
};

export function getMonitorContract(mode: AgentMode): MonitorContract {
  return MONITOR_CONTRACT_BY_MODE[mode];
}
