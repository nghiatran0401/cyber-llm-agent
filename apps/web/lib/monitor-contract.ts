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
    desc: "Prompt version, optional safety pass, and log analysis.",
  },
  {
    id: "reason",
    title: "Deep dive",
    desc: "Planner, threat prediction, worker tasks, and run budgets.",
  },
  {
    id: "respond",
    title: "Wrap-up",
    desc: "Responder, verifier, orchestrator, policy, and rubric.",
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
    key: "PromptVersion",
    title: "Prompt Version",
    whatItDoes: "Loads prompt template version metadata.",
    phaseId: "collect",
  },
  {
    key: "SafetyGuard",
    title: "Safety Guard",
    whatItDoes: "Checks prompt-injection and input safety signals.",
    phaseId: "collect",
    required: false,
  },
  {
    key: "LogAnalyzer",
    title: "Log Analyzer",
    whatItDoes: "Extracts suspicious patterns from logs.",
    phaseId: "collect",
  },
  {
    key: "WorkerPlanner",
    title: "Worker Planner",
    whatItDoes: "Plans worker tasks for deeper investigation.",
    phaseId: "reason",
  },
  {
    key: "ThreatPredictor",
    title: "Threat Predictor",
    whatItDoes: "Predicts attacker behavior and likely impact.",
    phaseId: "reason",
  },
  {
    key: "RunControl",
    title: "Run Control",
    whatItDoes: "Tracks shared execution budgets and stop conditions.",
    phaseId: "reason",
  },
  {
    key: "WorkerTask",
    title: "Worker Task",
    whatItDoes: "Executes worker tasks to gather more evidence.",
    phaseId: "reason",
  },
  {
    key: "IncidentResponder",
    title: "Incident Responder",
    whatItDoes: "Drafts containment and response actions.",
    phaseId: "respond",
  },
  {
    key: "Verifier",
    title: "Verifier",
    whatItDoes: "Checks response quality and consistency.",
    phaseId: "respond",
  },
  {
    key: "IncidentResponderRetry",
    title: "Responder Retry",
    whatItDoes: "Retries response generation when verification fails.",
    phaseId: "respond",
    required: false,
  },
  {
    key: "Orchestrator",
    title: "Orchestrator",
    whatItDoes: "Compiles final report from worker outputs.",
    phaseId: "respond",
  },
  {
    key: "PolicyGuard",
    title: "Policy Guard",
    whatItDoes: "Applies output safety policy rules.",
    phaseId: "respond",
  },
  {
    key: "RubricEvaluation",
    title: "Rubric Evaluation",
    whatItDoes: "Scores final report quality.",
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
