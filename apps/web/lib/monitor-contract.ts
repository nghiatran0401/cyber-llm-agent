import { AgentMode } from "@/lib/types";

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

const PHASES: MonitorPhaseDefinition[] = [
  {
    id: "collect",
    title: "1) Understand Input",
    desc: "Collect and normalize evidence before analysis starts.",
  },
  {
    id: "reason",
    title: "2) Reason About Risk",
    desc: "Evaluate risk signals and decide on response strategy.",
  },
  {
    id: "respond",
    title: "3) Build Response Plan",
    desc: "Produce final recommendations and quality guard checks.",
  },
];

const G1_STEPS: MonitorStepDefinition[] = [
  {
    key: "InputPreparation",
    title: "Input Preparation",
    whatItDoes: "Validates and sanitizes the request.",
    phaseId: "collect",
  },
  {
    key: "RoutingPolicy",
    title: "Routing Policy",
    whatItDoes: "Selects model strategy for this task.",
    phaseId: "collect",
  },
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
    key: "SingleAgentExecution",
    title: "Single Agent Execution",
    whatItDoes: "Runs analysis loop and tool usage.",
    phaseId: "reason",
  },
  {
    key: "RunControl",
    title: "Run Control",
    whatItDoes: "Applies execution bounds and stop reason tracking.",
    phaseId: "reason",
  },
  {
    key: "StructuredOutput",
    title: "Structured Output",
    whatItDoes: "Builds evidence-first response schema.",
    phaseId: "respond",
  },
  {
    key: "CriticReview",
    title: "Critic Review",
    whatItDoes: "Checks report quality and evidence coverage.",
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
    phases: PHASES,
    steps: G1_STEPS,
  },
  g2: {
    phases: PHASES,
    steps: G2_STEPS,
  },
};

export function getMonitorContract(mode: AgentMode): MonitorContract {
  return MONITOR_CONTRACT_BY_MODE[mode];
}
