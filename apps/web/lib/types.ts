export type AgentMode = "g1" | "g2";

export type StopReason = "completed" | "blocked" | "needs_human" | "budget_exceeded" | "error";

export type RubricLabel = "strong" | "acceptable" | "weak" | "disabled" | "n/a";

export interface ErrorInfo {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ResponseMeta {
  request_id: string;
  timestamp: string;
  api_version: "v1";
  mode?: AgentMode;
  model?: string;
  duration_ms?: number;
  stop_reason?: StopReason;
  steps_used?: number;
  prompt_version?: string;
  rubric_score?: number;
  rubric_label?: RubricLabel;
  run_id?: string;
  input_tokens_est?: number;
  output_tokens_est?: number;
  total_tokens_est?: number;
  cost_est_usd?: number;
  tool_calls?: number;
  tool_success?: number;
  tool_fail?: number;
}

export interface StepTrace {
  step: string;
  what_it_does: string;
  prompt_preview: string;
  input_summary: string;
  output_summary: string;
  run_id?: string;
  step_id?: string;
  tool_call_id?: string;
}

export interface ApiResponse<T = unknown> {
  ok: boolean;
  result: T;
  trace: StepTrace[];
  meta: ResponseMeta;
  error?: ErrorInfo | null;
}

export interface G2Result {
  log_analysis: string;
  threat_prediction: string;
  incident_response: string;
  final_report: string;
  cti_evidence?: string;
  assumptions?: string[];
}

export type SandboxEvent = Record<string, unknown>;

export type WorkspaceStreamEvent =
  | { type: "trace"; step: StepTrace }
  | { type: "final"; result: string; meta: ResponseMeta }
  | { type: "error"; error: ErrorInfo }
  | { type: "done" }
  | { type: "heartbeat" };

export interface LiveLogEnvelope {
  source: string;
  path: string;
  items: Array<Record<string, unknown>>;
}

export interface RecentDetectionItem {
  timestamp?: string;
  run_id?: string | null;
  endpoint?: string;
  mode?: AgentMode | null;
  success?: boolean;
  stop_reason?: StopReason | string;
  duration_ms?: number;
  total_tokens_est?: number;
  tool_calls?: number;
  tool_fail?: number;
}

export interface RecentDetectionEnvelope {
  items: RecentDetectionItem[];
  count: number;
}

export interface OwaspMitreMapping {
  owasp: string;
  mitre: string[];
}

export interface LabScenario {
  id: string;
  name: string;
  endpoint: string;
  method: "GET" | "POST";
  samplePayload: string;
  riskHint: string;
}

export interface LabSystemLogEntry {
  timestamp: string;
  requestId: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
  ip: string;
  userAgent: string;
  attackDetected?: boolean;
  scenarioId?: string;
  riskHint?: string;
  payloadSnippet?: string;
  message?: string;
  owaspCategory?: string;
}

export interface LabSimulationResult {
  scenarioId: string;
  scenarioName: string;
  endpoint: string;
  method: string;
  expectedRiskHint: string;
  owaspCategory: string;
  mitreTechniques: string[];
  status: number;
  responsePreview: string;
}
