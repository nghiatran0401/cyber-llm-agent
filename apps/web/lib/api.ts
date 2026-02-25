import {
  AgentMode,
  ApiResponse,
  G2Result,
  LiveLogEnvelope,
  OwaspMitreMapping,
  RecentDetectionEnvelope,
  SandboxEvent,
  WorkspaceStreamEvent,
} from "@/lib/types";

type WorkspaceStreamPayload = {
  task: "chat" | "analyze";
  mode: AgentMode;
  input: string;
  session_id?: string;
};

type StreamHandlers = {
  onEvent: (event: WorkspaceStreamEvent) => void;
};

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

function buildHeaders(init?: HeadersInit): Headers {
  const headers = new Headers(init ?? {});
  headers.set("Content-Type", "application/json");
  if (API_KEY) {
    headers.set("x-api-key", API_KEY);
  }
  return headers;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<ApiResponse<T>> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: buildHeaders(init?.headers),
    cache: "no-store",
  });

  let payload: ApiResponse<T> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<T>;
  } catch {
    // Keep payload as null to surface an explicit error below.
  }

  if (!response.ok || !payload?.ok) {
    const message = payload?.error?.message || `Request failed with status ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

function parseSseEvents(buffer: string): { events: WorkspaceStreamEvent[]; remainder: string } {
  const chunks = buffer.split("\n\n");
  const remainder = chunks.pop() ?? "";
  const events: WorkspaceStreamEvent[] = [];

  for (const chunk of chunks) {
    const dataLines = chunk
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trim())
      .filter(Boolean);

    if (dataLines.length === 0) {
      continue;
    }

    const eventPayload = dataLines.join("\n");
    try {
      const parsed = JSON.parse(eventPayload) as WorkspaceStreamEvent;
      if (parsed && typeof parsed === "object" && "type" in parsed) {
        events.push(parsed);
      }
    } catch {
      // Ignore malformed chunk and continue parsing stream.
    }
  }
  return { events, remainder };
}

export async function streamWorkspace(payload: WorkspaceStreamPayload, handlers: StreamHandlers): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/v1/workspace/stream`, {
    method: "POST",
    headers: buildHeaders({
      Accept: "text/event-stream",
    }),
    body: JSON.stringify(payload),
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to start stream (${response.status})`);
  }
  if (!response.body) {
    throw new Error("Streaming is not supported in this browser.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let finished = false;

  while (!finished) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    const { events, remainder } = parseSseEvents(buffer);
    buffer = remainder;

    for (const event of events) {
      handlers.onEvent(event);
      if (event.type === "done") {
        finished = true;
        break;
      }
    }
  }
}

export async function analyze(mode: AgentMode, input: string) {
  if (mode === "g1") {
    return requestJson<string>("/api/v1/analyze/g1", {
      method: "POST",
      body: JSON.stringify({ input, include_trace: true }),
    });
  }
  return requestJson<G2Result>("/api/v1/analyze/g2", {
    method: "POST",
    body: JSON.stringify({ input, include_trace: true }),
  });
}

export async function chat(mode: AgentMode, input: string) {
  return requestJson<string>("/api/v1/chat", {
    method: "POST",
    body: JSON.stringify({ input, mode, include_trace: true }),
  });
}

export async function getSandboxScenarios(): Promise<ApiResponse<string[]>> {
  return requestJson<string[]>("/api/v1/sandbox/scenarios", { method: "GET" });
}

export async function simulateSandboxEvent(payload: {
  scenario: string;
  vulnerable_mode: boolean;
  source_ip: string;
  append_to_live_log: boolean;
}): Promise<ApiResponse<SandboxEvent>> {
  return requestJson<SandboxEvent>("/api/v1/sandbox/simulate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function analyzeSandboxEvent(payload: {
  event: SandboxEvent;
  mode: AgentMode;
  session_id?: string;
  include_trace?: boolean;
}): Promise<ApiResponse<string | G2Result>> {
  return requestJson<string | G2Result>("/api/v1/sandbox/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getLiveLog(params?: {
  source?: "live_web_logs" | "vuln_lab_events" | "vuln_lab_detections";
  tail?: number;
}): Promise<ApiResponse<LiveLogEnvelope>> {
  const source = params?.source || "vuln_lab_events";
  const tail = params?.tail ?? 50;
  return requestJson<LiveLogEnvelope>(`/api/v1/sandbox/live-log?source=${source}&tail=${tail}`, {
    method: "GET",
  });
}

export async function getRecentDetections(limit = 25): Promise<ApiResponse<RecentDetectionEnvelope>> {
  return requestJson<RecentDetectionEnvelope>(`/api/v1/detections/recent?limit=${limit}`, {
    method: "GET",
  });
}

export async function getOwaspMitreMap(): Promise<ApiResponse<Record<string, OwaspMitreMapping>>> {
  return requestJson<Record<string, OwaspMitreMapping>>("/api/v1/knowledge/owasp-mitre-map", {
    method: "GET",
  });
}
