"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { TracePanel } from "@/components/TracePanel";
import {
  getLabScenarios,
  getLabSystemLogs,
  getLiveLog,
  getOwaspMitreMap,
  getRecentDetections,
  simulateLabScenario,
  streamWorkspace,
} from "@/lib/api";
import { deriveMonitorState, PhaseStatus, RunStatus } from "@/lib/monitor-state";
import { AgentMode, OwaspMitreMapping, RecentDetectionItem, StepTrace } from "@/lib/types";

type DashboardEvent = Record<string, unknown>;

function asText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function formatTimestamp(value: unknown): string {
  const raw = asText(value);
  if (!raw) return "n/a";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleString();
}

function getPhaseBadge(status: PhaseStatus): { label: string; className: string } {
  if (status === "completed") {
    return {
      label: "Completed",
      className: "status-badge bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300",
    };
  }
  if (status === "running") {
    return {
      label: "Running",
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
      label: "Skipped",
      className: "status-badge bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300",
    };
  }
  return {
    label: "Pending",
    className: "status-badge bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  };
}

function detectAttackFamily(logLines: string[]): "SQLi" | "XSS" | "IDOR" | "PathTraversal" | "Attack" {
  const joined = logLines.join(" ").toLowerCase();
  if (joined.includes("risk=sqli") || joined.includes("scenario=sqli")) return "SQLi";
  if (joined.includes("risk=xss") || joined.includes("scenario=reflectedxss") || joined.includes("storedxss")) return "XSS";
  if (joined.includes("risk=idor") || joined.includes("scenario=idor")) return "IDOR";
  if (joined.includes("pathtraversal") || joined.includes("scenario=pathtraversal")) return "PathTraversal";
  return "Attack";
}

function extractSection(text: string, title: string): string {
  const pattern = new RegExp(`${title}\\s*:?([\\s\\S]*?)(?:\\n\\s*[0-9]+\\)|$)`, "i");
  const match = text.match(pattern);
  return match ? match[1].trim() : "";
}

function buildFallbackWarning(logLines: string[]): string {
  const attackFamily = detectAttackFamily(logLines);
  if (attackFamily === "SQLi") {
    return [
      "ALERT: Possible SQL injection attack detected on your login endpoint.",
      "IMMEDIATE ACTIONS:",
      "- Temporarily block suspicious IPs and enable strict rate limiting on login.",
      "- Reject SQL-like patterns in username/password input immediately.",
      "- Use parameterized queries only; disable string-built SQL.",
      "- Rotate admin credentials and review recent successful logins.",
    ].join("\n");
  }
  if (attackFamily === "XSS") {
    return [
      "ALERT: Possible cross-site scripting (XSS) attack detected.",
      "IMMEDIATE ACTIONS:",
      "- Escape/sanitize all user-controlled output before rendering.",
      "- Turn on a strict Content Security Policy (CSP).",
      "- Remove malicious stored content and invalidate active sessions.",
      "- Monitor new requests for repeated script payload patterns.",
    ].join("\n");
  }
  return [
    "ALERT: Suspicious attack activity detected on your website.",
    "IMMEDIATE ACTIONS:",
    "- Block repeat offender IPs and tighten rate limits.",
    "- Validate and sanitize all user inputs at the server.",
    "- Review auth/admin actions from the same time window.",
    "- Keep logs and capture evidence for incident follow-up.",
  ].join("\n");
}

function buildUserWarning(finalText: string, logLines: string[]): string {
  const firstLine = finalText.split("\n").find((line) => line.trim().length > 0) || "";
  const introLooksUnhelpful = /i will|to analyze|first extract|based on this analysis/i.test(firstLine);
  if (introLooksUnhelpful) return buildFallbackWarning(logLines);

  const alertLine = finalText
    .split("\n")
    .find((line) => line.toLowerCase().includes("alert"))
    ?.trim();
  const immediate = extractSection(finalText, "IMMEDIATE ACTIONS");
  if (!alertLine) return buildFallbackWarning(logLines);

  const trimmedActions = immediate
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("-"))
    .slice(0, 4)
    .join("\n");

  return [alertLine, trimmedActions || "- Apply immediate containment and review recent attack logs."].join("\n");
}

export default function SandboxPage() {
  const [mode, setMode] = useState<AgentMode>("g1");
  const [trace, setTrace] = useState<StepTrace[]>([]);
  const [events, setEvents] = useState<DashboardEvent[]>([]);
  const [systemLogs, setSystemLogs] = useState<string[]>([]);
  const [detections, setDetections] = useState<RecentDetectionItem[]>([]);
  const [scenarios, setScenarios] = useState<Array<{ id: string; name: string; endpoint: string; method: string }>>(
    []
  );
  const [selectedScenario, setSelectedScenario] = useState("sqliLogin");
  const [analysisResult, setAnalysisResult] = useState("");
  const [mapping, setMapping] = useState<Record<string, OwaspMitreMapping>>({});
  const [error, setError] = useState("");
  const [runStatus, setRunStatus] = useState<RunStatus>("idle");
  const [currentStep, setCurrentStep] = useState("");
  const [liveStatus, setLiveStatus] = useState("Waiting for simulation.");
  const [autoModeEnabled, setAutoModeEnabled] = useState(true);
  const [warningText, setWarningText] = useState("");
  const [promptUsed, setPromptUsed] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string>("");
  const processedAttackIdsRef = useRef<Set<string>>(new Set());
  const inFlightAutoRunRef = useRef(false);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    setError("");
    try {
      const [eventsResponse, detectionsResponse, mappingResponse, systemLogResponse] = await Promise.all([
        getLiveLog({ source: "vuln_lab_events", tail: 40 }),
        getRecentDetections(25),
        getOwaspMitreMap(),
        getLabSystemLogs(80),
      ]);
      setEvents(eventsResponse.result.items);
      setDetections(detectionsResponse.result.items);
      setMapping(mappingResponse.result);
      setSystemLogs(
        systemLogResponse.result.map(
          (entry) =>
            `[${entry.timestamp}] req=${entry.requestId} ${entry.method} ${entry.path} ` +
            `status=${entry.status} latency_ms=${entry.latencyMs}` +
            `${entry.attackDetected ? " attack_detected=true" : ""}` +
            `${entry.scenarioId ? ` scenario=${entry.scenarioId}` : ""}` +
            `${entry.riskHint ? ` risk=${entry.riskHint}` : ""}` +
            `${entry.payloadSnippet ? ` payload="${entry.payloadSnippet}"` : ""}`
        )
      );
      setLastUpdatedAt(new Date().toISOString());
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed to refresh dashboard.");
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    async function loadScenarios() {
      try {
        const response = await getLabScenarios();
        setScenarios(response.result);
        if (response.result.length > 0) setSelectedScenario(response.result[0].id);
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "Failed to load scenarios.");
      }
    }
    void loadScenarios();
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const eventCategoryCount = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const event of events) {
      const category = asText(event.owaspCategory) || "Unknown";
      counts[category] = (counts[category] || 0) + 1;
    }
    return counts;
  }, [events]);

  const monitor = useMemo(
    () =>
      deriveMonitorState({
        mode,
        trace,
        currentStep,
        runStatus,
      }),
    [mode, trace, currentStep, runStatus]
  );

  function buildBeginnerPrompt(logLines: string[], scenarioLabel: string) {
    return [
      "You are a website security assistant for non-technical users.",
      "Task: detect if this is an active attack, then give a SHORT warning and immediate protection steps.",
      "Critical rules:",
      "- Do NOT explain your reasoning process.",
      "- Do NOT say phrases like 'I will analyze' or 'I will first'.",
      "- Start directly with: ALERT: ...",
      "Output format:",
      "1) ALERT (one sentence, plain language)",
      "2) WHAT HAPPENED (2-3 bullets)",
      "3) IMMEDIATE ACTIONS (max 5 bullets, concrete steps for website owner)",
      "4) NEXT 24H CHECKLIST (max 4 bullets)",
      "Keep it concise and practical. Avoid jargon where possible.",
      "",
      `Scenario hint: ${scenarioLabel}`,
      "System logs from vulnerable website:",
      ...logLines,
    ].join("\n");
  }

  async function executeGuidedAnalysis(logLines: string[], scenarioLabel: string, runLabel: string) {
    setAnalysisResult("");
    setWarningText("");
    setTrace([]);
    setRunStatus("running");
    setCurrentStep("");
    setLiveStatus(`${runLabel}: preparing AI analysis...`);

    const composedInput = buildBeginnerPrompt(logLines, scenarioLabel);
    setPromptUsed(composedInput);
    let receivedFinal = false;

    await streamWorkspace(
      {
        task: "chat",
        mode,
        input: composedInput,
      },
      {
        onEvent: (eventPayload) => {
          if (eventPayload.type === "trace") {
            setTrace((prev) => [...prev, eventPayload.step]);
            setCurrentStep(eventPayload.step.step);
            setLiveStatus(`${eventPayload.step.step}: ${eventPayload.step.what_it_does}`);
            return;
          }
          if (eventPayload.type === "final") {
            const finalText = eventPayload.result;
            setAnalysisResult(finalText);
            setWarningText(buildUserWarning(finalText, logLines));
            setRunStatus("completed");
            setCurrentStep("");
            setLiveStatus(`${runLabel}: analysis completed.`);
            receivedFinal = true;
            return;
          }
          if (eventPayload.type === "error") {
            setRunStatus("error");
            setCurrentStep("");
            setLiveStatus(`${runLabel}: analysis failed.`);
            setError(eventPayload.error.message || "Unexpected stream error.");
            return;
          }
          if (eventPayload.type === "done" && !receivedFinal) {
            setLiveStatus(`${runLabel}: run stopped before final output.`);
          }
        },
      }
    );
  }

  async function runGuidedSimulation() {
    setIsSimulating(true);
    setError("");
    setLiveStatus("Triggering attack simulation...");

    try {
      const simulation = await simulateLabScenario(selectedScenario);
      setLiveStatus(`Simulation completed: ${simulation.result.scenarioName}`);
      await new Promise((resolve) => window.setTimeout(resolve, 900));
      const logsResponse = await getLabSystemLogs(15);
      const logLines = logsResponse.result.map(
        (entry) =>
          `[${entry.timestamp}] ${entry.method} ${entry.path} status=${entry.status} latency_ms=${entry.latencyMs} ip=${entry.ip}` +
          `${entry.attackDetected ? " attack_detected=true" : ""}` +
          `${entry.scenarioId ? ` scenario=${entry.scenarioId}` : ""}` +
          `${entry.riskHint ? ` risk=${entry.riskHint}` : ""}` +
          `${entry.payloadSnippet ? ` payload="${entry.payloadSnippet}"` : ""}`
      );
      setSystemLogs(logLines);
      const scenarioMeta = scenarios.find((item) => item.id === selectedScenario);
      const scenarioLabel = scenarioMeta
        ? `${scenarioMeta.name} (${scenarioMeta.method} ${scenarioMeta.endpoint})`
        : selectedScenario;
      await executeGuidedAnalysis(logLines, scenarioLabel, "Manual simulation");
      await refresh();
    } catch (requestError) {
      setRunStatus("error");
      setLiveStatus("Simulation run failed.");
      setError(requestError instanceof Error ? requestError.message : "Simulation failed.");
    } finally {
      setIsSimulating(false);
    }
  }

  useEffect(() => {
    if (!autoModeEnabled || isSimulating || inFlightAutoRunRef.current) {
      return;
    }
    const latestAttackLog = systemLogs.find((line) => line.includes("attack_detected=true"));
    if (!latestAttackLog) {
      return;
    }
    const reqMatch = latestAttackLog.match(/req=([a-zA-Z0-9-]+)/);
    const reqId = reqMatch ? reqMatch[1] : latestAttackLog;
    if (processedAttackIdsRef.current.has(reqId)) {
      return;
    }
    processedAttackIdsRef.current.add(reqId);
    inFlightAutoRunRef.current = true;
    setLiveStatus("Auto mode: new attack detected, running analysis...");
    const recentAttackLogs = systemLogs.filter((line) => line.includes("attack_detected=true")).slice(0, 12);
    const scenarioHintMatch = latestAttackLog.match(/scenario=([a-zA-Z0-9_]+)/);
    const scenarioHint = scenarioHintMatch ? scenarioHintMatch[1] : "detected_attack";

    void executeGuidedAnalysis(recentAttackLogs, `Auto-detected ${scenarioHint}`, "Auto detection")
      .catch((requestError) => {
        setRunStatus("error");
        setLiveStatus("Auto mode: analysis failed.");
        setError(requestError instanceof Error ? requestError.message : "Auto analysis failed.");
      })
      .finally(() => {
        inFlightAutoRunRef.current = false;
      });
  }, [autoModeEnabled, isSimulating, systemLogs]);

  return (
    <main className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_480px]">
      <section className="panel lg:col-span-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-lg font-semibold">Unified Sandbox + Guided Dashboard</h2>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Automated flow: simulate attack to capture website logs, then run guided AI explanation with live monitor.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Last updated: {formatTimestamp(lastUpdatedAt)}
            </span>
            <button type="button" className="btn" onClick={() => void refresh()} disabled={isRefreshing}>
              {isRefreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>
        {error ? <p className="mt-2 text-sm text-rose-500">{error}</p> : null}
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">Automation Runner</h3>
        <div className="mb-3 grid gap-2 md:grid-cols-2">
          <label className="text-xs text-slate-600 dark:text-slate-300">
            Scenario
            <select
              className="input mt-1"
              value={selectedScenario}
              onChange={(event) => setSelectedScenario(event.target.value)}
              disabled={isSimulating}
            >
              {scenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-slate-600 dark:text-slate-300">
            Agent Mode
            <select className="input mt-1" value={mode} onChange={(event) => setMode(event.target.value as AgentMode)} disabled={isSimulating}>
              <option value="g1">G1 (Single Agent)</option>
              <option value="g2">G2 (Multiagent)</option>
            </select>
          </label>
          <label className="text-xs text-slate-600 dark:text-slate-300">
            Auto mode
            <select
              className="input mt-1"
              value={autoModeEnabled ? "on" : "off"}
              onChange={(event) => setAutoModeEnabled(event.target.value === "on")}
              disabled={isSimulating}
            >
              <option value="on">ON (auto-run when attack log appears)</option>
              <option value="off">OFF (manual only)</option>
            </select>
          </label>
        </div>
        <button type="button" className="btn mb-3 w-full" onClick={() => void runGuidedSimulation()} disabled={isSimulating || scenarios.length === 0}>
          {isSimulating ? "Running simulation and analysis..." : "Run full automated flow"}
        </button>
        <div className="rounded-md border border-cyan-300 bg-cyan-50 p-3 text-xs text-cyan-900 dark:border-cyan-800 dark:bg-cyan-950/30 dark:text-cyan-100">
          <p className="font-semibold">What is happening now?</p>
          <p className="mt-1">{liveStatus}</p>
        </div>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">Website System Logs (vuln-lab)</h3>
        <pre className="code-block max-h-[260px]">{systemLogs.length ? systemLogs.slice(0, 30).join("\n") : "No system logs yet."}</pre>
      </section>

      <section className="panel lg:col-span-2">
        <h3 className="section-title mb-2">Live Monitor (analysis internals)</h3>
        <div className="mb-3 rounded-md border border-slate-300 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-950/60">
          <div className="mb-2 flex items-center justify-between text-xs">
            <p className="font-medium text-slate-700 dark:text-slate-300">Overall run progress</p>
            <p className="text-slate-600 dark:text-slate-400">
              {monitor.requiredCompletedCount}/{monitor.requiredTotalCount} required steps
            </p>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-slate-300 dark:bg-slate-800">
            <div
              className="h-full rounded-full bg-cyan-500 transition-all"
              style={{ width: `${Math.min(100, Math.max(monitor.percentage, isSimulating ? 6 : 0))}%` }}
            />
          </div>
        </div>
        <div className="grid gap-2 md:grid-cols-3">
          {monitor.phases.map((phase) => {
            const badge = getPhaseBadge(phase.status);
            return (
              <div key={phase.id} className="rounded-md border border-slate-200 p-3 dark:border-slate-700">
                <div className="mb-1 flex items-center justify-between">
                  <p className="text-xs font-semibold text-slate-800 dark:text-slate-100">{phase.title}</p>
                  <span className={badge.className}>{badge.label}</span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400">{phase.desc}</p>
                <p className="mt-1 text-[10px] text-slate-500 dark:text-slate-500">
                  Progress: {phase.doneCount}/{phase.total}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">Prompt Sent To Chat Engine</h3>
        <pre className="code-block max-h-[260px]">{promptUsed || "Run the automated flow to generate prompt."}</pre>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">Beginner-Friendly AI Explanation</h3>
        <pre className="code-block max-h-[260px] whitespace-pre-wrap">{analysisResult || "Run the automated flow to get explanation."}</pre>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">User Warning</h3>
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-100">
          {warningText || "No warning yet. Trigger or detect an attack to generate one."}
        </div>
      </section>

      <section className="panel lg:col-span-2">
        <h3 className="section-title mb-2">Technical Trace Details</h3>
        <TracePanel trace={trace} />
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">Attack Stream</h3>
        <div className="space-y-2">
          {events.length === 0 ? (
            <p className="subtle-text">No events yet. Trigger the automated flow to populate this panel.</p>
          ) : (
            events.slice(0, 20).map((event, index) => (
              <article key={`${asText(event.timestamp)}-${index}`} className="rounded-md border border-slate-200 p-2 text-xs dark:border-slate-700">
                <p className="font-medium text-slate-700 dark:text-slate-200">
                  {asText(event.scenarioId) || "unknown-scenario"} · {asText(event.riskHint) || "risk:unknown"}
                </p>
                <p className="text-slate-600 dark:text-slate-400">
                  {formatTimestamp(event.timestamp)} · {asText(event.method)} {asText(event.path)} · status {String(event.status ?? "-")}
                </p>
              </article>
            ))
          )}
        </div>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">CTI Detection Timeline</h3>
        <div className="space-y-2">
          {detections.length === 0 ? (
            <p className="subtle-text">No detections yet. They appear after CTI analysis completes.</p>
          ) : (
            detections.slice(0, 20).map((item, index) => (
              <article key={`${item.run_id || item.timestamp || index}`} className="rounded-md border border-slate-200 p-2 text-xs dark:border-slate-700">
                <p className="font-medium text-slate-700 dark:text-slate-200">
                  {item.endpoint || "unknown-endpoint"} · {item.mode || "n/a"} · {item.stop_reason || "unknown"}
                </p>
                <p className="text-slate-600 dark:text-slate-400">
                  {formatTimestamp(item.timestamp)} · success: {String(item.success ?? false)} · duration: {String(item.duration_ms ?? "-")}ms
                </p>
              </article>
            ))
          )}
        </div>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">OWASP Category Counters</h3>
        <div className="space-y-1 text-sm">
          {Object.keys(eventCategoryCount).length === 0 ? (
            <p className="subtle-text">No categorized events yet.</p>
          ) : (
            Object.entries(eventCategoryCount).map(([category, count]) => (
              <p key={category} className="flex items-center justify-between rounded-md border border-slate-200 px-2 py-1 dark:border-slate-700">
                <span>{category}</span>
                <span className="font-semibold">{count}</span>
              </p>
            ))
          )}
        </div>
      </section>

      <section className="panel">
        <h3 className="section-title mb-2">OWASP ↔ MITRE Mapping</h3>
        <div className="space-y-2 text-sm">
          {Object.keys(mapping).length === 0 ? (
            <p className="subtle-text">Loading mapping...</p>
          ) : (
            Object.entries(mapping).map(([key, value]) => (
              <article key={key} className="rounded-md border border-slate-200 p-2 dark:border-slate-700">
                <p className="font-medium">{key}</p>
                <p className="text-xs text-slate-600 dark:text-slate-400">{value.owasp}</p>
                <p className="text-xs text-slate-600 dark:text-slate-400">MITRE: {value.mitre.join(", ")}</p>
              </article>
            ))
          )}
        </div>
      </section>
    </main>
  );
}
