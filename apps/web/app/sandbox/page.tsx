"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { TracePanel } from "@/components/TracePanel";
import { analyze, getLabSystemLogs, resetLabSystemLogs } from "@/lib/api";
import { AgentMode, G2Result, LabSystemLogEntry, ResponseMeta, StepTrace } from "@/lib/types";

const LAB_BASE = (process.env.NEXT_PUBLIC_LAB_BASE_URL || "http://127.0.0.1:3100").replace(/\/$/, "");
const POLL_MS = 2500;

function formatLabLine(entry: LabSystemLogEntry): string {
  return (
    `[${entry.timestamp}] req=${entry.requestId} ${entry.method} ${entry.path} ` +
    `status=${entry.status} latency_ms=${entry.latencyMs} ip=${entry.ip}` +
    `${entry.attackDetected ? " attack_detected=true" : ""}` +
    `${entry.scenarioId ? ` scenario=${entry.scenarioId}` : ""}` +
    `${entry.riskHint ? ` risk=${entry.riskHint}` : ""}` +
    `${entry.payloadSnippet ? ` payload="${entry.payloadSnippet}"` : ""}`
  );
}

function buildLabLogPrompt(lines: string[]): string {
  return [
    "You are helping a security analyst review HTTP request logs from a deliberately vulnerable local demo app (vuln-lab).",
    "Summarize what the log shows, likely intent, severity, and short containment or verification steps. Stay concise.",
    "",
    "Logs:",
    ...lines,
  ].join("\n");
}

function formatAnalysisResult(result: string | G2Result): string {
  if (typeof result === "string") {
    return result;
  }
  const parts = [
    result.log_analysis && `## Log analysis\n${result.log_analysis}`,
    result.threat_prediction && `## Threat assessment\n${result.threat_prediction}`,
    result.incident_response && `## Response ideas\n${result.incident_response}`,
    result.final_report && `## Summary\n${result.final_report}`,
  ].filter(Boolean);
  return parts.join("\n\n") || JSON.stringify(result, null, 2);
}

export default function SandboxPage() {
  const [logEntries, setLogEntries] = useState<LabSystemLogEntry[]>([]);
  const [labConnected, setLabConnected] = useState<boolean | null>(null);
  const [lastPollAt, setLastPollAt] = useState<string>("");

  const [mode, setMode] = useState<AgentMode>("g1");
  const [autoAnalyze, setAutoAnalyze] = useState(true);
  const [statusLine, setStatusLine] = useState("Waiting for lab logs.");

  const [analysisText, setAnalysisText] = useState("");
  const [trace, setTrace] = useState<StepTrace[]>([]);
  const [meta, setMeta] = useState<ResponseMeta | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [logsRefreshing, setLogsRefreshing] = useState(false);

  const processedAttackIdsRef = useRef<Set<string>>(new Set());
  const inFlightRef = useRef(false);

  const refreshLabLogs = useCallback(async (opts?: { manual?: boolean }) => {
    setLogsRefreshing(true);
    try {
      if (opts?.manual) {
        await resetLabSystemLogs();
        processedAttackIdsRef.current.clear();
        inFlightRef.current = false;
      }
      const res = await getLabSystemLogs(60);
      setLogEntries(res.result);
      setLabConnected(true);
      setLastPollAt(new Date().toISOString());
      setError((prev) => (prev.startsWith("Lab:") ? "" : prev));
      if (opts?.manual) {
        setStatusLine("Lab system log cleared. You can trigger new attacks in vuln-lab.");
      }
    } catch (e) {
      setLabConnected(false);
      setLogEntries([]);
      if (opts?.manual) {
        setError(
          e instanceof Error
            ? `Lab: ${e.message} — check that vuln-lab is running and NEXT_PUBLIC_LAB_BASE_URL matches this browser (e.g. http://127.0.0.1:3100).`
            : "Lab: could not load system logs.",
        );
      }
    } finally {
      setLogsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refreshLabLogs();
    const t = window.setInterval(() => void refreshLabLogs(), POLL_MS);
    return () => window.clearInterval(t);
  }, [refreshLabLogs]);

  const runAnalysisOnLines = useCallback(
    async (lines: string[], label: string) => {
      if (lines.length === 0) return;
      setBusy(true);
      setError("");
      setStatusLine(`${label}: analyzing…`);
      try {
        const input = buildLabLogPrompt(lines);
        const res = await analyze(mode, input);
        setAnalysisText(formatAnalysisResult(res.result as string | G2Result));
        setTrace(res.trace || []);
        setMeta(res.meta);
        setStatusLine(`${label}: done.`);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Analysis failed.");
        setStatusLine(`${label}: failed.`);
      } finally {
        setBusy(false);
      }
    },
    [mode],
  );

  const analyzeLatestAttack = useCallback(() => {
    const attacks = logEntries.filter((e) => e.attackDetected);
    if (attacks.length === 0) {
      setError("No attack lines in the current lab log buffer. Trigger SQLi, XSS, or failed logins in the lab.");
      return;
    }
    const context = attacks.slice(0, 15).reverse().map(formatLabLine);
    void runAnalysisOnLines(context, "Manual (latest attacks)");
  }, [logEntries, runAnalysisOnLines]);

  useEffect(() => {
    if (!autoAnalyze || !labConnected || busy || inFlightRef.current) {
      return;
    }
    const latest = logEntries.find((e) => e.attackDetected);
    if (!latest) {
      return;
    }
    if (processedAttackIdsRef.current.has(latest.requestId)) {
      return;
    }
    processedAttackIdsRef.current.add(latest.requestId);
    inFlightRef.current = true;
    setStatusLine("New attack in lab logs — analyzing…");
    const attacks = logEntries.filter((e) => e.attackDetected).slice(0, 15).reverse();
    const lines = attacks.map(formatLabLine);
    void runAnalysisOnLines(lines, "Auto (new attack)")
      .finally(() => {
        inFlightRef.current = false;
      });
  }, [autoAnalyze, labConnected, busy, logEntries, runAnalysisOnLines]);

  const displayLines = logEntries.map(formatLabLine);

  return (
    <main className="mx-auto max-w-3xl space-y-6">
      <section className="panel space-y-3">
        <h2 className="text-lg font-semibold">Lab monitor</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Open the{" "}
          <a className="underline" href={LAB_BASE} target="_blank" rel="noreferrer">
            vuln-lab
          </a>{" "}
          in another window (same machine, default <code className="text-xs">{LAB_BASE}</code>). The lab page loads a demo <strong className="font-medium text-slate-800 dark:text-slate-200">browser SDK</strong>{" "}
          (<code className="text-xs">copilot-sdk-demo.js</code>) that mimics a merchant site using our package: each <em>new</em> attack after page load triggers a native{" "}
          <code className="text-xs">alert()</code> in that tab. This page polls the same log buffer and can run <strong className="font-medium text-slate-800 dark:text-slate-200">G1</strong> or{" "}
          <strong className="font-medium text-slate-800 dark:text-slate-200">G2</strong> on new{" "}
          <code className="text-xs">attack_detected</code> lines automatically. Flow detail:{" "}
          <code className="text-xs">docs/architecture-current-state.md</code> and <code className="text-xs">docs/graph1.svg</code> /{" "}
          <code className="text-xs">docs/graph2.svg</code>.
        </p>
        <p className="text-xs text-slate-500">
          Requires <code className="text-xs">NEXT_PUBLIC_LAB_BASE_URL</code> to reach the lab from the browser (e.g. Docker host URL if the lab is not on
          localhost from the web container&apos;s perspective).
        </p>
      </section>

      <section className="panel space-y-3">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">How to simulate attacks (vuln-lab)</h3>
        <p className="text-xs text-slate-500">
          Start the lab in vulnerable mode so payloads are accepted and logged as attacks, e.g.{" "}
          <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">LAB_MODE=vulnerable npm --prefix apps/vuln-lab run dev</code> (see{" "}
          <code className="text-xs">apps/vuln-lab/README.md</code>).
        </p>
        <ol className="list-decimal space-y-3 pl-5 text-sm text-slate-700 dark:text-slate-300">
          <li>
            <span className="font-medium text-slate-800 dark:text-slate-200">SQL injection (login)</span>
            <p className="mt-1 text-slate-600 dark:text-slate-400">
              On the lab home page, under <strong>Sign in</strong>, enter any username and put{" "}
              <code className="text-xs">' OR '1'='1</code> in the password field, then submit. The lab calls{" "}
              <code className="text-xs">POST /lab/auth/login</code> (JSON). You should see <code className="text-xs">attack_detected=true</code>,{" "}
              <code className="text-xs">scenario=sqliLogin</code>, <code className="text-xs">risk=SQLi</code> on the next poll here.
            </p>
          </li>
          <li>
            <span className="font-medium text-slate-800 dark:text-slate-200">Reflected XSS (search)</span>
            <p className="mt-1 text-slate-600 dark:text-slate-400">
              Under <strong>Search</strong>, submit something that looks like HTML/JS, e.g.{" "}
              <code className="text-xs">&lt;script&gt;alert(1)&lt;/script&gt;</code> or{" "}
              <code className="text-xs">&lt;img src=x onerror=alert(1)&gt;</code>. That hits{" "}
              <code className="text-xs">GET /lab/api/products?q=…</code>. Expect <code className="text-xs">scenario=reflectedXss</code> and{" "}
              <code className="text-xs">risk=XSS</code> in the log.
            </p>
          </li>
          <li>
            <span className="font-medium text-slate-800 dark:text-slate-200">Brute-force pattern (credential stuffing style)</span>
            <p className="mt-1 text-slate-600 dark:text-slate-400">
              A <strong>single</strong> wrong password is treated as a normal 401 (no <code className="text-xs">attack_detected</code>). Submit{" "}
              <strong>wrong credentials at least 3 times</strong> from the same IP within ~10 minutes (e.g. <code className="text-xs">admin</code> / wrong
              password, click Sign in three times). The <strong>third</strong> failure logs <code className="text-xs">scenario=bruteForceLogin</code> and{" "}
              <code className="text-xs">risk=BruteForce</code>.
            </p>
          </li>
        </ol>
        <p className="text-xs text-slate-500">
          After each attack, this page should pick up new lines within a few seconds. If auto-analyze is on, analysis runs when a new <code className="text-xs">requestId</code>{" "}
          appears; otherwise use <strong>Analyze latest attack</strong>.
        </p>
      </section>

      <section className="panel space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Live lab log</h3>
          <span className="text-xs text-slate-500">
            {labConnected === false ? (
              <span className="text-amber-700 dark:text-amber-300">Lab unreachable — is it running on {LAB_BASE}?</span>
            ) : labConnected === true ? (
              <>Polling · last {lastPollAt ? new Date(lastPollAt).toLocaleTimeString() : ""}</>
            ) : (
              "Connecting…"
            )}
          </span>
        </div>
        <pre className="code-block max-h-56 overflow-auto text-xs">{displayLines.length ? displayLines.join("\n") : "—"}</pre>
        <p className="text-xs text-slate-500">{statusLine}</p>

        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm">
            <span className="text-slate-600 dark:text-slate-400">Engine</span>
            <select className="input w-auto py-1.5" value={mode} onChange={(e) => setMode(e.target.value as AgentMode)} disabled={busy}>
              <option value="g1">G1</option>
              <option value="g2">G2</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
            <input type="checkbox" checked={autoAnalyze} onChange={(e) => setAutoAnalyze(e.target.checked)} disabled={busy} />
            Auto-analyze new attacks
          </label>
          <button type="button" className="btn" disabled={busy || !labConnected} onClick={() => void analyzeLatestAttack()}>
            {busy ? "Analyzing…" : "Analyze latest attack"}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => void refreshLabLogs({ manual: true })}
            disabled={logsRefreshing}
          >
            {logsRefreshing ? "Clearing…" : "Clear logs & refresh"}
          </button>
        </div>
        <p className="text-xs text-slate-500">
          <strong className="font-medium text-slate-600 dark:text-slate-400">Clear logs & refresh</strong> wipes the lab&apos;s system log buffer (and its
          log file) so you can retry attacks from a clean list. Background polling does not clear. To reset SDK <code className="text-xs">alert()</code> state on
          the lab tab, reload that page.
        </p>
        {error ? <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p> : null}
      </section>

      <section className="panel space-y-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Analysis</h3>
        <pre className="code-block max-h-80 overflow-auto whitespace-pre-wrap text-sm">{analysisText || "—"}</pre>
        {meta?.stop_reason ? (
          <p className="text-xs text-slate-500">
            {meta.stop_reason}
            {meta.model ? ` · ${meta.model}` : ""}
            {meta.duration_ms != null ? ` · ${Math.round(meta.duration_ms)}ms` : ""}
          </p>
        ) : null}
      </section>

      {trace.length > 0 ? (
        <details className="panel">
          <summary className="cursor-pointer text-sm font-semibold text-slate-700 dark:text-slate-300">Trace steps</summary>
          <div className="mt-3">
            <TracePanel trace={trace} />
          </div>
        </details>
      ) : null}
    </main>
  );
}
