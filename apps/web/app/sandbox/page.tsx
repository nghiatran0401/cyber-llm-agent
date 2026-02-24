"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

import { TracePanel } from "@/components/TracePanel";
import { analyzeSandboxEvent, getSandboxScenarios, simulateSandboxEvent } from "@/lib/api";
import { AgentMode, G2Result, SandboxEvent, StepTrace } from "@/lib/types";

export default function SandboxPage() {
  const [mode, setMode] = useState<AgentMode>("g1");
  const [scenario, setScenario] = useState("sqli");
  const [sourceIp, setSourceIp] = useState("127.0.0.1");
  const [vulnerableMode, setVulnerableMode] = useState(false);
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [event, setEvent] = useState<SandboxEvent | null>(null);
  const [trace, setTrace] = useState<StepTrace[]>([]);
  const [resultText, setResultText] = useState("");
  const [g2Result, setG2Result] = useState<G2Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const canAnalyze = useMemo(() => !loading && !!event, [loading, event]);

  useEffect(() => {
    async function loadScenarios() {
      try {
        const response = await getSandboxScenarios();
        if (response.result.length > 0) {
          setScenarios(response.result);
          setScenario(response.result[0]);
        }
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "Failed to load scenarios");
      }
    }
    void loadScenarios();
  }, []);

  async function onSimulate(eventForm: FormEvent<HTMLFormElement>) {
    eventForm.preventDefault();
    setLoading(true);
    setError("");
    setTrace([]);
    setResultText("");
    setG2Result(null);
    try {
      const response = await simulateSandboxEvent({
        scenario,
        vulnerable_mode: vulnerableMode,
        source_ip: sourceIp,
        append_to_live_log: true,
      });
      setEvent(response.result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed to simulate event");
    } finally {
      setLoading(false);
    }
  }

  async function onAnalyze() {
    if (!event) return;
    setLoading(true);
    setError("");
    setTrace([]);
    setResultText("");
    setG2Result(null);
    try {
      const response = await analyzeSandboxEvent({
        event,
        mode,
        include_trace: true,
      });
      setTrace(response.trace);
      if (mode === "g1") {
        setResultText(String(response.result));
      } else {
        setG2Result(response.result as G2Result);
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed to analyze sandbox event");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="space-y-4">
      <section className="panel">
        <h2 className="mb-2 text-xl font-semibold">Educational OWASP sandbox</h2>
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
          Simulate local attack events and analyze them using the migrated Next.js + FastAPI flow.
        </p>
        <form className="grid gap-3 md:grid-cols-2" onSubmit={onSimulate}>
          <label className="text-sm text-slate-700 dark:text-slate-300">
            Scenario
            <select className="input mt-1" value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {scenarios.map((item) => (
                <option key={item} value={item}>
                  {item.toUpperCase()}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm text-slate-700 dark:text-slate-300">
            Agent Mode
            <select className="input mt-1" value={mode} onChange={(e) => setMode(e.target.value as AgentMode)}>
              <option value="g1">Single Agent (G1)</option>
              <option value="g2">Multiagent (G2)</option>
            </select>
          </label>
          <label className="text-sm text-slate-700 dark:text-slate-300">
            Source IP
            <input className="input mt-1" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={vulnerableMode}
              onChange={(e) => setVulnerableMode(e.target.checked)}
            />
            Vulnerable mode
          </label>
          <div className="md:col-span-2 flex gap-2">
            <button type="submit" className="btn" disabled={loading || scenarios.length === 0}>
              {loading ? "Simulating..." : "Simulate attack event"}
            </button>
            <button type="button" className="btn" disabled={!canAnalyze} onClick={() => void onAnalyze()}>
              {loading ? "Analyzing..." : "Analyze last event"}
            </button>
          </div>
        </form>
        {error ? <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p> : null}
      </section>

      <section className="panel">
        <h3 className="mb-2 text-lg font-semibold">Latest event</h3>
        {event ? (
          <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 text-sm dark:bg-slate-950">
            {JSON.stringify(event, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-400">No event generated yet.</p>
        )}
      </section>

      <section className="panel">
        <h3 className="mb-2 text-lg font-semibold">Analysis output</h3>
        {mode === "g1" ? (
          <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 text-sm dark:bg-slate-950">
            {resultText || "Run analysis to see output."}
          </pre>
        ) : g2Result ? (
          <div className="space-y-3 text-sm">
            <div>
              <h4 className="font-medium">Log analysis</h4>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 dark:bg-slate-950">{g2Result.log_analysis}</pre>
            </div>
            <div>
              <h4 className="font-medium">Threat prediction</h4>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 dark:bg-slate-950">{g2Result.threat_prediction}</pre>
            </div>
            <div>
              <h4 className="font-medium">Incident response</h4>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 dark:bg-slate-950">{g2Result.incident_response}</pre>
            </div>
            <div>
              <h4 className="font-medium">Executive summary</h4>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 dark:bg-slate-950">{g2Result.final_report}</pre>
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-400">Run analysis to see output.</p>
        )}
      </section>

      <section>
        <h3 className="mb-2 text-lg font-semibold">Execution trace</h3>
        <TracePanel trace={trace} />
      </section>
    </main>
  );
}
