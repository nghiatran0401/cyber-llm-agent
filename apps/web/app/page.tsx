"use client";

import { FormEvent, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { TracePanel } from "@/components/TracePanel";
import { deriveMonitorState, PhaseStatus, RunStatus } from "@/lib/monitor-state";
import { streamWorkspace } from "@/lib/api";
import { AgentMode, StepTrace } from "@/lib/types";
type WorkspaceMessage = { id: string; role: "user" | "assistant"; content: string };

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

function MarkdownContent({ content }: { content: string }) {
  return (
    <div className="markdown-body">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
    </div>
  );
}

export default function WorkspacePage() {
  const [messages, setMessages] = useState<WorkspaceMessage[]>([]);
  const [modelMode, setModelMode] = useState<AgentMode>("g1");
  const [draft, setDraft] = useState("");
  const [logPayload, setLogPayload] = useState("");
  const [logFileName, setLogFileName] = useState("");
  const [trace, setTrace] = useState<StepTrace[]>([]);
  const [lastResultText, setLastResultText] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [runStatus, setRunStatus] = useState<RunStatus>("idle");
  const [liveStatus, setLiveStatus] = useState("Waiting for request...");
  const [currentStep, setCurrentStep] = useState("");
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const canSubmit = useMemo(() => {
    if (isSubmitting) return false;
    return Boolean(draft.trim() || logPayload.trim());
  }, [draft, logPayload, isSubmitting]);

  const monitor = useMemo(
    () =>
      deriveMonitorState({
        mode: modelMode,
        trace,
        currentStep,
        runStatus,
      }),
    [modelMode, trace, currentStep, runStatus],
  );

  async function onUploadLogs(file: File | null) {
    if (!file) {
      setLogPayload("");
      setLogFileName("");
      return;
    }

    const supported = [".txt", ".log", ".json", ".jsonl"];
    const lowered = file.name.toLowerCase();
    if (!supported.some((suffix) => lowered.endsWith(suffix))) {
      setError("Unsupported file type. Use .txt, .log, .json, or .jsonl.");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError("File too large. Maximum size is 10MB.");
      return;
    }

    const content = await file.text();
    setLogPayload(content);
    setLogFileName(file.name);
    setError("");
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) return;

    const userInput =
      [draft.trim(), logPayload.trim()].filter(Boolean).join("\n\n");
    if (!userInput) return;

    setIsSubmitting(true);
    setError("");
    setTrace([]);
    setLastResultText("");
    setLiveStatus("Submitting request...");
    setRunStatus("running");
    setCurrentStep("");
    setMessages((prev) => [
      ...prev,
      {
        id: `user-${Date.now()}`,
        role: "user",
        content: userInput,
      },
    ]);
    setDraft("");

    try {
      let finalText = "";
      await streamWorkspace(
        {
          task: "chat",
          mode: modelMode,
          input: userInput,
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
              finalText = eventPayload.result;
              setLiveStatus("Completed.");
              setRunStatus("completed");
              setCurrentStep("");
              setLastResultText(finalText);
              setMessages((prev) => [
                ...prev,
                {
                  id: `assistant-${Date.now()}`,
                  role: "assistant",
                  content: finalText,
                },
              ]);
              return;
            }
            if (eventPayload.type === "error") {
              setError(eventPayload.error.message || "Unexpected request failure.");
              setRunStatus("error");
              setLiveStatus("Run failed.");
              setCurrentStep("");
            }
            if (eventPayload.type === "done") {
              if (!finalText) {
                setLiveStatus("Run stopped before final output.");
                setRunStatus("error");
              }
            }
          },
        },
      );
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unexpected request failure.");
      setRunStatus("error");
      setLiveStatus("Run failed.");
    } finally {
      setIsSubmitting(false);
    }
  }

  function onComposerKeyDown(event: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      if (!canSubmit) return;
      event.currentTarget.form?.requestSubmit();
    }
  }

  return (
    <main className="grid h-[calc(100dvh-120px)] gap-4 overflow-hidden lg:grid-cols-[minmax(0,1fr)_520px]">
      <section className="panel flex h-full flex-col overflow-hidden">
        <div className="mb-3 flex flex-wrap items-center gap-2 border-b border-slate-200 pb-3 dark:border-slate-800">
          <div>
            <p className="text-sm font-semibold">CyberAI Assistant</p>
            <p className="text-xs text-slate-600 dark:text-slate-400">Use chat + logs to produce incident-ready analysis.</p>
          </div>
          <label className="ml-auto text-xs text-slate-600 dark:text-slate-400">
            Mode
            <select
              className="ml-2 rounded-full border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-900 shadow-sm focus:border-cyan-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              value={modelMode}
              onChange={(event) => setModelMode(event.target.value as AgentMode)}
            >
              <option value="g1">G1 (Single Agent)</option>
              <option value="g2">G2 (Multiagent)</option>
            </select>
          </label>
        </div>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
          {!messages.length ? (
            <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center dark:border-slate-700">
              <p className="text-sm text-slate-700 dark:text-slate-300">Start with a question and optionally attach logs.</p>
            </div>
          ) : null}
          {messages.map((message) => (
            <article
              key={message.id}
              className={`max-w-[90%] rounded-xl border p-3 text-sm ${
                message.role === "user"
                  ? "ml-auto border-cyan-400/30 bg-cyan-500/10"
                  : "border-slate-300 bg-white dark:border-slate-700 dark:bg-slate-950/80"
              }`}
            >
              <p className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
                {message.role === "user" ? "You" : "Assistant"}
              </p>
              {message.role === "assistant" ? (
                <MarkdownContent content={message.content} />
              ) : (
                <p className="whitespace-pre-wrap leading-relaxed">{message.content}</p>
              )}
            </article>
          ))}
          {isSubmitting ? (
            <article className="max-w-[90%] rounded-xl border border-slate-300 bg-white p-3 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-950/80 dark:text-slate-400">
              {liveStatus}
            </article>
          ) : null}
        </div>

        <form className="mt-4 space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800" onSubmit={onSubmit}>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="rounded-full border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:border-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-cyan-400"
              onClick={() => fileInputRef.current?.click()}
              title="Attach log file"
            >
              Attach logs
            </button>
            <input
              ref={fileInputRef}
              className="hidden"
              type="file"
              accept=".txt,.log,.json,.jsonl"
              onChange={(event) => void onUploadLogs(event.target.files?.[0] ?? null)}
            />
            {logFileName ? (
              <span className="rounded-full border border-slate-300 bg-slate-100 px-3 py-1 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                {logFileName}
              </span>
            ) : null}
          </div>

          <textarea
            className="input min-h-28"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={onComposerKeyDown}
            placeholder="Ask anything about security, incidents, or attached logs..."
          />

          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-500 dark:text-slate-400">Ctrl/Cmd + Enter to submit quickly</p>
            <button className="btn" type="submit" disabled={!canSubmit}>
              {isSubmitting ? "Working..." : "Send"}
            </button>
          </div>
          {error ? <p className="text-sm text-rose-400">{error}</p> : null}
        </form>
      </section>

      <aside className="space-y-4 overflow-y-auto pr-1">
        <section className="panel">
          <h2 className="mb-2 text-base font-semibold">Live Monitor</h2>
          <p className="mb-3 text-xs text-slate-600 dark:text-slate-400">
            Big-picture view of backend workflow state in real time.
          </p>

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
                style={{
                  width: `${Math.min(100, Math.max(monitor.percentage, isSubmitting ? 6 : 0))}%`,
                }}
              />
            </div>
          </div>

          <div className="space-y-2">
            {monitor.phases.map((phase) => {
              const badge = getPhaseBadge(phase.status);
              return (
                <div
                  key={phase.id}
                  className={`rounded-md border p-3 ${
                    phase.status === "completed"
                      ? "border-emerald-300 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30"
                      : phase.status === "running"
                        ? "border-cyan-300 bg-cyan-50 dark:border-cyan-900 dark:bg-cyan-950/30"
                        : phase.status === "error"
                          ? "border-rose-300 bg-rose-50 dark:border-rose-900 dark:bg-rose-950/30"
                          : phase.status === "skipped"
                            ? "border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/30"
                        : "border-slate-300 bg-white dark:border-slate-700 dark:bg-slate-900"
                  }`}
                >
                  <div className="mb-1 flex items-center justify-between">
                    <p className="text-xs font-semibold text-slate-800 dark:text-slate-100">{phase.title}</p>
                    <span className={badge.className}>
                      {badge.label}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400">{phase.desc}</p>
                  <p className="mt-1 text-[10px] text-slate-500 dark:text-slate-500">
                    Progress: {phase.doneCount}/{phase.total} internal steps
                  </p>
                </div>
              );
            })}
          </div>

          <div className="mt-3 rounded-md border border-cyan-300 bg-cyan-50 p-3 text-xs text-cyan-900 dark:border-cyan-800 dark:bg-cyan-950/30 dark:text-cyan-100">
            <p className="font-semibold">What is happening now?</p>
            <p className="mt-1">
              {liveStatus}
            </p>
          </div>
          {monitor.unknownSteps.length > 0 ? (
            <p className="mt-2 rounded-md border border-amber-300 bg-amber-50 px-2 py-1 text-[11px] text-amber-900 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
              Unknown server steps received: {monitor.unknownSteps.join(", ")}
            </p>
          ) : null}
        </section>
        <section className="panel">
          <h2 className="mb-2 text-sm font-semibold">Technical Trace</h2>
          <TracePanel trace={trace} />
          {!trace.length && lastResultText ? (
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">Run output is available even if no trace was emitted.</p>
          ) : null}
        </section>
      </aside>
    </main>
  );
}
