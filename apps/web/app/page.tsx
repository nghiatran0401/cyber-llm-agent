"use client";

import { FormEvent, useMemo, useRef, useState } from "react";

/** Stable id for G1 session memory across messages in this browser tab (matches API safe pattern). */
function newWorkspaceSessionId(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return `web-${globalThis.crypto.randomUUID()}`;
  }
  return `web-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
}
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { LiveMonitorPanel } from "@/components/LiveMonitorPanel";
import { TracePanel } from "@/components/TracePanel";
import { deriveMonitorState, RunStatus } from "@/lib/monitor-state";
import { streamWorkspace } from "@/lib/api";
import { AgentMode, StepTrace } from "@/lib/types";
type WorkspaceMessage = { id: string; role: "user" | "assistant"; content: string };

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
  const workspaceSessionIdRef = useRef<string>("");
  if (!workspaceSessionIdRef.current) {
    workspaceSessionIdRef.current = newWorkspaceSessionId();
  }

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

  function clearLogAttachment() {
    setLogPayload("");
    setLogFileName("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  async function onUploadLogs(file: File | null) {
    if (!file) {
      clearLogAttachment();
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
    // One-shot attachment: otherwise the same file is re-appended on every later send in this tab.
    setLogPayload("");
    setLogFileName("");
    if (fileInputRef.current) fileInputRef.current.value = "";

    try {
      let finalText = "";
      await streamWorkspace(
        {
          task: "chat",
          mode: modelMode,
          input: userInput,
          session_id: workspaceSessionIdRef.current,
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
        <div className="mb-3 flex flex-wrap items-start gap-2 border-b border-slate-200 pb-3 dark:border-slate-800">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold">CyberAI Assistant</p>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Logs attach for the next send only. Use New chat between unrelated demos so G1 memory does not mix scenarios.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
            <button
              type="button"
              className="rounded-full border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:border-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-cyan-400"
              onClick={() => {
                workspaceSessionIdRef.current = newWorkspaceSessionId();
                setMessages([]);
                setTrace([]);
                setLastResultText("");
                setDraft("");
                clearLogAttachment();
                setError("");
                setRunStatus("idle");
                setCurrentStep("");
                setLiveStatus("Waiting for request...");
              }}
            >
              New chat
            </button>
            <label className="text-xs text-slate-600 dark:text-slate-400">
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
              <span className="inline-flex items-center gap-1 rounded-full border border-slate-300 bg-slate-100 py-1 pl-3 pr-1 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                {logFileName}
                <button
                  type="button"
                  className="rounded-full px-2 py-0.5 text-slate-500 hover:bg-slate-200 hover:text-slate-800 dark:hover:bg-slate-800 dark:hover:text-slate-100"
                  onClick={clearLogAttachment}
                  title="Remove attached logs"
                  aria-label="Remove attached logs"
                >
                  ×
                </button>
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
          <LiveMonitorPanel
            mode={modelMode}
            monitor={monitor}
            liveStatus={liveStatus}
            runInFlight={isSubmitting}
            phaseLayout="stack"
            heading="h2"
          />
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
