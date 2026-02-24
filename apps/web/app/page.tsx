"use client";

import { FormEvent, useMemo, useState } from "react";

import { TracePanel } from "@/components/TracePanel";
import { analyze, chat } from "@/lib/api";
import { AgentMode, G2Result, StepTrace } from "@/lib/types";

type TaskMode = "chat" | "analyze";

type WorkspaceMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  task: TaskMode;
};

const QUICK_PROMPTS = [
  "Summarize top 3 indicators from these logs.",
  "Is this behavior likely credential stuffing?",
  "Provide immediate containment actions.",
];

function formatG2Result(result: G2Result): string {
  return [
    "Executive Summary",
    result.final_report,
    "",
    "Log Analysis",
    result.log_analysis,
    "",
    "Threat Prediction",
    result.threat_prediction,
    "",
    "Incident Response",
    result.incident_response,
  ].join("\n");
}

export default function WorkspacePage() {
  const [messages, setMessages] = useState<WorkspaceMessage[]>([]);
  const [taskMode, setTaskMode] = useState<TaskMode>("chat");
  const [modelMode, setModelMode] = useState<AgentMode>("g1");
  const [draft, setDraft] = useState("");
  const [logPayload, setLogPayload] = useState("");
  const [logFileName, setLogFileName] = useState("");
  const [trace, setTrace] = useState<StepTrace[]>([]);
  const [lastResultText, setLastResultText] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const canSubmit = useMemo(() => {
    if (isSubmitting) return false;
    if (taskMode === "analyze") return Boolean(draft.trim() || logPayload.trim());
    return Boolean(draft.trim());
  }, [taskMode, draft, logPayload, isSubmitting]);

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
      taskMode === "analyze"
        ? [draft.trim(), logPayload.trim()].filter(Boolean).join("\n\n")
        : draft.trim();
    if (!userInput) return;

    setIsSubmitting(true);
    setError("");
    setTrace([]);
    setLastResultText("");
    setMessages((prev) => [
      ...prev,
      {
        id: `user-${Date.now()}`,
        role: "user",
        content: userInput,
        task: taskMode,
      },
    ]);
    setDraft("");

    try {
      if (taskMode === "analyze") {
        const response = await analyze(modelMode, userInput);
        const assistantText =
          modelMode === "g2" ? formatG2Result(response.result as G2Result) : String(response.result);
        setMessages((prev) => [
          ...prev,
          { id: `assistant-${Date.now()}`, role: "assistant", content: assistantText, task: "analyze" },
        ]);
        setTrace(response.trace);
        setLastResultText(assistantText);
      } else {
        const response = await chat(modelMode, userInput);
        const assistantText = String(response.result);
        setMessages((prev) => [
          ...prev,
          { id: `assistant-${Date.now()}`, role: "assistant", content: assistantText, task: "chat" },
        ]);
        setTrace(response.trace);
        setLastResultText(assistantText);
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unexpected request failure.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)_340px]">
      <aside className="panel h-fit space-y-3">
        <div>
          <p className="text-sm font-semibold">Workspace</p>
          <p className="text-xs text-slate-600 dark:text-slate-400">Single flow for chat + log analysis</p>
        </div>
        <button
          type="button"
          className="btn w-full"
          onClick={() => {
            setMessages([]);
            setTrace([]);
            setLastResultText("");
            setDraft("");
            setError("");
          }}
        >
          New conversation
        </button>
        <div className="space-y-2">
          <p className="text-xs font-medium text-slate-700 dark:text-slate-300">Popular prompts</p>
          {QUICK_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              type="button"
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-left text-xs text-slate-700 hover:border-cyan-500 dark:border-slate-700 dark:text-slate-300 dark:hover:border-cyan-400"
              onClick={() => setDraft(prompt)}
            >
              {prompt}
            </button>
          ))}
        </div>
      </aside>

      <section className="panel flex min-h-[70vh] flex-col">
        <div className="mb-3 flex flex-wrap items-center gap-2 border-b border-slate-200 pb-3 dark:border-slate-800">
          <p className="text-sm font-medium">Task</p>
          <button
            type="button"
            className={`rounded-full px-3 py-1 text-xs ${taskMode === "chat" ? "bg-cyan-500 text-slate-950" : "border border-slate-300 text-slate-700 dark:border-slate-700 dark:text-slate-300"}`}
            onClick={() => setTaskMode("chat")}
          >
            Chat
          </button>
          <button
            type="button"
            className={`rounded-full px-3 py-1 text-xs ${taskMode === "analyze" ? "bg-cyan-500 text-slate-950" : "border border-slate-300 text-slate-700 dark:border-slate-700 dark:text-slate-300"}`}
            onClick={() => setTaskMode("analyze")}
          >
            Analyze Logs
          </button>

          <label className="ml-auto text-xs text-slate-600 dark:text-slate-400">
            Engine
            <select
              className="ml-2 rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
              value={modelMode}
              onChange={(event) => setModelMode(event.target.value as AgentMode)}
            >
              <option value="g1">G1 (Single Agent)</option>
              <option value="g2">G2 (Multiagent)</option>
            </select>
          </label>
        </div>

        <div className="flex-1 space-y-3 overflow-y-auto pr-1">
          {!messages.length ? (
            <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center dark:border-slate-700">
              <p className="text-sm text-slate-700 dark:text-slate-300">Start with a question or upload logs for analysis.</p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-500">
                This unified workspace merges chat and analysis into one conversational flow.
              </p>
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
                {message.role === "user" ? "You" : "Assistant"} · {message.task}
              </p>
              <p className="whitespace-pre-wrap leading-relaxed">{message.content}</p>
            </article>
          ))}
          {isSubmitting ? (
            <article className="max-w-[90%] rounded-xl border border-slate-300 bg-white p-3 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-950/80 dark:text-slate-400">
              Assistant is thinking...
            </article>
          ) : null}
        </div>

        <form className="mt-4 space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800" onSubmit={onSubmit}>
          {taskMode === "analyze" ? (
            <div className="rounded-lg border border-slate-300 bg-slate-50 p-2 dark:border-slate-700 dark:bg-slate-950/60">
              <label className="text-xs text-slate-700 dark:text-slate-300">
                Upload logs
                <input
                  className="input mt-1"
                  type="file"
                  accept=".txt,.log,.json,.jsonl"
                  onChange={(event) => void onUploadLogs(event.target.files?.[0] ?? null)}
                />
              </label>
              {logFileName ? <p className="mt-1 text-xs text-slate-600 dark:text-slate-400">Attached: {logFileName}</p> : null}
            </div>
          ) : null}

          <textarea
            className="input min-h-28"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder={
              taskMode === "analyze"
                ? "Optional instruction (e.g., 'focus on brute force and summarize severity')"
                : "Ask about suspicious activity, incident response, or threat intelligence..."
            }
          />

          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-500 dark:text-slate-500">
              {taskMode === "analyze" ? "Log content + instruction will be analyzed together." : "Conversational mode."}
            </p>
            <button className="btn" type="submit" disabled={!canSubmit}>
              {isSubmitting ? "Working..." : "Send"}
            </button>
          </div>
          {error ? <p className="text-sm text-rose-400">{error}</p> : null}
        </form>
      </section>

      <aside className="space-y-4">
        <section className="panel">
          <h2 className="mb-2 text-sm font-semibold">Latest response</h2>
          <pre className="max-h-56 overflow-y-auto whitespace-pre-wrap rounded-md bg-slate-100 p-3 text-xs text-slate-700 dark:bg-slate-950 dark:text-slate-200">
            {lastResultText || "Results will appear here after each request."}
          </pre>
        </section>
        <section className="panel">
          <h2 className="mb-2 text-sm font-semibold">Execution trace</h2>
          <TracePanel trace={trace} />
        </section>
      </aside>
    </main>
  );
}
