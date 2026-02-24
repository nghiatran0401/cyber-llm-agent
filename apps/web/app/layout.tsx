import "./globals.css";
import Link from "next/link";
import type { Metadata } from "next";
import { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Cyber LLM Copilot",
  description: "AI security copilot for chat and log analysis",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="mx-auto min-h-screen max-w-[1400px] px-4 py-4">
          <header className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200/80 bg-white/85 px-4 py-3 backdrop-blur dark:border-slate-800/80 dark:bg-slate-900/70">
            <div>
              <h1 className="text-xl font-semibold tracking-tight">Cyber LLM Copilot</h1>
              <p className="text-xs text-slate-600 dark:text-slate-400">Security assistant for SOC triage and response planning</p>
            </div>
            <nav className="flex gap-2 text-sm">
              <Link className="rounded-md border border-slate-300 px-3 py-2 hover:border-cyan-500 dark:border-slate-700 dark:hover:border-cyan-400" href="/">
                Workspace
              </Link>
              <Link className="rounded-md border border-slate-300 px-3 py-2 hover:border-cyan-500 dark:border-slate-700 dark:hover:border-cyan-400" href="/sandbox">
                Sandbox
              </Link>
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
