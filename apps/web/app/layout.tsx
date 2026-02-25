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
        <div className="mx-auto min-h-screen max-w-[1420px] px-4 py-4">
          <header className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200/80 bg-white/90 px-4 py-3 shadow-sm backdrop-blur dark:border-slate-800/80 dark:bg-slate-900/75">
            <div>
              <h1 className="text-xl font-semibold tracking-tight">Cyber LLM Copilot</h1>
              <p className="text-xs text-slate-600 dark:text-slate-400">Security assistant for SOC triage and response planning</p>
            </div>
            <nav className="flex gap-2 text-sm">
              <Link className="btn-secondary" href="/">
                Chatbot
              </Link>
              <Link className="btn-secondary" href="/sandbox">
                Simulator
              </Link>
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
