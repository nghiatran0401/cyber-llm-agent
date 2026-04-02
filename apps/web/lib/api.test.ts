import { afterEach, describe, expect, it, vi } from "vitest";

import {
  analyze,
  analyzeSandboxEvent,
  chat,
  getLabScenarios,
  getLabSystemLogs,
  getLiveLog,
  getOwaspMitreMap,
  getRecentDetections,
  getSandboxScenarios,
  simulateLabScenario,
  simulateSandboxEvent,
} from "@/lib/api";

const mockedFetch = vi.fn();
global.fetch = mockedFetch as unknown as typeof fetch;

afterEach(() => {
  mockedFetch.mockReset();
});

describe("web api client", () => {
  it("calls g1 analyze endpoint and returns envelope", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ok: true,
        result: "analysis result",
        trace: [],
        meta: { request_id: "r1", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
        error: null,
      }),
    });

    const response = await analyze("g1", "failed login events");
    expect(response.result).toBe("analysis result");
    expect(mockedFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/v1/analyze/g1",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("calls g2 analyze endpoint and returns structured result", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ok: true,
        result: {
          log_analysis: "a",
          threat_prediction: "b",
          incident_response: "c",
          final_report: "d",
        },
        trace: [],
        meta: { request_id: "r2", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
        error: null,
      }),
    });

    const response = await analyze("g2", "events");
    expect(response.result.final_report).toBe("d");
    expect(mockedFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/v1/analyze/g2",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("calls chat endpoint and handles response", async () => {
    mockedFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        ok: true,
        result: "chat answer",
        trace: [],
        meta: { request_id: "r3", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
        error: null,
      }),
    });

    const response = await chat("g1", "what is brute force?");
    expect(response.result).toBe("chat answer");
    expect(mockedFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/v1/chat",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("calls sandbox simulate/analyze/scenarios endpoints", async () => {
    mockedFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: ["sqli", "xss"],
          trace: [],
          meta: { request_id: "r4", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: {
            timestamp: "2026-01-01T00:00:00Z",
            scenario_id: "owasp_sqli_001",
            source_ip: "127.0.0.1",
            endpoint: "/login",
            payload_pattern: "' OR '1'='1",
            status_code: 401,
            risk_hint: "SQLi",
            raw_event: "evt",
            mode: "vulnerable",
          },
          trace: [],
          meta: { request_id: "r5", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: "sandbox analysis",
          trace: [],
          meta: { request_id: "r6", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      });

    const scenarios = await getSandboxScenarios();
    expect(scenarios.result).toEqual(["sqli", "xss"]);

    const simulated = await simulateSandboxEvent({
      scenario: "sqli",
      vulnerable_mode: true,
      source_ip: "127.0.0.1",
      append_to_live_log: true,
    });
    expect(simulated.result.scenario_id).toBe("owasp_sqli_001");

    const analyzed = await analyzeSandboxEvent({
      event: simulated.result,
      mode: "g1",
      include_trace: true,
    });
    expect(analyzed.result).toBe("sandbox analysis");
  });

  it("calls dashboard visibility endpoints", async () => {
    mockedFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: {
            source: "vuln_lab_events",
            path: "data/logs/vuln_lab_events.jsonl",
            items: [{ scenarioId: "sqliLogin" }],
          },
          trace: [],
          meta: { request_id: "r7", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: {
            items: [{ endpoint: "/api/v1/sandbox/analyze", mode: "g1", success: true }],
            count: 1,
          },
          trace: [],
          meta: { request_id: "r8", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: {
            A03_Injection: {
              owasp: "A03:2021 Injection",
              mitre: ["T1190", "T1059"],
            },
          },
          trace: [],
          meta: { request_id: "r9", timestamp: "2026-01-01T00:00:00Z", api_version: "v1" },
          error: null,
        }),
      });

    const live = await getLiveLog({ source: "vuln_lab_events", tail: 10 });
    const detections = await getRecentDetections(5);
    const mapping = await getOwaspMitreMap();

    expect(live.result.source).toBe("vuln_lab_events");
    expect(detections.result.count).toBe(1);
    expect(mapping.result.A03_Injection.owasp).toContain("Injection");
  });

  it("calls vuln-lab dashboard endpoints", async () => {
    mockedFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: [
            {
              id: "sqliLogin",
              name: "SQL Injection Login Bypass",
              endpoint: "/lab/login",
              method: "POST",
              samplePayload: "' OR '1'='1",
              riskHint: "SQLi",
            },
          ],
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: {
            scenarioId: "sqliLogin",
            scenarioName: "SQL Injection Login Bypass",
            endpoint: "/lab/login",
            method: "POST",
            expectedRiskHint: "SQLi",
            owaspCategory: "A03:2021 Injection",
            mitreTechniques: ["T1190"],
            status: 200,
            responsePreview: "ok",
          },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          ok: true,
          result: [
            {
              timestamp: "2026-01-01T00:00:00Z",
              requestId: "req-1",
              method: "POST",
              path: "/lab/login",
              status: 200,
              latencyMs: 12,
              ip: "127.0.0.1",
              userAgent: "dashboard",
            },
          ],
        }),
      });

    const scenarios = await getLabScenarios();
    const simulated = await simulateLabScenario("sqliLogin");
    const systemLogs = await getLabSystemLogs(10);

    expect(scenarios.result[0].id).toBe("sqliLogin");
    expect(simulated.result.scenarioId).toBe("sqliLogin");
    expect(systemLogs.result[0].requestId).toBe("req-1");
  });
});
