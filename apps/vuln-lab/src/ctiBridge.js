function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function looksSuspicious(event) {
  const code = Number(event.status || 0);
  if (code >= 400) {
    return true;
  }
  const signal = String(event.riskHint || "").toLowerCase();
  return signal.length > 0 && signal !== "info";
}

function toSandboxEvent(event) {
  return {
    timestamp: event.timestamp,
    scenario_id: event.scenarioId,
    source_ip: event.ip,
    endpoint: event.path,
    payload_pattern: event.payloadSnippet,
    status_code: event.status,
    risk_hint: event.riskHint,
    raw_event: event.message,
    mode: event.labMode,
  };
}

function toBatchInput(events) {
  return events
    .map((event) => {
      return [
        `timestamp=${event.timestamp}`,
        `ip=${event.ip}`,
        `method=${event.method}`,
        `path=${event.path}`,
        `status=${event.status}`,
        `scenario=${event.scenarioId}`,
        `risk=${event.riskHint}`,
        `payload=${event.payloadSnippet}`,
      ].join(" ");
    })
    .join("\n");
}

async function postJsonWithRetry(url, payload, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const body = await response.text();
        throw new Error(`HTTP ${response.status}: ${body}`);
      }
      return await response.json();
    } catch (error) {
      if (attempt >= retries) {
        throw error;
      }
      await sleep(400 * (attempt + 1));
    }
  }
  throw new Error("retry failure");
}

function normalizeDetection(response, source, mode) {
  const meta = response && response.meta ? response.meta : {};
  return {
    timestamp: new Date().toISOString(),
    source,
    mode,
    ok: Boolean(response && response.ok),
    stopReason: meta.stop_reason || "unknown",
    severity:
      (response && response.result && response.result.severity) ||
      (response && response.result && response.result.final_report && "reported") ||
      "unknown",
    summary:
      typeof response.result === "string"
        ? response.result.slice(0, 240)
        : JSON.stringify(response.result || {}).slice(0, 240),
    runId: meta.run_id || meta.request_id || null,
  };
}

function createCtiBridge(config, telemetry) {
  let started = false;
  const queue = [];

  async function sendEventMode(event) {
    const payload = {
      event: toSandboxEvent(event),
      mode: config.ctiAnalyzeMode === "g2" ? "g2" : "g1",
      include_trace: false,
    };
    const response = await postJsonWithRetry(
      `${config.ctiApiBase}/api/v1/sandbox/analyze`,
      payload,
      2
    );
    telemetry.recordDetection(normalizeDetection(response, "sandbox_analyze", payload.mode));
  }

  async function flushBatchMode() {
    if (queue.length === 0) {
      return;
    }
    const slice = queue.splice(0, config.ctiBatchSize);
    const payload = {
      input: toBatchInput(slice),
      include_trace: false,
    };
    const mode = config.ctiAnalyzeMode === "g2" ? "g2" : "g1";
    const response = await postJsonWithRetry(
      `${config.ctiApiBase}/api/v1/analyze/${mode}`,
      payload,
      2
    );
    telemetry.recordDetection(normalizeDetection(response, "batch_analyze", mode));
  }

  function enqueueEvent(event) {
    if (!looksSuspicious(event)) {
      return;
    }
    queue.push(event);
    if (queue.length >= config.ctiBatchSize) {
      void flushBatchMode().catch((error) => {
        telemetry.recordDetection({
          timestamp: new Date().toISOString(),
          source: "batch_analyze",
          mode: config.ctiAnalyzeMode,
          ok: false,
          stopReason: "error",
          severity: "error",
          summary: `CTI batch bridge failed: ${error.message}`,
          runId: null,
        });
      });
    }
    if (config.ctiMode === "event" || config.ctiMode === "both") {
      void sendEventMode(event).catch((error) => {
        telemetry.recordDetection({
          timestamp: new Date().toISOString(),
          source: "sandbox_analyze",
          mode: config.ctiAnalyzeMode,
          ok: false,
          stopReason: "error",
          severity: "error",
          summary: `CTI event bridge failed: ${error.message}`,
          runId: null,
        });
      });
    }
  }

  function start() {
    if (started) {
      return;
    }
    started = true;
    setInterval(() => {
      if (config.ctiMode === "batch" || config.ctiMode === "both") {
        void flushBatchMode().catch((error) => {
          telemetry.recordDetection({
            timestamp: new Date().toISOString(),
            source: "batch_analyze",
            mode: config.ctiAnalyzeMode,
            ok: false,
            stopReason: "error",
            severity: "error",
            summary: `CTI scheduled flush failed: ${error.message}`,
            runId: null,
          });
        });
      }
    }, config.ctiFlushMs);
  }

  return {
    start,
    enqueueEvent,
    flushBatchMode,
  };
}

module.exports = {
  createCtiBridge,
};
