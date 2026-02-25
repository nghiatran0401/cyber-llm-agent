const fs = require("fs");
const path = require("path");

const MAX_BUFFER_ITEMS = 500;

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function appendJsonl(filePath, payload) {
  ensureParentDir(filePath);
  fs.appendFileSync(filePath, `${JSON.stringify(payload)}\n`, "utf8");
}

function appendLine(filePath, textLine) {
  ensureParentDir(filePath);
  fs.appendFileSync(filePath, `${textLine}\n`, "utf8");
}

function createTelemetryStore(config) {
  const events = [];
  const detections = [];
  const systemLogs = [];

  function pushWithLimit(buffer, item) {
    buffer.unshift(item);
    if (buffer.length > MAX_BUFFER_ITEMS) {
      buffer.length = MAX_BUFFER_ITEMS;
    }
  }

  function recordEvent(event) {
    pushWithLimit(events, event);
    appendJsonl(config.logsFilePath, event);
  }

  function recordDetection(detection) {
    pushWithLimit(detections, detection);
    appendJsonl(config.detectionsFilePath, detection);
  }

  function getRecentEvents(limit = 50) {
    return events.slice(0, Math.max(1, Math.min(limit, 200)));
  }

  function getRecentDetections(limit = 50) {
    return detections.slice(0, Math.max(1, Math.min(limit, 200)));
  }

  function getStats() {
    const byCategory = {};
    for (const event of events) {
      const key = event.owaspCategory || "Unknown";
      byCategory[key] = (byCategory[key] || 0) + 1;
    }
    return {
      totalEvents: events.length,
      totalDetections: detections.length,
      totalSystemLogs: systemLogs.length,
      mode: config.labMode,
      byCategory,
    };
  }

  function recordSystemLog(entry) {
    pushWithLimit(systemLogs, entry);
    const baseLine =
      `[${entry.timestamp}] req=${entry.requestId} ${entry.method} ${entry.path} ` +
      `status=${entry.status} latency_ms=${entry.latencyMs} ip=${entry.ip} ua="${entry.userAgent}"`;
    const securityParts = [];
    if (entry.attackDetected) {
      securityParts.push("attack_detected=true");
    }
    if (entry.scenarioId) {
      securityParts.push(`scenario=${entry.scenarioId}`);
    }
    if (entry.riskHint) {
      securityParts.push(`risk=${entry.riskHint}`);
    }
    if (entry.owaspCategory) {
      securityParts.push(`owasp="${entry.owaspCategory}"`);
    }
    if (entry.payloadSnippet) {
      securityParts.push(`payload="${String(entry.payloadSnippet).slice(0, 180)}"`);
    }
    const line = securityParts.length > 0 ? `${baseLine} ${securityParts.join(" ")}` : baseLine;
    appendLine(config.systemLogFilePath, line);
  }

  function getRecentSystemLogs(limit = 50) {
    return systemLogs.slice(0, Math.max(1, Math.min(limit, 200)));
  }

  return {
    recordEvent,
    recordDetection,
    recordSystemLog,
    getRecentEvents,
    getRecentDetections,
    getRecentSystemLogs,
    getStats,
  };
}

module.exports = {
  createTelemetryStore,
};
