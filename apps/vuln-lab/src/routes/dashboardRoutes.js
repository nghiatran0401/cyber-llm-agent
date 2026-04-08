const express = require("express");

const failedLoginTracker = require("../failedLoginTracker");
const { OWASP_MITRE_MAP, categoryForScenario, scenarioCatalog } = require("../scenarios");

async function simulateRequestForScenario(config, scenarioId) {
  const baseUrl = `http://${config.host}:${config.port}`;
  const headers = { "x-lab-simulator": "dashboard" };

  if (scenarioId === "sqliLogin") {
    return fetch(`${baseUrl}/lab/login`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "admin", password: "' OR '1'='1" }).toString(),
    });
  }
  if (scenarioId === "reflectedXss") {
    return fetch(`${baseUrl}/lab/search?q=${encodeURIComponent("<script>alert(1)</script>")}`, {
      method: "GET",
      headers,
    });
  }
  if (scenarioId === "bruteForceLogin") {
    const url = `${baseUrl}/lab/login`;
    const init = {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: "admin", password: "wrong-password" }).toString(),
    };
    const need = failedLoginTracker.BRUTE_FORCE_THRESHOLD;
    let last;
    for (let i = 0; i < need; i += 1) {
      last = await fetch(url, init);
    }
    return last;
  }
  return Promise.reject(new Error(`No simulation recipe for scenario '${scenarioId}'.`));
}

function makeDashboardRouter({ config, telemetry }) {
  const router = express.Router();

  router.get("/events", (req, res) => {
    const limit = Number(req.query.limit || 50);
    return res.json({ ok: true, result: telemetry.getRecentEvents(limit), mode: config.labMode });
  });

  router.get("/detections", (req, res) => {
    const limit = Number(req.query.limit || 50);
    return res.json({ ok: true, result: telemetry.getRecentDetections(limit) });
  });

  router.get("/stats", (_, res) => {
    return res.json({ ok: true, result: telemetry.getStats() });
  });

  router.get("/mappings", (_, res) => {
    return res.json({ ok: true, result: OWASP_MITRE_MAP });
  });

  router.post("/system-logs/reset", (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    failedLoginTracker.clearIp();
    telemetry.clearSystemLogs();
    return res.json({ ok: true, result: { cleared: true } });
  });

  router.get("/system-logs", (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    const limit = Number(req.query.limit || 80);
    const attackOnly = String(req.query.attack_only || "true").toLowerCase() !== "false";
    const entries = telemetry.getRecentSystemLogs(limit);
    return res.json({
      ok: true,
      result: attackOnly ? entries.filter((entry) => String(entry.path || "").startsWith("/lab/")) : entries,
    });
  });

  router.get("/scenarios", (_, res) => {
    return res.json({ ok: true, result: scenarioCatalog });
  });

  router.post("/simulate/:scenarioId", (req, res) => {
    const scenarioId = String(req.params.scenarioId || "");
    const scenario = scenarioCatalog.find((item) => item.id === scenarioId);
    if (!scenario) {
      return res.status(404).json({ ok: false, error: `Unknown scenario '${scenarioId}'` });
    }

    return simulateRequestForScenario(config, scenario.id)
      .then(async (response) => {
        const category = categoryForScenario(scenario.id);
        const preview = (await response.text()).slice(0, 260);
        return res.json({
          ok: true,
          result: {
            scenarioId: scenario.id,
            scenarioName: scenario.name,
            endpoint: scenario.endpoint,
            method: scenario.method,
            expectedRiskHint: scenario.riskHint,
            owaspCategory: category.owasp,
            mitreTechniques: category.mitre,
            status: response.status,
            responsePreview: preview,
          },
        });
      })
      .catch((error) => {
        return res.status(500).json({ ok: false, error: `Simulation failed: ${error.message}` });
      });
  });

  return router;
}

module.exports = {
  makeDashboardRouter,
};
