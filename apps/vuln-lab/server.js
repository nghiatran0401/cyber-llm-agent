const path = require("path");
const crypto = require("crypto");
const express = require("express");

const { config } = require("./src/config");
const { createTelemetryStore } = require("./src/telemetry");
const { createCtiBridge } = require("./src/ctiBridge");
const { makeLabRouter } = require("./src/routes/labRoutes");
const { makeDashboardRouter } = require("./src/routes/dashboardRoutes");

function assertSafeEnvironment() {
  if (process.env.ENVIRONMENT === "production") {
    throw new Error("Refusing to start vulnerable lab when ENVIRONMENT=production.");
  }
}

assertSafeEnvironment();

const app = express();
const telemetry = createTelemetryStore(config);
const ctiBridge = createCtiBridge(config, telemetry);

app.use((_, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-api-key");
  if (_.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  return next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use((req, res, next) => {
  const startedAt = Date.now();
  const requestId = crypto.randomUUID();
  res.setHeader("x-request-id", requestId);
  res.on("finish", () => {
    // Keep "system logs" focused on attack actions only.
    if (!req.originalUrl.startsWith("/lab/")) {
      return;
    }
    telemetry.recordSystemLog({
      timestamp: new Date().toISOString(),
      requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      latencyMs: Date.now() - startedAt,
      ip: req.ip || req.socket.remoteAddress || "127.0.0.1",
      userAgent: req.headers["user-agent"] || "",
      attackDetected: Boolean(req.securityContext && req.securityContext.attackDetected),
      scenarioId: req.securityContext ? req.securityContext.scenarioId : undefined,
      riskHint: req.securityContext ? req.securityContext.riskHint : undefined,
      payloadSnippet: req.securityContext ? req.securityContext.payloadSnippet : undefined,
      message: req.securityContext ? req.securityContext.message : undefined,
      owaspCategory: req.securityContext ? req.securityContext.owaspCategory : undefined,
    });
  });
  next();
});

app.get("/", (_, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use("/lab", makeLabRouter({ config, telemetry, ctiBridge }));
app.use("/api/dashboard", makeDashboardRouter({ config, telemetry, ctiBridge }));

ctiBridge.start();

app.listen(config.port, config.host, () => {
  // Keep this explicit so learners do not accidentally expose the lab.
  console.log(
    `[vuln-lab] running at http://${config.host}:${config.port} mode=${config.labMode} cti=${config.ctiApiBase}`
  );
});
