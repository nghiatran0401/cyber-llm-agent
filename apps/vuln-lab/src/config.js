const path = require("path");

const repoRoot = path.resolve(__dirname, "..", "..", "..");

const config = {
  appName: "OWASP Vulnerable Lab",
  env: process.env.NODE_ENV || "development",
  labMode: process.env.LAB_MODE || "vulnerable",
  host: process.env.LAB_HOST || "127.0.0.1",
  port: Number(process.env.LAB_PORT || 3100),
  ctiApiBase: process.env.CTI_API_BASE || "http://127.0.0.1:8000",
  ctiMode: process.env.CTI_BRIDGE_MODE || "both",
  ctiAnalyzeMode: process.env.CTI_ANALYZE_MODE || "g1",
  ctiBatchSize: Number(process.env.CTI_BATCH_SIZE || 8),
  ctiFlushMs: Number(process.env.CTI_FLUSH_MS || 7000),
  logsFilePath:
    process.env.LAB_LOG_FILE || path.join(repoRoot, "data", "logs", "vuln_lab_events.jsonl"),
  detectionsFilePath:
    process.env.LAB_DETECTION_FILE || path.join(repoRoot, "data", "logs", "vuln_lab_detections.jsonl"),
  systemLogFilePath:
    process.env.LAB_SYSTEM_LOG_FILE || path.join(repoRoot, "data", "logs", "vuln_lab_system.log"),
};

module.exports = {
  config,
};
