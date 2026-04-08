const { OWASP_MITRE_MAP, SCENARIO_MAP } = require("./owaspMap");

/** Three demo scenarios aligned with the API sandbox keys (sqli, xss, bruteforce). */
const scenarioCatalog = [
  {
    id: "sqliLogin",
    name: "SQL injection (login)",
    endpoint: "/lab/login",
    method: "POST",
    samplePayload: "' OR '1'='1",
    riskHint: "SQLi",
  },
  {
    id: "reflectedXss",
    name: "Cross-site scripting (search)",
    endpoint: "/lab/search",
    method: "GET",
    samplePayload: "<script>alert(1)</script>",
    riskHint: "XSS",
  },
  {
    id: "bruteForceLogin",
    name: "Brute-force login attempts",
    endpoint: "/lab/login",
    method: "POST",
    samplePayload: "wrong password ×3 within 10m (same IP)",
    riskHint: "BruteForce",
  },
];

function categoryForScenario(scenarioId) {
  const key = SCENARIO_MAP[scenarioId] || "A05_SecurityMisconfiguration";
  return OWASP_MITRE_MAP[key];
}

module.exports = {
  scenarioCatalog,
  categoryForScenario,
  OWASP_MITRE_MAP,
};
