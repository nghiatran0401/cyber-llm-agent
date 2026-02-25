const { OWASP_MITRE_MAP, SCENARIO_MAP } = require("./owaspMap");

const scenarioCatalog = [
  {
    id: "sqliLogin",
    name: "SQL Injection Login Bypass",
    endpoint: "/lab/login",
    method: "POST",
    samplePayload: "' OR '1'='1",
    riskHint: "SQLi",
  },
  {
    id: "reflectedXss",
    name: "Reflected XSS Search",
    endpoint: "/lab/search",
    method: "GET",
    samplePayload: "<script>alert('xss')</script>",
    riskHint: "XSS",
  },
  {
    id: "storedXssComment",
    name: "Stored XSS Comment",
    endpoint: "/lab/comment",
    method: "POST",
    samplePayload: "<img src=x onerror=alert('stored')>",
    riskHint: "StoredXSS",
  },
  {
    id: "idorProfile",
    name: "IDOR Profile Access",
    endpoint: "/lab/api/profile/1002?viewer=1001",
    method: "GET",
    samplePayload: "viewer=1001 target=1002",
    riskHint: "IDOR",
  },
  {
    id: "adminBypass",
    name: "Broken Access Control Admin",
    endpoint: "/lab/admin?role=user&debug=true",
    method: "GET",
    samplePayload: "role=user&debug=true",
    riskHint: "AccessControlBypass",
  },
  {
    id: "bruteForceLogin",
    name: "Brute Force Login Attempts",
    endpoint: "/lab/login",
    method: "POST",
    samplePayload: "admin:password123",
    riskHint: "BruteForce",
  },
  {
    id: "pathTraversalDownload",
    name: "Path Traversal Download",
    endpoint: "/lab/download?file=../../.env",
    method: "GET",
    samplePayload: "../../.env",
    riskHint: "PathTraversal",
  },
  {
    id: "unsafeDeserializer",
    name: "Unsafe Config Import",
    endpoint: "/lab/import-config",
    method: "POST",
    samplePayload: "{\"__proto__\":{\"isAdmin\":true}}",
    riskHint: "UnsafeDeserialization",
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
