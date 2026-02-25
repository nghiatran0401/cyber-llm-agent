const OWASP_MITRE_MAP = {
  A01_BrokenAccessControl: {
    owasp: "A01:2021 Broken Access Control",
    mitre: ["T1190", "T1068"],
    summary: "Unauthorized access to privileged resources or other user data.",
  },
  A02_CryptographicFailures: {
    owasp: "A02:2021 Cryptographic Failures",
    mitre: ["T1557", "T1040"],
    summary: "Sensitive data exposure through weak or missing crypto controls.",
  },
  A03_Injection: {
    owasp: "A03:2021 Injection",
    mitre: ["T1190", "T1059"],
    summary: "Untrusted input is interpreted as code or query syntax.",
  },
  A05_SecurityMisconfiguration: {
    owasp: "A05:2021 Security Misconfiguration",
    mitre: ["T1190", "T1580"],
    summary: "Weak defaults and verbose internals increase attack surface.",
  },
  A06_VulnerableComponents: {
    owasp: "A06:2021 Vulnerable and Outdated Components",
    mitre: ["T1195", "T1588"],
    summary: "Outdated dependencies and known-CVE patterns are exploitable.",
  },
  A07_IdentificationAuthFailures: {
    owasp: "A07:2021 Identification and Authentication Failures",
    mitre: ["T1110", "T1078"],
    summary: "Weak login/session controls allow brute force and account takeover.",
  },
  A08_SoftwareDataIntegrityFailures: {
    owasp: "A08:2021 Software and Data Integrity Failures",
    mitre: ["T1553", "T1195"],
    summary: "Unsafe deserialization or unsigned updates enable tampering.",
  },
};

const SCENARIO_MAP = {
  sqliLogin: "A03_Injection",
  reflectedXss: "A03_Injection",
  storedXssComment: "A03_Injection",
  idorProfile: "A01_BrokenAccessControl",
  adminBypass: "A01_BrokenAccessControl",
  weakSession: "A07_IdentificationAuthFailures",
  bruteForceLogin: "A07_IdentificationAuthFailures",
  debugConfigLeak: "A05_SecurityMisconfiguration",
  pathTraversalDownload: "A05_SecurityMisconfiguration",
  weakCryptoToken: "A02_CryptographicFailures",
  outdatedComponentBanner: "A06_VulnerableComponents",
  unsafeDeserializer: "A08_SoftwareDataIntegrityFailures",
};

module.exports = {
  OWASP_MITRE_MAP,
  SCENARIO_MAP,
};
