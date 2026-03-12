# T1606 - Forge Web Credentials

**Tactic:** Credential Access
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1606

## Description

Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.

Adversaries may generate these credential materials in order to gain access to web resources. This differs from Steal Web Session Cookie, Steal Application Access Token, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users.

The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values. Adversaries may also forge tokens by taking advantage of features such as the `AssumeRole` and `GetFederationToken` APIs in AWS, which allow users to request temporary security credentials (i.e., Temporary Elevated Cloud Access), or the `zmprov gdpak` command in Zimbra, which generates a pre-authentication key that can be used to generate tokens for any user in the domain.

Once forged, adversaries may use these web credentials to access resources (ex: Use Alternate Authentication Material), which may bypass multi-factor and other authentication protection mechanisms.

## Detection

### Detection Analytics

**Analytic 0717**

Defenders may detect adversaries forging web credentials in IaaS environments by monitoring for anomalous API activity such as AssumeRole or GetFederationToken being executed by unusual principals. These events often correlate with sudden logon sessions from unfamiliar IP addresses or regions. The chain is usually secret material misuse (stolen private key or password) → API request generating a new token → access to high-value resources.

**Analytic 0718**

Forged web credentials may manifest as anomalous SAML token issuance, OpenID Connect token minting, or Zimbra pre-auth key usage. Defenders may see tokens issued without normal authentication events, multiple valid tokens generated simultaneously, or signing anomalies in IdP logs.

**Analytic 0719**

Forged web credentials on Windows endpoints may be detected by anomalous browser cookie files, local token cache manipulations, or tools injecting tokens into sessions. Defenders may observe processes accessing LSASS or browser credential stores unexpectedly, followed by unusual logon sessions.

**Analytic 0720**

On Linux systems, forged credentials may be injected into browser session files, curl/wget headers, or token caches in memory. Detection can leverage auditd to track processes accessing sensitive files (~/.mozilla, ~/.config/chromium, ~/.aws/credentials) and correlate with suspicious outbound connections.

**Analytic 0721**

Forged credentials on macOS may be visible through Unified Logs showing abnormal access to Keychain or browser session files. Correlated with anomalous web session usage from Safari or Chrome processes outside typical user context.

**Analytic 0722**

SaaS platforms may show forged credentials as unusual API keys, tokens, or session cookies being used without corresponding authentication. Correlated patterns include simultaneous valid sessions from multiple geographies, unusual API calls with new tokens, or bypass of expected MFA enforcement.

**Analytic 0723**

Forged web credentials in Office Suite contexts may appear as abnormal authentication headers in Outlook or Teams traffic, or unexplained OAuth grants in M365/Azure logs. Defenders should correlate token usage events with missing authentication flows and mismatched device/user context.


## Mitigations

### M1047 - Audit

Administrators should perform an audit of all access lists and the permissions they have been granted to access web applications and services. This should be done extensively on all resources in order to establish a baseline, followed up on with periodic audits of new or updated resources. Suspicious accounts/credentials should be investigated and removed.
 
Enable advanced auditing on ADFS. Check the success and failure audit options in the ADFS Management snap-in. Enable Audit Application Generated events on the AD FS farm via Group Policy Object.

### M1026 - Privileged Account Management

Restrict permissions and access to the AD FS server to only originate from privileged access workstations.

### M1054 - Software Configuration

Configure browsers/applications to regularly delete persistent web credentials (such as cookies).

### M1018 - User Account Management

Ensure that user accounts with administrative rights follow best practices, including use of privileged access workstations, Just in Time/Just Enough Administration (JIT/JEA), and strong authentication. Reduce the number of users that are members of highly privileged Directory Roles. In AWS environments, prohibit users from calling the `sts:GetFederationToken` API unless explicitly required.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
