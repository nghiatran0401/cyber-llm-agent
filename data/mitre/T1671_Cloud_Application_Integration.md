# T1671 - Cloud Application Integration

**Tactic:** Persistence
**Platforms:** Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1671

## Description

Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends.

OAuth is an open standard that allows users to authorize applications to access their information on their behalf. In a SaaS environment such as Microsoft 365 or Google Workspace, users may integrate applications to improve their workflow and achieve tasks.  

Leveraging application integrations may allow adversaries to persist in an environment – for example, by granting consent to an application from a high-privileged adversary-controlled account in order to maintain access to its data, even in the event of losing access to the account. In some cases, integrations may remain valid even after the original consenting user account is disabled. Application integrations may also allow adversaries to bypass multi-factor authentication requirements through the use of Application Access Tokens. Finally, they may enable persistent Automated Exfiltration over time.

Creating or adding a new application may require the adversary to create a dedicated Cloud Account for the application and assign it Additional Cloud Roles – for example, in Microsoft 365 environments, an application can only access resources via an associated service principal.

## Detection

### Detection Analytics

**Analytic 1487**

Detects suspicious OAuth application integrations within Office 365 or Google Workspace environments, such as new app registrations, unexpected consent grants, or privilege assignments. Defenders should correlate between application creation/modification events and associated user or service principal activity to identify persistence via app integrations.

**Analytic 1488**

Detects anomalous SaaS application integration activity across environments such as Slack, Salesforce, or other enterprise SaaS services. Focus is on unauthorized app additions, unusual permission grants, and persistence through service principal tokens.


## Mitigations

### M1047 - Audit

Periodically review SaaS integrations for unapproved or potentially malicious applications.

### M1042 - Disable or Remove Feature or Program

Do not allow users to add new application integrations into a SaaS environment. In Entra ID environments, consider enforcing the “Do not allow user consent” option.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors deceived victims into authorizing malicious connected apps to their organization's Salesforce portal.
