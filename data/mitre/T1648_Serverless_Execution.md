# T1648 - Serverless Execution

**Tactic:** Execution
**Platforms:** IaaS, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1648

## Description

Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers. 

Adversaries may abuse these resources in various ways as a means of executing arbitrary commands. For example, adversaries may use serverless functions to execute malicious code, such as crypto-mining malware (i.e. Resource Hijacking). Adversaries may also create functions that enable further compromise of the cloud environment. For example, an adversary may use the `IAM:PassRole` permission in AWS or the `iam.serviceAccounts.actAs` permission in Google Cloud to add Additional Cloud Roles to a serverless cloud function, which may then be able to perform actions the original user cannot.

Serverless functions can also be invoked in response to cloud events (i.e. Event Triggered Execution), potentially enabling persistent execution over time. For example, in AWS environments, an adversary may create a Lambda function that automatically adds Additional Cloud Credentials to a user and a corresponding CloudWatch events rule that invokes that function whenever a new user is created. This is also possible in many cloud-based office application suites. For example, in Microsoft 365 environments, an adversary may create a Power Automate workflow that forwards all emails a user receives or creates anonymous sharing links whenever a user is granted access to a document in SharePoint. In Google Workspace environments, they may instead create an Apps Script that exfiltrates a user's data when they open a file.

## Detection

### Detection Analytics

**Analytic 1053**

Correlate creation or modification of serverless functions (e.g., AWS Lambda, GCP Cloud Functions, Azure Functions) with anomalous IAM role assignments or permissions escalation events. Detect subsequent executions of newly created functions that perform unexpected actions such as spawning outbound network connections, accessing sensitive resources, or creating additional credentials.

**Analytic 1054**

Monitor for creation of new Power Automate flows or equivalent automation scripts that trigger on user or file events. Detect anomalous actions performed by these automations, such as email forwarding, anonymous link creation, or unexpected API calls to external endpoints.

**Analytic 1055**

Track creation or update of SaaS automation scripts (e.g., Google Workspace Apps Script). Detect when these scripts are bound to user events such as file opens or account modifications, and correlate with subsequent abnormal API calls that exfiltrate or modify user data.


## Mitigations

### M1036 - Account Use Policies

Where possible, consider restricting access to and use of serverless functions. For examples, conditional access policies can be applied to users attempting to create workflows in Microsoft Power Automate. Google Apps Scripts that use OAuth can be limited by restricting access to high-risk OAuth scopes.

### M1018 - User Account Management

Remove permissions to create, modify, or run serverless resources from users that do not explicitly require them.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1091 - Pacu

Pacu can create malicious Lambda functions.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
