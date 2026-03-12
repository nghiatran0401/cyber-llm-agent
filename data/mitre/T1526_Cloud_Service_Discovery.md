# T1526 - Cloud Service Discovery

**Tactic:** Discovery
**Platforms:** IaaS, Identity Provider, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1526

## Description

An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Entra ID, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs.

Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Microsoft Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.

For example, Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.

Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses through Disable or Modify Tools or Disable or Modify Cloud Logs.

## Detection

### Detection Analytics

**Analytic 1127**

Unusual enumeration of services and resources through cloud APIs such as AWS CLI `describe-*`, Azure Resource Manager queries, or GCP project listings. Defender perspective includes anomalous API calls, unexpected volume of service enumeration, and correlation of discovery with recently compromised sessions.

**Analytic 1128**

Enumeration of directories, applications, or service principals through APIs such as Microsoft Graph or Okta API. Defender perspective includes unexpected listing of users, roles, applications, and abnormal access to identity management endpoints.

**Analytic 1129**

Discovery of SaaS services connected to productivity platforms (e.g., Microsoft 365, Google Workspace). Defender perspective includes unexpected enumeration of enabled services, API integrations, or OAuth applications tied to user accounts.

**Analytic 1130**

Discovery of connected SaaS applications, APIs, or configurations within platforms like Salesforce, Slack, or Zoom. Defender perspective includes enumeration of available integrations, abnormal querying of service metadata, and follow-on attempts to exploit or persist via discovered services.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can enumerate information about a variety of cloud services, such as Office 365 and Sharepoint instances or OpenID Configurations.

### S1091 - Pacu

Pacu can enumerate AWS services, such as CloudTrail and CloudWatch.

### S0684 - ROADTools

ROADTools can enumerate Azure AD applications and service principals.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
