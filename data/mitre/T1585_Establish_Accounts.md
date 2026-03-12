# T1585 - Establish Accounts

**Tactic:** Resource Development
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1585

## Description

Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.

For operations incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, GitHub, Docker Hub, etc.). Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos.

Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for Phishing for Information or Phishing. In addition, establishing accounts may allow adversaries to abuse free services, such as registering for trial periods to Acquire Infrastructure for malicious purposes.

## Detection

### Detection Analytics

**Analytic 2005**

Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently created/modified accounts making numerous connection requests to accounts affiliated with your organization.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: Phishing).


## Mitigations

### M1056 - Pre-compromise

This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors created Salesforce trial accounts to register their malicious applications.
