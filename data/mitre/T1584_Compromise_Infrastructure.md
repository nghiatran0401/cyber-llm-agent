# T1584 - Compromise Infrastructure

**Tactic:** Resource Development
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1584

## Description

Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle. Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.

Use of compromised infrastructure allows adversaries to stage, launch, and execute operations. Compromised infrastructure can help adversary operations blend in with traffic that is seen as normal, such as contact with high reputation or trusted sites. For example, adversaries may leverage compromised infrastructure (potentially also in conjunction with Digital Certificates) to further blend in and support staged information gathering and/or Phishing campaigns. Adversaries may also compromise numerous machines to support Proxy and/or proxyware services or to form a botnet. Additionally, adversaries may compromise infrastructure residing in close proximity to a target in order to gain Initial Access via Wi-Fi Networks.

By using compromised infrastructure, adversaries may enable follow-on malicious operations. Prior to targeting, adversaries may also compromise the infrastructure of other adversaries.

## Detection

### Detection Analytics

**Analytic 2017**

Once adversaries have provisioned compromised infrastructure (ex: a server for use in command and control), internet scans may help proactively discover compromised infrastructure. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software.
Consider monitoring for anomalous changes to domain registrant information and/or domain resolution information that may indicate the compromise of a domain. Efforts may need to be tailored to specific domains of interest as benign registration and resolution changes are a common occurrence on the internet.
Monitor for queried domain name system (DNS) registry data that may compromise third-party infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Monitor for logged domain name system (DNS) data that may compromise third-party infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Monitor for contextual data about an Internet-facing resource gathered from a scan, such as running services or ports that may compromise third-party infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.


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

### C0051 - APT28 Nearest Neighbor Campaign

During APT28 Nearest Neighbor Campaign, APT28 compromised third-party infrastructure in physical proximity to targets of interest for follow-on activities.

### C0043 - Indian Critical Infrastructure Intrusions

Indian Critical Infrastructure Intrusions included the use of compromised infrastructure, such as DVR and IP camera devices, for command and control purposes in ShadowPad activity.
