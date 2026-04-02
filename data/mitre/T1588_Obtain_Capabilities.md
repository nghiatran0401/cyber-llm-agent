# T1588 - Obtain Capabilities

**Tactic:** Resource Development
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1588

## Description

Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.

In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals.

In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.

## Detection

### Detection Analytics

**Analytic 1982**

Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Some server-side components of adversary tools may have default values set for SSL/TLS certificates. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.
Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.
Monitor for logged network traffic in response to a scan showing both protocol header and body values that may buy and/or steal capabilities that can be used during targeting. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.
Consider analyzing malware for features that may be associated with malware providers, such as compiler used, debugging artifacts, code similarities, or even group identifiers associated with specific Malware-as-a-Service (MaaS) offerings. Malware repositories can also be used to identify additional samples associated with the developers and the adversary utilizing their services. Identifying overlaps in malware use by different adversaries may indicate malware was obtained by the adversary rather than developed by them. In some cases, identifying overlapping characteristics in malware used by different adversaries may point to a shared quartermaster. Malware repositories can also be used to identify features of tool use associated with an adversary, such as watermarks in Cobalt Strike payloads.


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

_No campaigns documented._
