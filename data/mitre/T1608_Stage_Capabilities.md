# T1608 - Stage Capabilities

**Tactic:** Resource Development
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1608

## Description

Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications.

Staging of capabilities can aid the adversary in a number of initial access and post-compromise behaviors, including (but not limited to):

* Staging web resources necessary to conduct Drive-by Compromise when a user browses to a site.
* Staging web resources for a link target to be used with spearphishing.
* Uploading malware or tools to a location accessible to a victim network to enable Ingress Tool Transfer.
* Installing a previously acquired SSL/TLS certificate to use to encrypt command and control traffic (ex: Asymmetric Cryptography with Web Protocols).

## Detection

### Detection Analytics

**Analytic 1971**

If infrastructure or patterns in malware, tooling, certificates, or malicious web content have been previously identified, internet scanning may uncover when an adversary has staged their capabilities.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as initial access and post-compromise behaviors.


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
