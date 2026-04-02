# T1650 - Acquire Access

**Tactic:** Resource Development
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1650

## Description

Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems. In some cases, adversary groups may form partnerships to share compromised systems with each other.

Footholds to compromised systems may take a variety of forms, such as access to planted backdoors (e.g., Web Shell) or established access via External Remote Services. In some cases, access brokers will implant compromised systems with a “load” that can be used to install additional malware for paying customers.

By leveraging existing access broker networks rather than developing or obtaining their own initial access capabilities, an adversary can potentially reduce the resources required to gain a foothold on a target network and focus their efforts on later stages of compromise. Adversaries may prioritize acquiring access to systems that have been determined to lack security monitoring or that have high privileges, or systems that belong to organizations in a particular sector.

In some cases, purchasing access to an organization in sectors such as IT contracting, software development, or telecommunications may allow an adversary to compromise additional victims via a Trusted Relationship, Multi-Factor Authentication Interception, or even Supply Chain Compromise.

**Note:** while this technique is distinct from other behaviors such as Purchase Technical Data and Credentials, they may often be used in conjunction (especially where the acquired foothold requires Valid Accounts).

## Detection

### Detection Analytics

**Analytic 2016**

Much of this takes place outside the visibility of the target organization, making detection difficult for defenders. 

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.


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
