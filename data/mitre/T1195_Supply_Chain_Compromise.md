# T1195 - Supply Chain Compromise

**Tactic:** Initial Access
**Platforms:** Linux, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1195

## Description

Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

* Manipulation of development tools
* Manipulation of a development environment
* Manipulation of source code repositories (public or private)
* Manipulation of source code in open-source dependencies
* Manipulation of software update/distribution mechanisms
* Compromised/infected system images (removable media infected at the factory) 
* Replacement of legitimate software with modified versions
* Sales of modified/counterfeit products to legitimate distributors
* Shipment interdiction

While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. Adversaries may limit targeting to a desired victim set or distribute malicious software to a broad set of consumers but only follow up with specific victims. Popular open-source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.

In some cases, adversaries may conduct “second-order” supply chain compromises by leveraging the access gained from an initial supply chain compromise to further compromise a software component. This may allow the threat actor to spread to even more victims.

## Detection

### Detection Analytics

**Analytic 1480**

1) New or updated software is delivered/installed from atypical sources or with signature/hash mismatches; 2) installer/updater writes binaries to unexpected paths or replaces existing signed files; 3) first run causes unsigned/abnormally signed modules to load or child processes to execute, optionally followed by network egress to new destinations.

**Analytic 1481**

1) Package manager or curl/wget installs/upgrades from non-approved repos or unsigned packages; 2) new ELF written into PATH directories or replacement of existing binaries/libraries; 3) first run leads to unexpected child processes or outbound connections.

**Analytic 1482**

1) pkg/notarization installs from atypical sources or with Gatekeeper/AMFI warnings; 2) new Mach-O written into /Applications or ~/Library paths or substitution of signed components; 3) first run from installer spawns unsigned children or exfil.


## Mitigations

### M1013 - Application Developer Guidance

Application developers should be cautious when selecting third-party libraries to integrate into their application. Additionally, where possible, developers should lock software dependencies to specific versions rather than pulling the latest version on build.

### M1046 - Boot Integrity

Use secure methods to boot a system and verify the integrity of the operating system and loading mechanisms.

### M1033 - Limit Software Installation

Where possible, consider requiring developers to pull from internal repositories containing verified and approved packages rather than from external ones.

### M1051 - Update Software

A patch management process should be implemented to check unused dependencies, unmaintained and/or previously vulnerable dependencies, unnecessary features, components, files, and documentation.

### M1018 - User Account Management

Implement robust user account management practices to limit permissions associated with software execution. Ensure that software runs with the lowest necessary privileges, avoiding the use of root or administrator accounts when possible. By restricting permissions, you can minimize the risk of propagation and unauthorized actions in the event of a supply chain compromise, reducing the attack surface for adversaries to exploit within compromised systems.

### M1016 - Vulnerability Scanning

Continuous monitoring of vulnerability sources and the use of automatic and manual code review tools should also be implemented as well.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1213 - Lumma Stealer

Lumma Stealer has been delivered through cracked software downloads.

### S1148 - Raccoon Stealer

Raccoon Stealer has been distributed through cracked software downloads.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
