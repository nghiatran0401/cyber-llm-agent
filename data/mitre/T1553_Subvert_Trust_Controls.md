# T1553 - Subvert Trust Controls

**Tactic:** Defense Evasion
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1553

## Description

Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.

Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct File and Directory Permissions Modification or Modify Registry in support of subverting these controls. Adversaries may also create or steal code signing certificates to acquire trust on target systems.

## Detection

### Detection Analytics

**Analytic 1246**

Detection correlates abnormal installation or modification of root or code-signing certificates, creation/modification of suspicious registry keys for trust providers, and unusual module loads from non-standard locations. Identifies unsigned or improperly signed executables bypassing trust prompts, combined with persistence artifacts.

**Analytic 1247**

Detection monitors extended attribute manipulation (xattr) to strip quarantine or trust metadata, anomalous installation of root certificates in /etc/ssl or /usr/local/share/ca-certificates, and unauthorized modification of system trust stores. Correlates with unexpected process execution involving package managers or custom certificate utilities.

**Analytic 1248**

Detection monitors modification of code signing attributes, Gatekeeper/quarantine flags, and insertion of new trust certificates via security add-trusted-cert. Identifies adversary use of xattr to strip quarantine flags from downloaded binaries. Correlates with abnormal module loads bypassing SIP protections.


## Mitigations

### M1038 - Execution Prevention

System settings can prevent applications from running that haven't been downloaded through the Apple Store (or other legitimate repositories) which can help mitigate some of these issues. Also enable application control solutions such as AppLocker and/or Device Guard to block the loading of malicious content.

### M1028 - Operating System Configuration

Windows Group Policy can be used to manage root certificates and the <code>Flags</code> value of <code>HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\ProtectedRoots</code> can be set to 1 to prevent non-administrator users from making further root installations into their own HKCU certificate store.

### M1026 - Privileged Account Management

Manage the creation, modification, use, and permissions associated to privileged accounts, including SYSTEM and root.

### M1024 - Restrict Registry Permissions

Ensure proper permissions are set for Registry hives to prevent users from modifying keys related to SIP and trust provider components. Components may still be able to be hijacked to suitable functions already present on disk if malicious modifications to Registry keys are not prevented.

### M1054 - Software Configuration

HTTP Public Key Pinning (HPKP) is one method to mitigate potential Adversary-in-the-Middle situations where and adversary uses a mis-issued or fraudulent certificate to intercept encrypted communications by enforcing use of an expected certificate.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
