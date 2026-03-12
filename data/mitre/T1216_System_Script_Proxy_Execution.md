# T1216 - System Script Proxy Execution

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1216

## Description

Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.

## Detection

### Detection Analytics

**Analytic 1288**

Execution of Microsoft-signed scripts (e.g., pubprn.vbs, installutil.exe, wscript.exe, cscript.exe) used to proxy execution of untrusted or external binaries. Behavior is detected through command-line process lineage, child process spawning, and unsigned payload execution from signed parent.


## Mitigations

### M1038 - Execution Prevention

Certain signed scripts that can be used to execute other programs may not be necessary within a given environment. Use application control configured to block execution of these scripts if they are not required for a given system or network to prevent potential misuse by adversaries.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
