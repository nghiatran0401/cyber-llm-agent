# T1218 - System Binary Proxy Execution

**Tactic:** Defense Evasion
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1218

## Description

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system. Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.

Similarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.

## Detection

### Detection Analytics

**Analytic 0226**

Execution of trusted, Microsoft-signed binaries such as `rundll32.exe`, `msiexec.exe`, or `regsvr32.exe` used to execute externally hosted, unsigned, or suspicious payloads through command-line parameters or network retrieval.

**Analytic 0227**

Execution of trusted system binaries (e.g., `split`, `tee`, `bash`, `env`) used in uncommon sequences or chained behaviors to execute malicious payloads or perform actions inconsistent with normal system or script behavior.

**Analytic 0228**

Use of system binaries such as `osascript`, `bash`, or `curl` to download or execute unsigned code or files in conjunction with application proxying.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Many native binaries may not be necessary within a given environment.

### M1038 - Execution Prevention

Consider using application control to prevent execution of binaries that are susceptible to abuse and not required for a given system or network.

### M1050 - Exploit Protection

Microsoft's Enhanced Mitigation Experience Toolkit (EMET) Attack Surface Reduction (ASR) feature can be used to block methods of using using trusted binaries to bypass application control.

### M1037 - Filter Network Traffic

Use network appliances to filter ingress or egress traffic and perform protocol-based filtering. Configure software on endpoints to filter network traffic.

### M1026 - Privileged Account Management

Restrict execution of particularly vulnerable binaries to privileged accounts or groups that need to use it to lessen the opportunities for malicious usage.

### M1021 - Restrict Web-Based Content

Restrict use of certain websites, block downloads/attachments, block Javascript, restrict browser extensions, etc.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
