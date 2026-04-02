# T1204 - User Execution

**Tactic:** Execution
**Platforms:** Containers, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1204

## Description

An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing.

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after Internal Spearphishing.

Adversaries may also deceive users into performing actions such as:

* Enabling Remote Access Tools, allowing direct control of the system to the adversary
* Running malicious JavaScript in their browser, allowing adversaries to Steal Web Session Cookies
* Downloading and executing malware for User Execution
* Coerceing users to copy, paste, and execute malicious code manually

For example, tech support scams can be facilitated through Phishing, vishing, or various forms of user interaction. Adversaries can use a combination of these methods, such as spoofing and promoting toll-free numbers or call centers that are used to direct victims to malicious websites, to deliver and execute payloads containing malware or Remote Access Tools.

## Detection

### Detection Analytics

**Analytic 1314**

Cause→effect chain: (1) User-facing app (Office/PDF/archiver/browser) records an open/click or abnormal event, then (2) a downloaded file is created in a user-writable path and/or decompressed, (3) the parent user app spawns a living-off-the-land binary (e.g., powershell/cmd/mshta/rundll32/msiexec/wscript/expand/zip) or installer, and (4) immediate outbound HTTP(S)/DNS/SMB from the same lineage.

**Analytic 1315**

Cause→effect chain: (1) User app/browser/archiver logs an open/click or abnormal exit, (2) new executable/script/archive extracted into $HOME/Downloads, /tmp, or ~/.cache, (3) parent app spawns shell/interpreter (bash/sh/python/node/curl/wget) or desktop file, and (4) new outbound connection(s) from the child lineage.

**Analytic 1316**

Cause→effect chain: (1) unified logs show application open/click or crash for Safari/Chrome/Office/Preview/archiver, (2) file write/extraction into ~/Downloads, /private/var/folders/* or ~/Library, (3) parent app spawns osascript/bash/zsh/curl/python or opens a quarantined app with Gatekeeper prompts, (4) network egress from child.

**Analytic 1317**

Cause→effect chain in CI/dev desktops: (1) user triggers container run/pull after opening a doc/link/script, (2) newly created image/container uses unexpected external registry or entrypoint, (3) container starts and immediately egresses to suspicious destinations.

**Analytic 1318**

Cause→effect chain in cloud consoles: (1) user clicks link then invokes instance/image creation via API, (2) instance/image originates from external AMI or unknown image, (3) instance immediately egresses or retrieves payloads.


## Mitigations

### M1040 - Behavior Prevention on Endpoint

On Windows 10, enable Attack Surface Reduction (ASR) rules to prevent executable files from running unless they meet a prevalence, age, or trusted list criteria and to prevent Office applications from creating potentially malicious executable content by blocking malicious code from being written to disk. Note: cloud-delivered protection must be enabled to use certain rules.

### M1038 - Execution Prevention

Application control may be able to prevent the running of executables masquerading as other files.

### M1033 - Limit Software Installation

Where possible, consider requiring developers to pull from internal repositories containing verified and approved packages rather than from external ones.

### M1031 - Network Intrusion Prevention

If a link is being visited by a user, network intrusion prevention systems and systems designed to scan and remove malicious downloads can be used to block activity.

### M1021 - Restrict Web-Based Content

If a link is being visited by a user, block unknown or unused files in transit by default that should not be downloaded or by policy from suspicious sites as a best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc. Some download scanning devices can open and analyze compressed and encrypted formats, such as zip and rar that may be used to conceal malicious files.

### M1017 - User Training

Use user training as a way to bring awareness to common phishing and spearphishing techniques and how to raise suspicion for potentially malicious events.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1213 - Lumma Stealer

Lumma Stealer has been distributed through a fake CAPTCHA that presents instructions to the victim to open Windows Run window (“Windows Button + R”) and paste clipboard contents (“CTRL + V”) and press “Enter” to execute a Base64-encoded PowerShell.

### S1130 - Raspberry Robin

Raspberry Robin execution can rely on users directly interacting with malicious LNK files.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0037 - Water Curupira Pikabot Distribution

Water Curupira Pikabot Distribution requires users to interact with malicious attachments in order to start Pikabot installation.
