# T1070 - Indicator Removal

**Tactic:** Defense Evasion
**Platforms:** Containers, ESXi, Linux, Network Devices, Office Suite, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1070

## Description

Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.

Removal of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.

## Detection

### Detection Analytics

**Analytic 0520**

Monitors sequences involving deletion/modification of logs, registry keys, scheduled tasks, or prefetch files following suspicious process activity or elevated access escalation.

**Analytic 0521**

Detects deletion or overwriting of bash history, syslog, audit logs, and .ssh metadata following privilege elevation or suspicious process spawning.

**Analytic 0522**

Detects clearing of unified logs, deletion of plist files tied to persistence, and manipulation of Terminal history after initial execution.

**Analytic 0523**

Monitors tampering with audit logs, volumes, or mounted storage often used for side-channel logging (e.g., /var/log inside containers) post-compromise.

**Analytic 0524**

Tracks suspicious use of ESXi shell commands or PowerCLI to delete logs, rotate system files, or tamper with hostd/vpxa history.

**Analytic 0525**

Detects deletion or hiding of security-related mail rules, audit mailboxes, or calendar/log sync artifacts indicative of tampering post-intrusion.


## Mitigations

### M1041 - Encrypt Sensitive Information

Obfuscate/encrypt event files locally and in transit to avoid giving feedback to an adversary.

### M1029 - Remote Data Storage

Automatically forward events to a log server or data repository to prevent conditions in which the adversary can locate and manipulate data on the local system. When possible, minimize time delay on event reporting to avoid prolonged storage on the local system.

### M1022 - Restrict File and Directory Permissions

Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1161 - BPFDoor

BPFDoor clears the file location `/proc/<PID>/environ` removing all environment variables for the process.

### S0239 - Bankshot

Bankshot deletes all artifacts associated with the malware from the infected machine.

### S0089 - BlackEnergy

BlackEnergy has removed the watermark associated with enabling the <code>TESTSIGNING</code> boot configuration option by removing the relevant strings in the <code>user32.dll.mui</code> of the system.

### S0527 - CSPY Downloader

CSPY Downloader has the ability to remove values it writes to the Registry.

### S1159 - DUSTTRAP

DUSTTRAP restores the `.text` section of compromised DLLs after malicious code is loaded into memory and before the file is closed.

### S0673 - DarkWatchman

DarkWatchman can uninstall malicious components from the Registry, stop processes, and clear the browser history.

### S0695 - Donut

Donut can erase file references to payloads in-memory after being reflectively loaded and executed.

### S0568 - EVILNUM

EVILNUM has a function called "DeleteLeftovers" to remove certain artifacts of the attack.

### S0696 - Flagpro

Flagpro can close specific Windows Security and Internet Explorer dialog boxes to mask external connections.

### S1044 - FunnyDream

FunnyDream has the ability to clean traces of malware deployment.

### S0697 - HermeticWiper

HermeticWiper can disable pop-up information about folders and desktop items and delete Registry keys to hide malicious services.

### S1132 - IPsec Helper

IPsec Helper can delete various registry keys related to its execution and use.

### S0449 - Maze

Maze has used the “Wow64RevertWow64FsRedirection” function following attempts to delete the shadow volumes, in order to leave the system in the same state as it was prior to redirection.

### S0455 - Metamorfo

Metamorfo has a command to delete a Registry key it uses, <code>\Software\Microsoft\Internet Explorer\notes</code>.

### S1135 - MultiLayer Wiper

MultiLayer Wiper uses a batch script to clear file system cache memory via the <code>ProcessIdleTasks</code> export in <code>advapi32.dll</code> as an anti-analysis and anti-forensics technique.

### S0691 - Neoichor

Neoichor can clear the browser history on a compromised host by changing the `ClearBrowsingHistoryOnExit` value to 1 in the `HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Privacy` Registry key.

### S0229 - Orz

Orz can overwrite Registry settings to reduce its visibility on the victim.

### S0448 - Rising Sun

Rising Sun can clear a memory blog in the process by overwriting it with junk bytes.

### S0461 - SDBbot

SDBbot has the ability to clean up and remove data structures from a compromised host.

### S0692 - SILENTTRINITY

SILENTTRINITY can remove artifacts from the compromised host, including created Registry keys.

### S0559 - SUNBURST

SUNBURST removed HTTP proxy registry values to clean up traces of execution.

### S1085 - Sardonic

Sardonic has the ability to delete created WMI objects to evade detections.

### S0596 - ShadowPad

ShadowPad has deleted arbitrary Registry values.

### S0589 - Sibot

Sibot will delete an associated registry key if a certain server response is received.

### S0603 - Stuxnet

Stuxnet can delete OLE Automation and SQL stored procedures used to store malicious payloads.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0029 - Cutting Edge

During Cutting Edge, threat actors cleared logs to remove traces of their activity and restored compromised systems to a clean state to bypass manufacturer mitigations for CVE-2023-46805 and CVE-2024-21887.

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 temporarily replaced legitimate utilities with their own, executed their payload, and then restored the original file.
