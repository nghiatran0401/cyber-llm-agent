# T1679 - Selective Exclusion

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1679

## Description

Adversaries may intentionally exclude certain files, folders, directories, file types, or system components from encryption or tampering during a ransomware or malicious payload execution. Some file extensions that adversaries may avoid encrypting include `.dll`, `.exe`, and `.lnk`.  

Adversaries may perform this behavior to avoid alerting users, to evade detection by security tools and analysts, or, in the case of ransomware, to ensure that the system remains operational enough to deliver the ransom notice. 

Exclusions may target files and components whose corruption would cause instability, break core services, or immediately expose the attack. By carefully avoiding these areas, adversaries maintain system responsiveness while minimizing indicators that could trigger alarms or otherwise inhibit achieving their goals.

## Detection

### Detection Analytics

**Analytic 2030**

A process with no prior history or outside of known whitelisted tools initiates file or registry modifications to configure exclusion rules for antivirus, backup, or file-handling systems. Or a file system enumeration for specific file names andcritical extensions like .dll, .exe, .sys, or specific directories such as 'Program Files' or security tool paths or system component discovery for the exclusion of the files or components.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1247 - Embargo

Embargo has avoided encrypting specific files and directories by leveraging a regular expression within the ransomware binary.

### S1245 - InvisibleFerret

InvisibleFerret has the capability to scan for file names, file extensions, and avoids pre-designated path names and file types.

### S1244 - Medusa Ransomware

Medusa Ransomware has avoided specified files, file extensions and folders to ensure successful execution of the payload and continued operations of the impacted device.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
