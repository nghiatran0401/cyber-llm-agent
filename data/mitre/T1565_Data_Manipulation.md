# T1565 - Data Manipulation

**Tactic:** Impact
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1565

## Description

Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

## Detection

### Detection Analytics

**Analytic 0162**

Correlate unauthorized or anomalous file modifications, deletions, or metadata changes with suspicious process execution or API calls. Detect abnormal changes to structured data (e.g., database files, logs, financial records) outside expected business process activity.

**Analytic 0163**

Detect unauthorized manipulation of log files, database entries, or system configuration files through auditd and syslog. Correlate shell commands that alter HISTFILE or data-related processes with abnormal file access patterns.

**Analytic 0164**

Detect manipulation of system or application files in `/Library`, `/System`, or user data directories using FSEvents and Unified Logs. Identify anomalous process execution modifying plist files, structured data, or logs outside expected update cycles.


## Mitigations

### M1041 - Encrypt Sensitive Information

Consider encrypting important information to reduce an adversary’s ability to perform tailored data modifications.

### M1030 - Network Segmentation

Identify critical business and system processes that may be targeted by adversaries and work to isolate and secure those systems against unauthorized access and tampering.

### M1029 - Remote Data Storage

Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and manipulate backups.

### M1022 - Restrict File and Directory Permissions

Ensure least privilege principles are applied to important information resources to reduce exposure to data manipulation risk.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
