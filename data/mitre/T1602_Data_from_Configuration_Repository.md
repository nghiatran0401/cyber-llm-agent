# T1602 - Data from Configuration Repository

**Tactic:** Collection
**Platforms:** Network Devices
**Reference:** https://attack.mitre.org/techniques/T1602

## Description

Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.

Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.

## Detection

### Detection Analytics

**Analytic 1630**

Defenders may observe adversary attempts to extract configuration data from management repositories by monitoring for anomalous SNMP queries, API calls, or protocol requests (e.g., NETCONF, RESTCONF) that enumerate system configuration. Suspicious sequences include repeated queries from untrusted IPs, abnormal query types requesting sensitive configuration data, or repository access occurring outside of normal administrative maintenance windows. Abnormal authentication attempts, sudden enumeration of device inventory, or bulk data transfer of configuration files may also be observed.


## Mitigations

### M1041 - Encrypt Sensitive Information

Configure SNMPv3 to use the highest level of security (authPriv) available.

### M1037 - Filter Network Traffic

Apply extended ACLs to block unauthorized protocols outside the trusted network.

### M1031 - Network Intrusion Prevention

Configure intrusion prevention devices to detect SNMP queries and commands from unauthorized sources.

### M1030 - Network Segmentation

Segregate SNMP traffic on a separate management network.

### M1054 - Software Configuration

Allowlist MIB objects and implement SNMP views.

### M1051 - Update Software

Keep system images and software updated and migrate to SNMPv3.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
