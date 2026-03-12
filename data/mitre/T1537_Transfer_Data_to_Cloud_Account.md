# T1537 - Transfer Data to Cloud Account

**Tactic:** Exfiltration
**Platforms:** IaaS, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1537

## Description

Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service.

A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.

Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymous file sharing links or, in Azure, a shared access signature (SAS) URI.

Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.

## Detection

### Detection Analytics

**Analytic 1580**

Detects snapshot sharing, backup exports, or data object transfers from victim-owned cloud accounts to other cloud identities within the same provider (e.g., AWS, Azure) using snapshot sharing, S3 bucket policy updates, or SAS URI generation.

**Analytic 1581**

Detects user activity that shares or syncs files with external domains via link generation, OneDrive external sharing, or file transfer actions involving non-whitelisted partner tenants.

**Analytic 1582**

Detects use of built-in SaaS sharing mechanisms to transfer ownership or share access of critical data to external tenants or untrusted users through API calls or link generation features.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can prevent and block sensitive data from being shared with individuals outside an organization.

### M1037 - Filter Network Traffic

Implement network-based filtering restrictions to prohibit data transfers to untrusted VPCs.

### M1054 - Software Configuration

Configure appropriate data sharing restrictions in cloud services. For example, external sharing in Microsoft SharePoint and Google Drive can be turned off altogether, blocked for certain domains, or restricted to certain users.

### M1018 - User Account Management

Limit user account and IAM policies to the least privileges required.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
