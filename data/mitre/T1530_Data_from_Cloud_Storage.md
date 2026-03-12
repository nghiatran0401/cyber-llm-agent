# T1530 - Data from Cloud Storage

**Tactic:** Collection
**Platforms:** IaaS, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1530

## Description

Adversaries may access data from cloud storage.

Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Workspace provide cloud-based document storage to users through services such as OneDrive and Google Drive, while SaaS application providers such as Slack, Confluence, Salesforce, and Dropbox may provide cloud storage solutions as a peripheral or primary use case of their platform. 

In some cases, as with IaaS-based cloud storage, there exists no overarching application (such as SQL or Elasticsearch) with which to interact with the stored objects: instead, data from these solutions is retrieved directly though the Cloud API. In SaaS applications, adversaries may be able to collect this data directly from APIs or backend cloud storage objects, rather than through their front-end application or interface (i.e., Data from Information Repositories). 

Adversaries may collect sensitive data from these cloud storage solutions. Providers typically offer security guides to help end users configure systems, though misconfigurations are a common problem. There have been numerous incidents where cloud storage has been improperly secured, typically by unintentionally allowing public access to unauthenticated users, overly-broad access by all users, or even access for any anonymous person outside the control of the Identity Access Management system without even needing basic user permissions.

This open access may expose various types of sensitive data, such as credit cards, personally identifiable information, or medical records.

Adversaries may also obtain then abuse leaked credentials from source repositories, logs, or other means as a way to gain access to cloud storage objects.

## Detection

### Detection Analytics

**Analytic 1328**

Spike in object access from new IAM user or role followed by data exfiltration to external IPs

**Analytic 1329**

OAuth token granted to external app followed by download of high-volume files in OneDrive/Google Drive

**Analytic 1330**

Internal user account accesses shared links outside org followed by mass file download


## Mitigations

### M1047 - Audit

Frequently check permissions on cloud storage to ensure proper permissions are set to deny open or unprivileged access to resources.

### M1041 - Encrypt Sensitive Information

Encrypt data stored at rest in cloud storage. Managed encryption keys can be rotated by most providers. At a minimum, ensure an incident response plan to storage breach includes rotating the keys and test for impact on client applications.

### M1037 - Filter Network Traffic

Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.

### M1032 - Multi-factor Authentication

Consider using multi-factor authentication to restrict access to resources and cloud storage APIs.

### M1022 - Restrict File and Directory Permissions

Use access control lists on storage systems and objects.

### M1018 - User Account Management

Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can collect files from a user’s OneDrive.

### S1091 - Pacu

Pacu can enumerate and download files stored in AWS storage services, such as S3 buckets.

### S0683 - Peirates

Peirates can dump the contents of AWS S3 buckets. It can also retrieve service account tokens from kOps buckets in Google Cloud Storage or S3.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0027 - C0027

During C0027, Scattered Spider accessed victim OneDrive environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.
