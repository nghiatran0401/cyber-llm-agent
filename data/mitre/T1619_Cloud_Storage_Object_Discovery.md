# T1619 - Cloud Storage Object Discovery

**Tactic:** Discovery
**Platforms:** IaaS
**Reference:** https://attack.mitre.org/techniques/T1619

## Description

Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.  Similar to File and Directory Discovery on a local host, after identifying available storage services (i.e. Cloud Infrastructure Discovery) adversaries may access the contents/objects stored in cloud infrastructure.

Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage. Examples include ListObjectsV2 in AWS and List Blobs in Azure .

## Detection

### Detection Analytics

**Analytic 1594**

Detection of suspicious enumeration of cloud storage objects via API calls such as AWS S3 ListObjectsV2, Azure List Blobs, or GCP ListObjects. Correlate access with account role, user context, and prior authentication activity to identify anomalous usage patterns (e.g., unusual account, unexpected regions, or large-scale enumeration in short time windows).


## Mitigations

### M1018 - User Account Management

Restrict granting of permissions related to listing objects in cloud storage to necessary accounts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1091 - Pacu

Pacu can enumerate AWS storage services, such as S3 buckets and Elastic Block Store volumes.

### S0683 - Peirates

Peirates can list AWS S3 buckets.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
