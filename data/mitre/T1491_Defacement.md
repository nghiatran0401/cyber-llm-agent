# T1491 - Defacement

**Tactic:** Impact
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1491

## Description

Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages.

## Detection

### Detection Analytics

**Analytic 0662**

Adversary modifies website or application-hosted content via unauthorized file changes or script injections, often by exploiting web servers or CMS access.

**Analytic 0663**

Adversary gains shell access or uploads a malicious script to deface hosted web content in Nginx, Apache, or other services.

**Analytic 0664**

Adversary modifies internal or external site content through manipulated application bundles, hosted content, or web server configs.

**Analytic 0665**

Adversary defaces internal VM-hosted portals or web UIs by modifying static content on datastore-mounted paths.

**Analytic 0666**

Adversary uses compromised instance credentials or web application access to deface content hosted in S3 buckets, Azure Blob Storage, or GCP Buckets.


## Mitigations

### M1053 - Data Backup

Consider implementing IT disaster recovery plans that contain procedures for taking regular data backups that can be used to restore organizational data. Ensure backups are stored off system and is protected from common methods adversaries may use to gain access and destroy the backups to prevent recovery.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
