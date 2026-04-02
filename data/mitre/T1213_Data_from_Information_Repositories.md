# T1213 - Data from Information Repositories

**Tactic:** Collection
**Platforms:** IaaS, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1213

## Description

Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, such as Credential Access, Lateral Movement, or Defense Evasion, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization (i.e., Transfer Data to Cloud Account). 

The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials (i.e., Unsecured Credentials) 
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources
* Contact or other sensitive information about business partners and customers, including personally identifiable information (PII) 

Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include the following:

* Storage services such as IaaS databases, enterprise databases, and more specialized platforms such as customer relationship management (CRM) databases 
* Collaboration platforms such as SharePoint, Confluence, and code repositories
* Messaging platforms such as Slack and Microsoft Teams 

In some cases, information repositories have been improperly secured, typically by unintentionally allowing for overly-broad access by all users or even public access to unauthenticated users. This is particularly common with cloud-native or cloud-hosted services, such as AWS Relational Database Service (RDS), Redis, or ElasticSearch.

## Detection

### Detection Analytics

**Analytic 1160**

Programmatic or excessive access to file shares, SharePoint, or database repositories by users not typically interacting with them. This includes abnormal access by privileged accounts, enumeration of large numbers of files, or downloads of sensitive content in bursts.

**Analytic 1161**

Command-line tools (e.g., curl, rsync, wget, or custom Python scripts) used to scrape documentation systems or internal REST APIs. Unusual access patterns to knowledge base folders or shared team drives.

**Analytic 1162**

Abuse of SaaS platforms such as Confluence, GitHub, SharePoint Online, or Slack to access excessive internal documentation or export source code/data. Includes use of tokens or browser automation from unapproved IPs.

**Analytic 1163**

Access of mounted cloud shares or document repositories via browser, terminal, or Finder by users not typically interacting with those resources. Includes script-based enumeration or mass download.


## Mitigations

### M1047 - Audit

Consider periodic review of accounts and privileges for critical and sensitive repositories. Ensure that repositories such as cloud-hosted databases are not unintentionally exposed to the public, and that security groups assigned to them permit only necessary and authorized hosts.

### M1041 - Encrypt Sensitive Information

Encrypt data stored at rest in databases.

### M1032 - Multi-factor Authentication

Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

### M1060 - Out-of-Band Communications Channel

Create plans for leveraging a secure out-of-band communications channel, rather than existing in-network chat applications, in case of a security incident.

### M1054 - Software Configuration

Consider implementing data retention policies to automate periodically archiving and/or deleting data that is no longer needed.

### M1018 - User Account Management

Enforce the principle of least-privilege. Consider implementing access control mechanisms that include both authentication and authorization.

### M1017 - User Training

Develop and publish policies that define acceptable information to be stored in repositories.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1148 - Raccoon Stealer

Raccoon Stealer gathers information from repositories associated with cryptocurrency wallets and the Telegram messaging service.

### S1196 - Troll Stealer

Troll Stealer gathers information from the Government Public Key Infrastructure (GPKI) folder, associated with South Korean government public key infrastructure, on infected systems.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 accessed victims' internal knowledge repositories (wikis) to view sensitive corporate information on products, services, and internal business operations.
