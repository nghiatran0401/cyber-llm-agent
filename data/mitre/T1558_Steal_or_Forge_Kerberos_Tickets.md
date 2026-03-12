# T1558 - Steal or Forge Kerberos Tickets

**Tactic:** Credential Access
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1558

## Description

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.

On Windows, the built-in <code>klist</code> utility can be used to list and analyze cached Kerberos tickets.

## Detection

### Detection Analytics

**Analytic 1443**

Detects anomalous Kerberos activity such as forged or stolen tickets by correlating malformed fields in logon events, RC4-encrypted TGTs, or TGS requests without corresponding TGT requests. Also detects suspicious processes accessing LSASS memory for ticket extraction.

**Analytic 1444**

Detects suspicious access to SSSD secrets database and Kerberos key material indicating ticket theft or replay attempts. Correlates anomalous file access with unusual Kerberos service ticket requests.

**Analytic 1445**

Detects attempts to forge or replay Kerberos tickets by monitoring Unified Logs for anomalous kinit/klist activity and correlating unusual authentication sequences.


## Mitigations

### M1015 - Active Directory Configuration

For containing the impact of a previously generated golden ticket, reset the built-in KRBTGT account password twice, which will invalidate any existing golden tickets that have been created with the KRBTGT hash and other Kerberos tickets derived from it. For each domain, change the KRBTGT account password once, force replication, and then change the password a second time. Consider rotating the KRBTGT account password every 180 days.

### M1047 - Audit

Perform audits or scans of systems, permissions, insecure software, insecure configurations, etc. to identify potential weaknesses.

### M1043 - Credential Access Protection

On Linux systems, protect resources with Security Enhanced Linux (SELinux) by defining entry points, process types, and file labels.

### M1041 - Encrypt Sensitive Information

Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible.

### M1027 - Password Policies

Ensure strong password length (ideally 25+ characters) and complexity for service accounts and that these passwords periodically expire. Also consider using Group Managed Service Accounts or another third party product such as password vaulting.

### M1026 - Privileged Account Management

Limit domain admin account permissions to domain controllers and limited servers. Delegate other admin functions to separate accounts.

Limit service accounts to minimal required privileges, including membership in privileged groups such as Domain Administrators.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
