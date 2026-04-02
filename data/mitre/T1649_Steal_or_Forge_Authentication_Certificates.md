# T1649 - Steal or Forge Authentication Certificates

**Tactic:** Credential Access
**Platforms:** Identity Provider, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1649

## Description

Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Entra ID device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts.

Authentication certificates can be both stolen and forged. For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files), misplaced certificate files (i.e. Unsecured Credentials), or directly from the Windows certificate store via various crypto APIs. With appropriate enrollment rights, users and/or machines within a domain can also request and/or manually renew certificates from enterprise certificate authorities (CA). This enrollment process defines various settings and permissions associated with the certificate. Of note, the certificate’s extended key usage (EKU) values define signing, encryption, and authentication use cases, while the certificate’s subject alternative name (SAN) values define the certificate owner’s alternate names.

Abusing certificates for authentication credentials may enable other behaviors such as Lateral Movement. Certificate-related misconfigurations may also enable opportunities for Privilege Escalation, by way of allowing users to impersonate or assume privileged accounts or permissions via the identities (SANs) associated with a certificate. These abuses may also enable Persistence via stealing or forging certificates that can be used as Valid Accounts for the duration of the certificate's validity, despite user password resets. Authentication certificates can also be stolen and forged for machine accounts.

Adversaries who have access to root (or subordinate) CA certificate private keys (or mechanisms protecting/managing these keys) may also establish Persistence by forging arbitrary authentication certificates for the victim domain (known as “golden” certificates). Adversaries may also target certificates and related services in order to access other forms of credentials, such as Golden Ticket ticket-granting tickets (TGT) or NTLM plaintext.

## Detection

### Detection Analytics

**Analytic 0671**

Monitor for abnormal certificate enrollment and usage activity in Active Directory Certificate Services (AD CS), registry access to certificate storage locations, and unusual process executions that attempt to export or access private keys.

**Analytic 0672**

Monitor for file access to certificate directories, commands invoking OpenSSL or PKCS#12 utilities to export or modify certificates, and processes accessing sensitive key storage paths.

**Analytic 0673**

Monitor for security commands and API calls interacting with the Keychain, as well as file access attempts to stored certificates and private keys in ~/Library/Keychains or /Library/Keychains.

**Analytic 0674**

Monitor for abnormal certificate enrollment events in identity platforms, unexpected use of token-signing certificates, and unusual CA configuration modifications.


## Mitigations

### M1015 - Active Directory Configuration

Ensure certificate authorities (CA) are properly secured, including treating CA servers (and other resources hosting CA certificates) as tier 0 assets. Harden abusable CA settings and attributes.

For example, consider disabling the usage of AD CS certificate SANs within relevant authentication protocol settings to enforce strict user mappings and prevent certificates from authenticating as other identifies. Also consider enforcing CA Certificate Manager approval for the templates that include SAN as an issuance requirement.

### M1047 - Audit

Check and remediate unneeded existing authentication certificates as well as common abusable misconfigurations of CA settings and permissions, such as AD CS certificate enrollment permissions and published overly permissive certificate templates (which define available settings for created certificates). For example, available AD CS certificate templates can be checked via the Certificate Authority MMC snap-in (`certsrv.msc`). `certutil.exe` can also be used to examine various information within an AD CS CA database.

### M1042 - Disable or Remove Feature or Program

Consider disabling old/dangerous authentication protocols (e.g. NTLM), as well as unnecessary certificate features, such as potentially vulnerable AD CS web and other enrollment server roles.

### M1041 - Encrypt Sensitive Information

Ensure certificates as well as associated private keys are appropriately secured. Consider utilizing additional hardware credential protections such as trusted platform modules (TPM) or hardware security modules (HSM). Enforce HTTPS and enable Extended Protection for
Authentication.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can create and export various authentication certificates, including those associated with Azure AD joined/registered devices.

### S0002 - Mimikatz

Mimikatz's `CRYPTO` module can create and export various types of authentication certificates.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
