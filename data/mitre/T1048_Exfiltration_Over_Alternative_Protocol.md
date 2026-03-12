# T1048 - Exfiltration Over Alternative Protocol

**Tactic:** Exfiltration
**Platforms:** ESXi, IaaS, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1048

## Description

Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. 

Exfiltration Over Alternative Protocol can be done using various common operating system utilities such as Net/SMB or FTP. On macOS and Linux <code>curl</code> may be used to invoke protocols such as HTTP/S or FTP/S to exfiltrate data from a system.

Many IaaS and SaaS platforms (such as Microsoft Exchange, Microsoft SharePoint, GitHub, and AWS S3) support the direct download of files, emails, source code, and other sensitive information via the web console or Cloud API.

## Detection

### Detection Analytics

**Analytic 0367**

Detects unusual outbound file transfer behavior using protocols like FTP, SMB, SMTP, or DNS, involving non-standard processes, off-hour activity, or uncommonly high volume.

**Analytic 0368**

Detects file exfiltration using tools like curl, scp, or custom binaries over protocols such as FTP, HTTP/S, or DNS tunneling, especially outside baseline user behavior.

**Analytic 0369**

Detects non-native file transfer via curl, Python scripts, or AppleScript using uncommon protocols like FTP, SMTP, or DNS exfiltration through mDNSResponder abuse.

**Analytic 0370**

Detects access to cloud APIs or CLI tools to move or sync files from sensitive buckets to external endpoints using protocols like HTTPS or S3 APIs.

**Analytic 0371**

Detects outbound traffic from hostd/vpxa or guest VM interfaces using unauthorized protocols such as FTP, HTTP POST bursts, or long-lived DNS tunnels.


## Mitigations

### M1057 - Data Loss Prevention

Data loss prevention can detect and block sensitive data being uploaded via web browsers.

### M1037 - Filter Network Traffic

Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network. Cloud service providers support IP-based restrictions when accessing cloud resources. Consider using IP allowlisting along with user account management to ensure that data access is restricted not only to valid users but only from expected IP ranges to mitigate the use of stolen credentials to access data.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level.

### M1030 - Network Segmentation

Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network.

### M1022 - Restrict File and Directory Permissions

Use access control lists on cloud storage systems and objects.

### M1018 - User Account Management

Configure user permissions groups and roles for access to cloud storage. Implement strict Identity and Access Management (IAM) controls to prevent access to storage solutions except for the applications, users, and services that require access. Ensure that temporary access tokens are issued rather than permanent credentials, especially when access is being granted to entities outside of the internal security boundary.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can directly download cloud user data such as OneDrive files.

### S0482 - Bundlore

Bundlore uses the <code>curl -s -L -o</code> command to exfiltrate archived data to a URL.

### S0631 - Chaes

Chaes has exfiltrated its collected data from the infected machine to the C2, sometimes using the MIME protocol.

### S0503 - FrameworkPOS

FrameworkPOS can use DNS tunneling for exfiltration of credit card data.

### S0203 - Hydraq

Hydraq connects to a predefined domain on port 443 to exfil gathered information.

### S0641 - Kobalos

Kobalos can exfiltrate credentials over the network via UDP.

### S0428 - PoetRAT

PoetRAT has used a .NET tool named dog.exe to exiltrate information over an e-mail account.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
