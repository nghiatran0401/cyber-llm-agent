# T1555 - Credentials from Password Stores

**Tactic:** Credential Access
**Platforms:** IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1555

## Description

Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

## Detection

### Detection Analytics

**Analytic 1198**

Monitors suspicious access to password stores such as LSASS, DPAPI, Windows Credential Manager, or browser credential databases. Detects anomalous process-to-process access (e.g., Mimikatz accessing LSASS) and correlation of credential store file reads with execution of non-standard processes.

**Analytic 1199**

Detects access to known password store files (e.g., /etc/shadow, GNOME Keyring, KWallet, browser credential databases). Monitors anomalous process read attempts and suspicious API calls that attempt to extract stored credentials.

**Analytic 1200**

Monitors Keychain database access and suspicious invocations of security and osascript utilities. Correlates process execution with attempts to dump or unlock Keychain data.

**Analytic 1201**

Detects attempts to access or enumerate cloud password/secrets storage services such as AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager. Monitors API calls for abnormal enumeration or bulk retrieval of secrets.


## Mitigations

### M1027 - Password Policies

The password for the user's login keychain can be changed from the user's login password. This increases the complexity for an adversary because they need to know an additional password.

Organizations may consider weighing the risk of storing credentials in password stores and web browsers. If system, software, or web browser credential disclosure is a significant concern, technical controls, policy, and user training may be used to prevent storage of credentials in improper locations.

### M1026 - Privileged Account Management

Limit the number of accounts and services with permission to query information from password stores to only those required. Ensure that accounts and services with permissions to query password stores only have access to the secrets they require.

### M1051 - Update Software

Perform regular software updates to mitigate exploitation risk.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla has the ability to steal credentials from FTP clients and wireless profiles.

### S0373 - Astaroth

Astaroth uses an external software known as NetPass to recover passwords.

### S1246 - BeaverTail

BeaverTail has collected keys stored for Solana stored in `.config/solana/id.json` and other login details associated with macOS within `/Library/Keychains/login.keychain` or for Linux within `/.local/share/keyrings`.

### S0484 - Carberp

Carberp's passw.plug plugin can gather account information from multiple instant messaging, email, and social media services, as well as FTP, VNC, and VPN clients.

### S0050 - CosmicDuke

CosmicDuke collects user credentials, including passwords, for various programs including popular instant messaging applications and email clients as well as WLAN keys.

### S1111 - DarkGate

DarkGate use Nirsoft Network Password Recovery or NetPass tools to steal stored RDP credentials in some malware versions.

### S0526 - KGH_SPY

KGH_SPY can collect credentials from WINSCP.

### S0349 - LaZagne

LaZagne can obtain credentials from databases, mail, and WiFi across multiple platforms.

### S0447 - Lokibot

Lokibot has stolen credentials from multiple applications and data sources including Windows OS credentials, email clients, FTP, and SFTP clients.

### S1156 - Manjusaka

Manjusaka extracts credentials from the Windows Registry associated with Premiumsoft Navicat, a utility used to facilitate access to various database types.

### S0167 - Matryoshka

Matryoshka is capable of stealing Outlook passwords.

### S1146 - MgBot

MgBot includes modules for stealing stored credentials from Outlook and Foxmail email client software.

### S0002 - Mimikatz

Mimikatz performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the credential vault and DPAPI.

### S1122 - Mispadu

Mispadu has obtained credentials from mail clients via NirSoft MailPassView.

### S0198 - NETWIRE

NETWIRE can retrieve passwords from messaging and mail client applications.

### S0138 - OLDBAIT

OLDBAIT collects credentials from several email clients.

### S0435 - PLEAD

PLEAD has the ability to steal saved passwords from Microsoft Outlook.

### S0048 - PinchDuke

PinchDuke steals credentials from compromised hosts. PinchDuke's credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by PinchDuke include ones associated with many sources such as The Bat!, Yahoo!, Mail.ru, Passport.Net, Google Talk, and Microsoft Outlook.

### S0378 - PoshC2

PoshC2 can decrypt passwords stored in the RDCMan configuration file.

### S0113 - Prikormka

A module in Prikormka collects passwords stored in applications installed on the victim.

### S0192 - Pupy

Pupy can use Lazagne for harvesting credentials.

### S0262 - QuasarRAT

QuasarRAT can obtain passwords from common FTP clients.

### S1240 - RedLine Stealer

RedLine Stealer has obtained credentials from VPN services, FTP clients and Instant Messenger (IM)/Chat clients.

### S1207 - XLoader

XLoader can collect credentials stored in email clients.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0024 - SolarWinds Compromise

During the SolarWinds Compromise, APT29 used account credentials they obtained to attempt access to Group Managed Service Account (gMSA) passwords.
