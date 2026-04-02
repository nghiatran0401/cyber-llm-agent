# T1600 - Weaken Encryption

**Tactic:** Defense Evasion
**Platforms:** Network Devices
**Reference:** https://attack.mitre.org/techniques/T1600

## Description

Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.

Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.

Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as Modify System Image, Reduce Key Space, and Disable Crypto Hardware, an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts.

## Detection

### Detection Analytics

**Analytic 0961**

Defenders may observe unauthorized modifications to encryption-related configuration files, firmware, or crypto modules on network devices. Suspicious patterns include changes to cipher suite configurations, unexpected firmware updates affecting crypto libraries, disabling of hardware cryptographic accelerators, or reductions in key length policies. Correlating configuration changes with anomalies in encrypted traffic characteristics (e.g., weaker ciphers or sudden plaintext transmission) strengthens detection.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
