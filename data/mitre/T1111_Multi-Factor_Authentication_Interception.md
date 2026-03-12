# T1111 - Multi-Factor Authentication Interception

**Tactic:** Credential Access
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1111

## Description

Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. 

If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.

Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes).

Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.

## Detection

### Detection Analytics

**Analytic 0687**

Behavior chain involving unexpected API calls to capture keyboard input, driver loads for keyloggers, or remote use of smart card authentication via logon sessions not initiated by local user interaction

**Analytic 0688**

Detection of unauthorized keylogger behavior through access to `/dev/input`, loading kernel modules (e.g., via insmod), or polling user input devices from non-user shells

**Analytic 0689**

Processes accessing TCC-protected input APIs or polling HID services without user interaction, or dynamically loaded keylogging frameworks using accessibility privileges


## Mitigations

### M1017 - User Training

Remove smart cards when not in use.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1104 - SLOWPULSE

SLOWPULSE can log credentials on compromised Pulse Secure VPNs during the `DSAuth::AceAuthServer::checkUsernamePassword`ACE-2FA authentication procedure.

### S0018 - Sykipot

Sykipot is known to contain functionality that enables targeting of smart card technologies to proxy authentication for connections to restricted network resources using detected hardware tokens.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0049 - Leviathan Australian Intrusions

Leviathan abused compromised appliance access to collect multifactor authentication token values during Leviathan Australian Intrusions.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used a custom collection method to intercept two-factor authentication soft tokens.
