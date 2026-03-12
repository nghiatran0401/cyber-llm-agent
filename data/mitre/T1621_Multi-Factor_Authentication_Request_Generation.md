# T1621 - Multi-Factor Authentication Request Generation

**Tactic:** Credential Access
**Platforms:** IaaS, Identity Provider, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1621

## Description

Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

Adversaries in possession of credentials to Valid Accounts may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account. If adversaries lack credentials to victim accounts, they may also abuse automatic push notification generation when this option is configured for self-service password reset (SSPR).

In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to “MFA fatigue.”

## Detection

### Detection Analytics

**Analytic 0449**

Monitor for excessive or anomalous MFA push notifications or token requests, especially when login attempts originate from unusual IPs or geolocations and do not correspond to legitimate user-initiated sessions.

**Analytic 0450**

Detect abnormal MFA activity within cloud service provider logs, such as repeated generation of MFA challenges for the same user session or mismatched MFA device and login origin.

**Analytic 0451**

Detect repeated failed login events followed by MFA challenges triggered in rapid succession, especially if originating from service accounts or anomalous IP addresses.

**Analytic 0452**

Monitor PAM and syslog entries for unusual frequency of login attempts that trigger MFA prompts, particularly when MFA challenges do not match expected user behavior.

**Analytic 0453**

Detect anomalous OAuth or SSO logins that repeatedly generate MFA challenges, particularly where MFA approvals are denied or timed out by the user.

**Analytic 0454**

Detect user account logon attempts that trigger multiple MFA challenges through enterprise identity integrations, especially if MFA push requests are generated without successful interactive login.


## Mitigations

### M1036 - Account Use Policies

Enable account restrictions to prevent login attempts, and the subsequent 2FA/MFA service requests, from being initiated from suspicious locations or when the source of the login attempts do not match the location of the 2FA/MFA smart device. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges.

### M1032 - Multi-factor Authentication

Implement more secure 2FA/MFA mechanisms in replacement of simple push or one-click 2FA/MFA options. For example, having users enter a one-time code provided by the login screen into the 2FA/MFA application or utilizing other out-of-band 2FA/MFA mechanisms (such as rotating code-based hardware tokens providing rotating codes that need an accompanying user pin) may be more secure. Furthermore, change default configurations and implement limits upon the maximum number of 2FA/MFA request prompts that can be sent to users in period of time.

### M1017 - User Training

Train users to only accept 2FA/MFA requests from login attempts they initiated, to review source location of the login attempt prompting the 2FA/MFA requests, and to report suspicious/unsolicited prompts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0027 - C0027

During C0027, Scattered Spider attempted to gain access by continuously sending MFA messages to the victim until they accept the MFA push challenge.
