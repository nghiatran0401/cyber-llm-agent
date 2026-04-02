# T1110 - Brute Force

**Tactic:** Credential Access
**Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1110

## Description

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as OS Credential Dumping, Account Discovery, or Password Policy Discovery. Adversaries may also combine brute forcing activity with behaviors such as External Remote Services as part of Initial Access. 

If an adversary guesses the correct password but fails to login to a compromised account due to location-based conditional access policies, they may change their infrastructure until they match the victim’s location and therefore bypass those policies.

## Detection

### Detection Analytics

**Analytic 1275**

High volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe

**Analytic 1276**

Multiple authentication failures for valid or invalid users followed by success from same IP/user

**Analytic 1277**

Password spraying or brute force attempts across user pool within short time intervals

**Analytic 1278**

Multiple failed authentications in unified logs (e.g., loginwindow or sshd)

**Analytic 1279**

Excessive login attempts followed by success from SaaS apps like O365, Dropbox, etc.


## Mitigations

### M1036 - Account Use Policies

Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges. Consider blocking risky authentication requests, such as those originating from anonymizing services/proxies.

### M1032 - Multi-factor Authentication

Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.

### M1027 - Password Policies

Refer to NIST guidelines when creating password policies.

### M1018 - User Account Management

Proactively reset accounts that are known to be part of breached credentials either immediately, or after detecting bruteforce attempts.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a module to perform brute force attacks on a system.

### S0220 - Chaos

Chaos conducts brute force attacks against SSH services to gain initial access.

### S0488 - CrackMapExec

CrackMapExec can brute force supplied user credentials across a network range.

### S0599 - Kinsing

Kinsing has attempted to brute force hosts over SSH.

### S0378 - PoshC2

PoshC2 has modules for brute forcing local administrator and AD user accounts.

### S0583 - Pysa

Pysa has used brute force attempts against a central management console, as well as some Active Directory accounts.

### S0650 - QakBot

QakBot can conduct brute force attacks to capture credentials.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0025 - 2016 Ukraine Electric Power Attack

During the 2016 Ukraine Electric Power Attack, Sandworm Team used a script to attempt RPC authentication against a number of hosts.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group performed brute force attacks against administrator accounts.
