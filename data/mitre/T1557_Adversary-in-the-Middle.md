# T1557 - Adversary-in-the-Middle

**Tactic:** Collection, Credential Access
**Platforms:** Linux, Network Devices, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1557

## Description

Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or replay attacks (Exploitation for Credential Access). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.

For example, adversaries may manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware. Adversaries may also manipulate DNS and leverage their position in order to intercept user credentials, including access tokens (Steal Application Access Token) and session cookies (Steal Web Session Cookie). Downgrade Attacks can also be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of communication protocol (SSL/TLS) or encryption algorithm.

Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in Transmitted Data Manipulation. Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to Impair Defenses and/or in support of a Network Denial of Service.

## Detection

### Detection Analytics

**Analytic 0823**

Detects suspicious DNS/ARP poisoning attempts, unauthorized modifications to registry/network configuration, or abnormal TLS downgrade activity. Correlates changes in system configuration with subsequent unusual network flows or authentication events.

**Analytic 0824**

Detects unauthorized edits to /etc/hosts, /etc/resolv.conf, or suspicious ARP broadcasts. Correlates file modifications with subsequent unexpected network sessions or service creation.

**Analytic 0825**

Detects unauthorized edits to system configuration profiles, unexpected certificate trust changes, or abnormal ARP/DNS patterns indicative of interception.

**Analytic 0826**

Detects unauthorized firmware or configuration changes enabling adversary-in-the-middle positioning (e.g., route injection, DNS spoofing, SSL downgrade). Behavioral analytics focus on sudden changes to routing tables or image file integrity failures.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Disable legacy network protocols that may be used   to intercept network traffic if applicable, especially those that are not needed within an environment.

### M1041 - Encrypt Sensitive Information

Ensure that all wired and/or wireless traffic is encrypted appropriately. Use best practices for authentication protocols, such as Kerberos, and ensure web traffic that may contain credentials is protected by SSL/TLS.

### M1037 - Filter Network Traffic

Use network appliances and host-based security software to block network traffic that is not necessary within the environment, such as legacy protocols that may be leveraged for AiTM conditions.

### M1035 - Limit Access to Resource Over Network

Limit access to network infrastructure and resources that can be used to reshape traffic or otherwise produce AiTM conditions.

### M1031 - Network Intrusion Prevention

Network intrusion detection and prevention systems that can identify traffic patterns indicative of AiTM activity can be used to mitigate activity at the network level.

### M1030 - Network Segmentation

Network segmentation can be used to isolate infrastructure components that do not require broad network access. This may mitigate, or at least alleviate, the scope of AiTM activity.

### M1017 - User Training

Train users to be suspicious about certificate errors. Adversaries may use their own certificates in an attempt to intercept HTTPS traffic. Certificate errors may arise when the application’s certificate does not match the one expected by the host.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0281 - Dok

Dok proxies web traffic to potentially monitor and alter victim HTTP(S) traffic.

### S1188 - Line Runner

Line Runner intercepts HTTP requests to the victim Cisco ASA, looking for a request with a 32-character, victim dependent parameter. If that parameter matches a value in the malware, a contained payload is then written to a Lua script and executed.

### S1131 - NPPSPY

NPPSPY opens a new network listener for the <code>mpnotify.exe</code> process that is typically contacted by the Winlogon process in Windows. A new, alternative RPC channel is set up with a malicious DLL recording plaintext credentials entered into Winlogon, effectively intercepting and redirecting the logon information.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0046 - ArcaneDoor

ArcaneDoor included interception of HTTP traffic to victim devices to identify and parse command and control information sent to the device.
