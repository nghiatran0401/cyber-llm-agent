# T1599 - Network Boundary Bridging

**Tactic:** Defense Evasion
**Platforms:** Network Devices
**Reference:** https://attack.mitre.org/techniques/T1599

## Description

Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.

Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks.  They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections.  Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications.  To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised.

When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance.  By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via Multi-hop Proxy or exfiltration of data via Traffic Duplication. Adversaries may also target internal devices responsible for network segmentation and abuse these in conjunction with Internal Proxy to achieve the same goals.  In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments.

## Detection

### Detection Analytics

**Analytic 0015**

From a defender’s perspective, suspicious bridging is observed when network devices begin allowing traffic that contradicts existing segmentation or access policies. Observable behaviors include sudden modifications to ACLs or firewall rules, unusual cross-boundary traffic flows (e.g., east-west communications across separated VLANs), or simultaneous ingress/egress anomalies. Multi-event correlation is key: configuration changes on a router/firewall followed by unexpected traffic patterns, especially from unusual sources, is a strong indicator of compromise.


## Mitigations

### M1043 - Credential Access Protection

Some embedded network devices are capable of storing passwords for local accounts in either plain-text or encrypted formats.  Ensure that, where available, local passwords are always encrypted, per vendor recommendations.

### M1037 - Filter Network Traffic

Upon identifying a compromised network device being used to bridge a network boundary, block the malicious packets using an unaffected network device in path, such as a firewall or a router that has not been compromised.  Continue to monitor for additional activity and to ensure that the blocks are indeed effective.

### M1032 - Multi-factor Authentication

Use multi-factor authentication for user and privileged accounts. Most embedded network devices support TACACS+ and/or RADIUS.  Follow vendor prescribed best practices for hardening access control.

### M1027 - Password Policies

Refer to NIST guidelines when creating password policies.

### M1026 - Privileged Account Management

Restrict administrator accounts to as few individuals as possible, following least privilege principles.  Prevent credential overlap across systems of administrator and privileged accounts, particularly between network and non-network platforms, such as servers or endpoints.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

### C0043 - Indian Critical Infrastructure Intrusions

Indian Critical Infrastructure Intrusions involved the use of FRP to bridge network boundaries and overcome NAT. Indian Critical Infrastructure Intrusions also involved the use of VPN tunnels with a potentially compromised MSP entity allowing for direct access to critical infrastructure entity networks.
