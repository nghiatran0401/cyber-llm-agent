# T1651 - Cloud Administration Command

**Tactic:** Execution
**Platforms:** IaaS
**Reference:** https://attack.mitre.org/techniques/T1651

## Description

Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents.

If an adversary gains administrative access to a cloud environment, they may be able to abuse cloud management services to execute commands in the environment’s virtual machines. Additionally, an adversary that compromises a service provider or delegated administrator account may similarly be able to leverage a Trusted Relationship to execute commands in connected virtual machines.

## Detection

### Detection Analytics

**Analytic 1502**

Monitor for suspicious use of cloud-native administrative command services (e.g., AWS Systems Manager Run Command, Azure RunCommand, GCP OS Config) to execute code inside VMs. Detect anomalies such as commands/scripts executed by unexpected users, execution outside of maintenance windows, or commands initiated by service accounts not normally tied to administration. Correlate cloud control-plane activity logs with host-level execution (process creation, script execution) to validate if commands materialized inside the guest OS.


## Mitigations

### M1026 - Privileged Account Management

Limit the number of cloud accounts with permissions to remotely execute commands on virtual machines, and ensure that these are not used for day-to-day operations. In Azure, limit the number of accounts with the roles Azure Virtual Machine Contributer and above, and consider using temporary Just-in-Time (JIT) roles to avoid permanently assigning privileged access to virtual machines.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can execute commands on Azure virtual machines using the VM agent.

### S1091 - Pacu

Pacu can run commands on EC2 instances using AWS Systems Manager Run Command.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
