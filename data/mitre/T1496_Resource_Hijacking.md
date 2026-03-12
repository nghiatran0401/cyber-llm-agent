# T1496 - Resource Hijacking

**Tactic:** Impact
**Platforms:** Containers, IaaS, Linux, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1496

## Description

Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. 

Resource hijacking may take a number of different forms. For example, adversaries may:

* Leverage compute resources in order to mine cryptocurrency
* Sell network bandwidth to proxy networks
* Generate SMS traffic for profit
* Abuse cloud-based messaging services to send large quantities of spam messages

In some cases, adversaries may leverage multiple types of Resource Hijacking at once.

## Detection

### Detection Analytics

**Analytic 0741**

Persistent high CPU utilization combined with suspicious command-line execution (e.g., mining tools or obfuscated scripts) and outbound connections to mining/proxy networks.

**Analytic 0742**

Abnormal CPU/memory usage by unauthorized processes with outbound connections to known mining pools or using cron jobs/scripts to maintain persistence.

**Analytic 0743**

Background launch agents/daemons with high CPU use and network access to external mining services.

**Analytic 0744**

Sudden spikes in cloud VM CPU usage with outbound traffic to mining pools and unauthorized instance creation.

**Analytic 0745**

High CPU usage by unauthorized containers running mining binaries or public proxy tools.

**Analytic 0746**

Abuse of cloud messaging platforms to send mass spam or consume quota-based resources.


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
