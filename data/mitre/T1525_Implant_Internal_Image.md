# T1525 - Implant Internal Image

**Tactic:** Persistence
**Platforms:** Containers, IaaS
**Reference:** https://attack.mitre.org/techniques/T1525

## Description

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike Upload Malware, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.

A tool has been developed to facilitate planting backdoors in cloud container images. If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell.

## Detection

### Detection Analytics

**Analytic 0946**

Implantation of malicious code into container images followed by registry push and use in new deployments.

**Analytic 0947**

Creation or modification of cloud virtual machine images (AMIs, custom images) with persistence mechanisms, followed by infrastructure provisioning that uses these implanted images.


## Mitigations

### M1047 - Audit

Periodically check the integrity of images and containers used in cloud deployments to ensure they have not been modified to include malicious software.

### M1045 - Code Signing

Several cloud service providers support content trust models that require container images be signed by trusted sources.

### M1026 - Privileged Account Management

Limit permissions associated with creating and modifying platform images or containers based on the principle of least privilege.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
