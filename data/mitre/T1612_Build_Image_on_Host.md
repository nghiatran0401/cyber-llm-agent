# T1612 - Build Image on Host

**Tactic:** Defense Evasion
**Platforms:** Containers
**Reference:** https://attack.mitre.org/techniques/T1612

## Description

Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote <code>build</code> request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.

An adversary may take advantage of that <code>build</code> API to build a custom image on the host that includes malware downloaded from their C2 server, and then they may utilize Deploy Container using that custom image. If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image. If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment.

## Detection

### Detection Analytics

**Analytic 1261**

Detection of container image build activity directly on the host using Docker or Kubernetes APIs. Defenders may observe Docker build requests, anomalous Dockerfile instructions (such as downloading code from unknown IPs), or creation of new images followed by immediate deployment. This behavior chain typically consists of an unexpected image creation event correlated with outbound network communication to non-standard or untrusted destinations.


## Mitigations

### M1047 - Audit

Audit images deployed within the environment to ensure they do not contain any malicious components.

### M1035 - Limit Access to Resource Over Network

Limit communications with the container service to local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API on port 2375. Instead, communicate with the Docker API over TLS on port 2376.

### M1030 - Network Segmentation

Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.

### M1026 - Privileged Account Management

Ensure containers are not running as root by default. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
