# T1613 - Container and Resource Discovery

**Tactic:** Discovery
**Platforms:** Containers
**Reference:** https://attack.mitre.org/techniques/T1613

## Description

Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.

These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs. In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution.

## Detection

### Detection Analytics

**Analytic 1352**

Detection of adversary attempts to enumerate containers, pods, nodes, and related resources within containerized environments. Defenders may observe anomalous API calls to Docker or Kubernetes (e.g., 'docker ps', 'kubectl get pods', 'kubectl get nodes'), unusual account activity against the Kubernetes dashboard, or unexpected queries against container metadata endpoints. These events should be correlated with user context and network activity to reveal resource discovery attempts.


## Mitigations

### M1035 - Limit Access to Resource Over Network

Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.

### M1030 - Network Segmentation

Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.

### M1018 - User Account Management

Enforce the principle of least privilege by limiting dashboard visibility to only the required users. When using Kubernetes, avoid giving users wildcard permissions or adding users to the `system:masters` group, and use `RoleBindings` rather than `ClusterRoleBindings` to limit user privileges to specific namespaces.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0601 - Hildegard

Hildegard has used masscan to search for kubelets and the kubelet API for additional running containers.

### S0683 - Peirates

Peirates can enumerate Kubernetes pods in a given namespace.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
