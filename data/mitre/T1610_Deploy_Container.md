# T1610 - Deploy Container

**Tactic:** Defense Evasion, Execution
**Platforms:** Containers
**Reference:** https://attack.mitre.org/techniques/T1610

## Description

Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment. In Kubernetes environments, an adversary may attempt to deploy a privileged or vulnerable container into a specific node in order to Escape to Host and access other containers running on the node.

Containers can be deployed by various means, such as via Docker's <code>create</code> and <code>start</code> APIs or via a web application such as the Kubernetes dashboard or Kubeflow. In Kubernetes environments, containers may be deployed through workloads such as ReplicaSets or DaemonSets, which can allow containers to be deployed across multiple nodes. Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.

## Detection

### Detection Analytics

**Analytic 0693**

Remote/API driven creation **and** start of a container whose image is not on an allow‑list (or is tagged `latest`), executed by a non-admin principal, and/or started with risky runtime attributes (e.g., `--privileged`, host PID/NET namespaces, sensitive host path mounts, capability adds). Correlates *create* ➜ *start* ➜ first network/process actions from that container within a short time window.


## Mitigations

### M1047 - Audit

Scan images before deployment, and block those that are not in compliance with security policies. In Kubernetes environments, the admission controller can be used to validate images after a container deployment request is authenticated but before the container is deployed.

### M1035 - Limit Access to Resource Over Network

Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API, Kubernetes API Server, and container orchestration web applications. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.

### M1030 - Network Segmentation

Deny direct remote access to internal systems through the use of network proxies, gateways, and firewalls.

### M1018 - User Account Management

Enforce the principle of least privilege by limiting container dashboard access to only the necessary users. When using Kubernetes, avoid giving users wildcard permissions or adding users to the `system:masters` group, and use `RoleBindings` rather than `ClusterRoleBindings` to limit user privileges to specific namespaces.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0600 - Doki

Doki was run through a deployed container.

### S0599 - Kinsing

Kinsing was run through a deployed Ubuntu container.

### S0683 - Peirates

Peirates can deploy a pod that mounts its node’s root file system, then execute a command to create a reverse shell on the node.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
