# T1609 - Container Administration Command

**Tactic:** Execution
**Platforms:** Containers
**Reference:** https://attack.mitre.org/techniques/T1609

## Description

Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.

In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as <code>docker exec</code> to execute a command within a running container. In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as <code>kubectl exec</code>.

## Detection

### Detection Analytics

**Analytic 0177**

Defenders may detect abuse of container administration commands by observing anomalous use of management utilities (`docker exec`, `kubectl exec`, or API calls to kubelet) correlated with unexpected process creation inside containers. Behavioral chains include unauthorized API requests followed by command execution within running pods or containers, often originating from unusual user accounts, automation scripts, or IP addresses outside the expected cluster management plane.


## Mitigations

### M1042 - Disable or Remove Feature or Program

Remove unnecessary tools and software from containers.

### M1038 - Execution Prevention

Use read-only containers, read-only file systems, and minimal images when possible to prevent the execution of commands. Where possible, also consider using application control and software restriction tools (such as those provided by SELinux) to restrict access to files, processes, and system calls in containers.

### M1035 - Limit Access to Resource Over Network

Limit communications with the container service to managed and secured channels, such as local Unix sockets or remote access via SSH. Require secure port access to communicate with the APIs over TLS by disabling unauthenticated access to the Docker API and Kubernetes API Server. In Kubernetes clusters deployed in cloud environments, use native cloud platform features to restrict the IP ranges that are permitted to access to API server. Where possible, consider enabling just-in-time (JIT) access to the Kubernetes API to place additional restrictions on access.

### M1026 - Privileged Account Management

Ensure containers are not running as root by default. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers and using the `NodeRestriction` admission controller to deny the kublet access to nodes and pods outside of the node it belongs to.

### M1018 - User Account Management

Enforce authentication and role-based access control on the container service to restrict users to the least privileges required. When using Kubernetes, avoid giving users wildcard permissions or adding users to the `system:masters` group, and use `RoleBindings` rather than `ClusterRoleBindings` to limit user privileges to specific namespaces.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0601 - Hildegard

Hildegard was executed through the kubelet API run command and by executing commands on running containers.

### S0599 - Kinsing

Kinsing was executed with an Ubuntu container entry point that runs shell scripts.

### S0683 - Peirates

Peirates can use `kubectl` or the Kubernetes API to run commands.

### S0623 - Siloscape

Siloscape can send kubectl commands to victim clusters through an IRC channel and can run kubectl locally to spread once within a victim cluster.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
