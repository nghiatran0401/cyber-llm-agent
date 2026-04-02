# T1611 - Escape to Host

**Tactic:** Privilege Escalation
**Platforms:** Containers, ESXi, Linux, Windows
**Reference:** https://attack.mitre.org/techniques/T1611

## Description

Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself. In principle, containerized / virtualized resources should provide a clear separation of application functionality and be isolated from the host environment.

There are multiple ways an adversary may escape from a container to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host; utilizing a privileged container to run commands or load a malicious kernel module on the underlying host; or abusing system calls such as `unshare` and `keyctl` to escalate privileges and steal secrets.

Additionally, an adversary may be able to exploit a compromised container with a mounted container management socket, such as `docker.sock`, to break out of the container via a Container Administration Command. Adversaries may also escape via Exploitation for Privilege Escalation, such as exploiting vulnerabilities in global symbolic links in order to access the root directory of a host machine.

In ESXi environments, an adversary may exploit a vulnerability in order to escape from a virtual machine into the hypervisor.

Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, accessing other containers or virtual machines running on the host, or setting up a command and control channel on the host.

## Detection

### Detection Analytics

**Analytic 0612**

Detection of container escape attempts via bind mounts, privileged containers, or abuse of docker.sock. Defenders may observe anomalous volume mount configurations (e.g., hostPath to / or /proc), unexpected privileged container launches, or use of container administration commands to access host resources. These events typically correlate with subsequent process execution on the host outside of normal container isolation.

**Analytic 0613**

Detection of Linux container escape attempts via syscalls (`unshare`, `keyctl`, `mount`) or process execution outside container namespaces. Defenders may correlate unusual system calls from containerized processes with subsequent process creation on the host or modification of host resources.

**Analytic 0614**

Detection of Windows container escape attempts by observing processes accessing host directories, symbolic link abuse, or privilege escalation attempts. Defenders may detect anomalous process execution with access to system-level directories outside of container boundaries.

**Analytic 0615**

Detection of ESXi escape attempts by monitoring for anomalies in hypervisor logs such as unexpected VM operations, privilege escalation events, or attempts to load malicious kernel modules within the hypervisor environment.


## Mitigations

### M1048 - Application Isolation and Sandboxing

Consider utilizing seccomp, seccomp-bpf, or a similar solution that restricts certain system calls such as mount. In Kubernetes environments, consider defining Pod Security Standards that limit container access to host process namespaces, the host network, and the host file system.

### M1042 - Disable or Remove Feature or Program

Remove unnecessary tools and software from containers.

### M1038 - Execution Prevention

Use read-only containers, read-only file systems, and minimal images when possible to prevent the running of commands. Where possible, also consider using application control and software restriction tools (such as those provided by SELinux) to restrict access to files, processes, and system calls in containers.

### M1026 - Privileged Account Management

Ensure containers are not running as root by default and do not use unnecessary privileges or mounted components. In Kubernetes environments, consider defining Pod Security Standards that prevent pods from running privileged containers.

### M1051 - Update Software

Ensure that hosts are kept up-to-date with security patches.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0600 - Doki

Doki’s container was configured to bind the host root directory.

### S0601 - Hildegard

Hildegard has used the BOtB tool that can break out of containers.

### S0683 - Peirates

Peirates can gain a reverse shell on a host node by mounting the Kubernetes hostPath.

### S0623 - Siloscape

Siloscape maps the host’s C drive to the container by creating a global symbolic link to the host through the calling of <code>NtSetInformationSymbolicLink</code>.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
