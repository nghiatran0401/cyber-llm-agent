# T1673 - Virtual Machine Discovery

**Tactic:** Discovery
**Platforms:** ESXi, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1673

## Description

An adversary may attempt to enumerate running virtual machines (VMs) after gaining access to a host or hypervisor. For example, adversaries may enumerate a list of VMs on an ESXi hypervisor using a Hypervisor CLI such as `esxcli` or `vim-cmd` (e.g. `esxcli vm process list or vim-cmd vmsvc/getallvms`). Adversaries may also directly leverage a graphical user interface, such as VMware vCenter, in order to view virtual machines on a host. 

Adversaries may use the information from Virtual Machine Discovery during discovery to shape follow-on behaviors. Subsequently discovered VMs may be leveraged for follow-on activities such as Service Stop or Data Encrypted for Impact.

## Detection

### Detection Analytics

**Analytic 0572**

Monitor for execution of hypervisor management commands such as `esxcli vm process list` or `vim-cmd vmsvc/getallvms` that enumerate virtual machines. Defenders observe unexpected users issuing VM listing commands outside normal administrative workflows.

**Analytic 0573**

Detects attempts to enumerate VMs via hypervisor tools like `virsh`, `VBoxManage`, or `qemu-img`. Defender correlates suspicious command invocations with parent process lineage and unexpected users.

**Analytic 0574**

Detects enumeration of VMs using PowerShell (`Get-VM`), VMware Workstation (`vmrun.exe`), or Hyper-V (`VBoxManage.exe`). Defender observes suspicious command lines executed by unexpected users or outside normal administrative sessions.

**Analytic 0575**

Detects VM enumeration attempts using virtualization utilities such as VirtualBox (`VBoxManage`) or Parallels CLI. Defender observes abnormal invocation of VM listing commands correlated with non-admin users or unusual parent processes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1096 - Cheerscrypt

Cheerscrypt has leveraged `esxcli vm process list` in order to gather a list of running virtual machines to terminate them.

### S1242 - Qilin

Qilin can detect virtual machine environments.

### S1217 - VIRTUALPITA

VIRTUALPITA can target specific guest virtual machines for script execution.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
