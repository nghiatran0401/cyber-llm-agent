# T1489 - Service Stop

**Tactic:** Impact
**Platforms:** ESXi, IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1489

## Description

Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. 

Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible. In some cases, adversaries may stop or disable many or all services to render systems unusable. Services or processes may not allow for modification of their data stores while running. Adversaries may stop services or processes in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server, or on virtual machines hosted on ESXi infrastructure.

Threat actors may also disable or stop service in cloud environments. For example, by leveraging the `DisableAPIServiceAccess` API in AWS, a threat actor may prevent the service from creating service-linked roles on new accounts in the AWS Organization.

## Detection

### Detection Analytics

**Analytic 0061**

Adversary disables or stops critical services (e.g., Exchange, SQL, AV, endpoint monitoring) using native utilities or API calls, often preceding destructive actions (T1485, T1486). Behavioral chain: Elevated execution context + stop-service or sc.exe or ChangeServiceConfigW + terminated or disabled service + possible follow-up file manipulation.

**Analytic 0062**

Adversary executes systemctl or service stop targeting high-value services (e.g., mysql, sshd), possibly followed by rm or shred against data stores. Behavioral chain: sudo/su usage + stop command + /var/log/messages or syslog entries + file access/delete.

**Analytic 0063**

Use of launchctl to stop services or kill critical background processes (e.g., securityd, com.apple.*), typically followed by command-line tools like rm or diskutil. Behavioral chain: Terminal or remote shell + launchctl bootout/disable + process termination + follow-on modification.

**Analytic 0064**

Attacker disables VM-related services or stops VMs forcibly to target vmdk or logs. Behavioral chain: esxcli or vim-cmd stop + audit log showing user privilege use + datastore file manipulation.


## Mitigations

### M1030 - Network Segmentation

Operate intrusion detection, analysis, and response systems on a separate network from the production environment to lessen the chances that an adversary can see and interfere with critical response functions.

### M1060 - Out-of-Band Communications Channel

Develop and enforce security policies that include the use of out-of-band communication channels for critical communications during a security incident.

### M1022 - Restrict File and Directory Permissions

Ensure proper process and file permissions are in place to inhibit adversaries from disabling or interfering with critical services.

### M1024 - Restrict Registry Permissions

Ensure proper registry permissions are in place to inhibit adversaries from disabling or interfering with critical services.

### M1018 - User Account Management

Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service configurations.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1194 - Akira _v2

Akira _v2 can stop running virtual machines.

### S0640 - Avaddon

Avaddon looks for and attempts to stop database processes.

### S1053 - AvosLocker

AvosLocker has terminated specific processes before encryption.

### S0638 - Babuk

Babuk can stop specific services related to backups.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware can terminate running services.

### S1068 - BlackCat

BlackCat has the ability to stop VM services on compromised networks.

### S1096 - Cheerscrypt

Cheerscrypt has the ability to terminate VM processes on compromised hosts through execution of `esxcli vm process kill`.

### S0611 - Clop

Clop can kill several processes and services related to backups and security solutions.

### S0575 - Conti

Conti can stop up to 146 Windows services related to security, backup, database, and email solutions through the use of <code>net stop</code>.

### S0625 - Cuba

Cuba has a hardcoded list of services and processes to terminate.

### S0659 - Diavol

Diavol will terminate services using the Service Control Manager (SCM) API.

### S0605 - EKANS

EKANS stops database, data backup solution, antivirus, and ICS-related processes.

### S1247 - Embargo

Embargo has terminated active processes and services based on a hardcoded list using the `CloseServiceHandle()` function. Embargo has also leveraged MS4Killer to terminate processes contained in an embedded list of security software process names that were XOR-encrypted.

### S1211 - Hannotog

Hannotog can stop Windows services.

### S0697 - HermeticWiper

HermeticWiper has the ability to stop the Volume Shadow Copy service.

### S0431 - HotCroissant

HotCroissant has the ability to stop services on the infected host.

### S1139 - INC Ransomware

INC Ransomware can issue a command to kill a process on compromised hosts.

### S0604 - Industroyer

Industroyer’s data wiper module writes zeros into the registry keys in <code>SYSTEM\CurrentControlSet\Services</code> to render a system inoperable.

### S1245 - InvisibleFerret

InvisibleFerret has terminated Chrome and Brave browsers using the `taskkill` command on Windows and the `killall` command on other systems such as Linux and macOS. InvisibleFerret has also utilized it’s `ssh_kill` command to terminate Chrome and Brave browser processes.

### S0607 - KillDisk

KillDisk terminates various processes to get the user to reboot the victim machine.

### S1199 - LockBit 2.0

LockBit 2.0 can automatically terminate processes that may interfere with the encryption or file extraction processes.

### S1202 - LockBit 3.0

LockBit 3.0 can terminate targeted processes and services related to security, backup, database management, and other applications that could stop or interfere with encryption.

### S0582 - LookBack

LookBack can kill processes and delete services.

### S0449 - Maze

Maze has stopped SQL services to ensure it can encrypt any database.

### S1244 - Medusa Ransomware

Medusa Ransomware has the capability to terminate services related to backups, security, databases, communication, filesharing and websites. Medusa Ransomware has also utilized the `taskkill /F /IM <process> /T` command to stop targeted processes and `net stop <process>` command to stop designated services.

### S0576 - MegaCortex

MegaCortex can stop and disable services on the system.

### S1191 - Megazord

Megazord has the ability to terminate a list of services and processes.

### S0688 - Meteor

Meteor can disconnect all network adapters on a compromised host using `powershell -Command "Get-WmiObject -class Win32_NetworkAdapter | ForEach { If ($.NetEnabled) { $.Disable() } }" > NUL`.

### S0457 - Netwalker

Netwalker can terminate system processes and services, some of which relate to backup software.

### S0365 - Olympic Destroyer

Olympic Destroyer uses the API call <code>ChangeServiceConfigW</code> to disable all services on the affected system.

### S0556 - Pay2Key

Pay2Key can stop the MS SQL service at the end of the encryption process to release files locked by the service.

### S1058 - Prestige

Prestige has attempted to stop the MSSQL Windows service to ensure successful encryption using `C:\Windows\System32\net.exe stop MSSQLSERVER`.

### S0583 - Pysa

Pysa can stop services and processes.

### S1242 - Qilin

Qilin can terminate specific services on compromised hosts.

### S0496 - REvil

REvil has the capability to stop services and kill processes.

### S1150 - ROADSWEEP

ROADSWEEP can disable critical services and processes.

### S0481 - Ragnar Locker

Ragnar Locker has attempted to stop services associated with business applications and databases to release the lock on files used by these applications so they may be encrypted.

### S1212 - RansomHub

RansomHub has the ability to terminate specified services.

### S0400 - RobbinHood

RobbinHood stops 181 Windows services on the system before beginning the encryption process.

### S1073 - Royal

Royal can use `RmShutDown` to kill  applications and services using the resources that are targeted for encryption.

### S0446 - Ryuk

Ryuk has called <code>kill.bat</code> for stopping services, disabling services and killing processes.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has the capability to stop processes and services.

### S1217 - VIRTUALPITA

VIRTUALPITA can start and stop the `vmsyslogd` service.

### S0366 - WannaCry

WannaCry attempts to kill processes associated with Exchange, Microsoft SQL Server, and MySQL to make it possible to encrypt their data stores.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
