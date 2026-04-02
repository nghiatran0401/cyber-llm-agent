# T1112 - Modify Registry

**Tactic:** Defense Evasion, Persistence
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1112

## Description

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.

Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility Reg may be used for local or remote Registry modification. Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API.

The Registry may be modified in order to hide configuration information or malicious payloads via Obfuscated Files or Information. The Registry may also be modified to Impair Defenses, such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory.

The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. Often Valid Accounts are required, along with access to the remote system's SMB/Windows Admin Shares for RPC communication.

Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via Reg or other utilities using the Win32 API. Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.

## Detection

### Detection Analytics

**Analytic 0781**

Behavior chain involving abnormal registry modifications via CLI, PowerShell, WMI, or direct API calls, especially targeting persistence, privilege escalation, or defense evasion keys, potentially followed by service restart or process execution. Such as editing Notify/Userinit/Startup keys, or disabling SafeDllSearchMode.


## Mitigations

### M1024 - Restrict Registry Permissions

Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can modify registry keys as part of setting a new pass-through authentication agent.

### S0045 - ADVSTORESHELL

ADVSTORESHELL is capable of setting and deleting Registry values.

### S0331 - Agent Tesla

Agent Tesla can achieve persistence by modifying Registry key entries.

### S1025 - Amadey

Amadey has overwritten registry keys for persistence.

### S0438 - Attor

Attor's dispatcher can modify the Run registry key.

### S0640 - Avaddon

Avaddon modifies several registry keys for persistence and UAC bypass.

### S0031 - BACKSPACE

BACKSPACE is capable of deleting Registry keys, sub-keys, and values on a victim system.

### S0245 - BADCALL

BADCALL modifies the firewall Registry key <code>SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfileGloballyOpenPorts\\List</code>.

### S1226 - BOOKWORM

BOOKWORM has modified Registry key values as part of its created service `DeviceSync`.

### S0239 - Bankshot

Bankshot writes data into the Registry key <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Pniumj</code>.

### S0268 - Bisonal

Bisonal has deleted Registry keys to clean up its prior activity.

### S0570 - BitPaymer

BitPaymer can set values in the Registry to help in execution.

### S1070 - Black Basta

Black Basta has modified the Registry to enable itself to run in safe mode, to change the icons and file extensions for encrypted files, and to add the malware path for persistence.

### S1181 - BlackByte 2.0 Ransomware

BlackByte 2.0 Ransomware modifies the victim Registry to allow for elevated execution.

### S1180 - BlackByte Ransomware

BlackByte Ransomware modifies the victim Registry to prevent system recovery.

### S1068 - BlackCat

BlackCat has the ability to add the following registry key on compromised networks to maintain persistence: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services \LanmanServer\Paramenters`

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can use the Windows Registry Environment key to change the `%windir%` variable to point to `c:\Windows` to enable payload execution.

### S0023 - CHOPSTICK

CHOPSTICK may modify Registry keys to store RC4 encrypted configuration information.

### S0527 - CSPY Downloader

CSPY Downloader can write to the Registry under the <code>%windir%</code> variable to execute tasks.

### S0348 - Cardinal RAT

Cardinal RAT sets <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load</code> to point to its executable.

### S0261 - Catchamas

Catchamas creates three Registry keys to establish persistence by adding a Windows Service.

### S0572 - Caterpillar WebShell

Caterpillar WebShell has a command to modify a Registry key.

### S0631 - Chaes

Chaes can modify Registry values to stored information and establish persistence.

### S0674 - CharmPower

CharmPower can remove persistence-related artifacts from the Registry.

### S0660 - Clambling

Clambling can set and delete Registry keys.

### S0611 - Clop

Clop can make modifications to Registry keys.

### S0154 - Cobalt Strike

Cobalt Strike can modify Registry values within <code>HKEY_CURRENT_USER\Software\Microsoft\Office\<Excel Version>\Excel\Security\AccessVBOM\</code> to enable the execution of additional code.

### S0126 - ComRAT

ComRAT has modified Registry values to store encrypted orchestrator code and payloads.

### S0608 - Conficker

Conficker adds keys to the Registry at <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</code> and various other Registry locations.

### S0488 - CrackMapExec

CrackMapExec can create a registry key using wdigest.

### S0115 - Crimson

Crimson can set a Registry key to determine how long it has been installed and possibly to indicate the version number.

### S1033 - DCSrv

DCSrv has created Registry keys for persistence.

### S0334 - DarkComet

DarkComet adds a Registry value for its installation routine to the Registry Key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System Enable LUA=”0”</code> and <code>HKEY_CURRENT_USER\Software\DC3_FEXEC</code>.

### S1066 - DarkTortilla

DarkTortilla has modified registry keys for persistence.

### S0673 - DarkWatchman

DarkWatchman can modify Registry values to store configuration strings, keylogger, and output of components.

### S0568 - EVILNUM

EVILNUM can make modifications to the Regsitry for persistence.

### S1247 - Embargo

Embargo has modified and deleted Registry keys to add services, and to disable Security Solutions such as Windows Defender.

### S0343 - Exaramel for Windows

Exaramel for Windows adds the configuration to the Registry in XML format.

### S0569 - Explosive

Explosive has a function to write itself to Registry values.

### S0267 - FELIXROOT

FELIXROOT deletes the Registry key <code>HKCU\Software\Classes\Applications\rundll32.exe\shell\open</code>.

### S0679 - Ferocious

Ferocious has the ability to add a Class ID in the current user Registry hive to enable persistence mechanisms.

### S0666 - Gelsemium

Gelsemium can modify the Registry to store its components.

### S0531 - Grandoreiro

Grandoreiro can modify the Registry to store its configuration at `HKCU\Software\` under frequently changing names including <code>%USERNAME%</code> and <code>ToolTech-RM</code>.

### S0342 - GreyEnergy

GreyEnergy modifies conditions in the Registry and adds keys.

### S1230 - HIUPAN

HIUPAN has modified registry keys to ensure hidden files and extensions are not visible through the modification of `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`.

### S0376 - HOPLIGHT

HOPLIGHT has modified Managed Object Format (MOF) files within the Registry to run specific commands and create persistence on the system.

### S0697 - HermeticWiper

HermeticWiper has the ability to modify Registry keys to disable crash dumps, colors for compressed files, and pop-up information about folders and desktop items.

### S0203 - Hydraq

Hydraq creates a Registry subkey to register its created service, and can also uninstall itself later by deleting this value. Hydraq's backdoor also enables remote attackers to modify and delete subkeys.

### S0537 - HyperStack

HyperStack can add the name of its communication pipe to <code>HKLM\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters\NullSessionPipes</code>.

### S1132 - IPsec Helper

IPsec Helper can make arbitrary changes to registry keys based on provided input.

### S0260 - InvisiMole

InvisiMole has a command to create, set, copy, or delete a specified Registry key or value.

### S0271 - KEYMARBLE

KEYMARBLE has a command to create Registry entries for storing data under <code>HKEY_CURRENT_USER\SOFTWARE\Microsoft\WABE\DataPath</code>.

### S0669 - KOCTOPUS

KOCTOPUS has added and deleted keys from the Registry.

### S0356 - KONNI

KONNI has modified registry keys of ComSysApp, Svchost, and xmlProv on the machine to gain persistence.

### S1190 - Kapeka

Kapeka writes persistent configuration information to the victim host registry.

### S0397 - LoJax

LoJax has modified the Registry key <code>‘HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute’</code> from <code>‘autocheck autochk *’</code> to <code>‘autocheck autoche *’</code>.

### S1199 - LockBit 2.0

LockBit 2.0 can create Registry keys to bypass UAC and for persistence.

### S1202 - LockBit 3.0

LockBit 3.0 can change the Registry values for Group Policy refresh time, to disable SmartScreen, and to disable Windows Defender.

### S0447 - Lokibot

Lokibot has modified the Registry as part of its UAC bypass process.

### S1060 - Mafalda

Mafalda can manipulate the system registry on a compromised host.

### S0576 - MegaCortex

MegaCortex has added entries to the Registry for ransom contact information.

### S0455 - Metamorfo

Metamorfo has written process names to the Registry, disabled IE browser features, deleted Registry keys, and changed the ExtendedUIHoverTime key.

### S1047 - Mori

Mori can write data to `HKLM\Software\NFC\IPA` and `HKLM\Software\NFC\` and delete Registry values.

### S0256 - Mosquito

Mosquito can modify Registry keys under <code>HKCU\Software\Microsoft\[dllname]</code> to store configuration values. Mosquito also modifies Registry keys under <code>HKCR\CLSID\...\InprocServer32</code> with a path to the launcher.

### S0198 - NETWIRE

NETWIRE can modify the Registry to store its configuration information.

### S1131 - NPPSPY

NPPSPY modifies the Registry to record the malicious listener for output from the Winlogon process.

### S0205 - Naid

Naid creates Registry entries that store information about a created service and point to a malicious DLL dropped to disk.

### S0336 - NanoCore

NanoCore has the capability to edit the Registry.

### S0691 - Neoichor

Neoichor has the ability to configure browser settings by modifying Registry entries under `HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer`.

### S0210 - Nerex

Nerex creates a Registry subkey that registers a new service.

### S0457 - Netwalker

Netwalker can add the following registry entry: <code>HKEY_CURRENT_USER\SOFTWARE\{8 random characters}</code>.

### S1090 - NightClub

NightClub can modify the Registry to set the ServiceDLL for a service created by the malware for persistence.

### S0229 - Orz

Orz can perform Registry operations.

### S0158 - PHOREAL

PHOREAL is capable of manipulating the Registry.

### S0254 - PLAINTEE

PLAINTEE uses <code>reg add</code> to add a Registry Run key for persistence.

### S0664 - Pandora

Pandora can write an encrypted token to the Registry to enable processing of remote commands.

### S1050 - PcShare

PcShare can delete its persistence mechanisms from the registry.

### S0517 - Pillowmint

Pillowmint has modified the Registry key <code>HKLM\SOFTWARE\Microsoft\DRM</code> to store a malicious payload.

### S0501 - PipeMon

PipeMon has modified the Registry to store its encrypted payload.

### S0013 - PlugX

PlugX has a module to create, delete, or modify Registry keys.

### S0428 - PoetRAT

PoetRAT has made registry modifications to alter its behavior upon execution.

### S0012 - PoisonIvy

PoisonIvy creates a Registry subkey that registers a new system device.

### S0518 - PolyglotDuke

PolyglotDuke can write encrypted JSON configuration files to the Registry.

### S0441 - PowerShower

PowerShower has added a registry key so future powershell.exe instances are spawned off-screen by default, and has removed all registry entries that are left behind during the dropper process.

### S1058 - Prestige

Prestige has the ability to register new registry keys for a new extension handler via `HKCR\.enc` and `HKCR\enc\shell\open\command`.

### S0583 - Pysa

Pysa has modified the registry key “SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System” and added the ransom note.

### S0269 - QUADAGENT

QUADAGENT modifies an HKCU Registry key to store a session identifier unique to the compromised system as well as a pre-shared key used for encrypting and decrypting C2 communications.

### S0650 - QakBot

QakBot can modify the Registry to store its configuration information in a randomly named subkey under <code>HKCU\Software\Microsoft</code>.

### S1242 - Qilin

Qilin can make Registry modifications to share networked drives between elevated and non-elevated processes and to increase the number of outstanding network requests per client.

### S0262 - QuasarRAT

QuasarRAT has a command to edit the Registry on the victim’s machine.

### S0662 - RCSession

RCSession can write its configuration file to the Registry.

### S0496 - REvil

REvil can modify the Registry to save encryption parameters and system information.

### S0240 - ROKRAT

ROKRAT can modify the `HKEY_CURRENT_USER\Software\Microsoft\Office\` registry key so it can bypass the VB object model (VBOM) on a compromised host.

### S0148 - RTM

RTM can delete all Registry entries created during its execution.

### S0075 - Reg

Reg may be used to interact with and modify the Windows Registry of a local or remote system at the command-line interface.

### S0511 - RegDuke

RegDuke can create seemingly legitimate Registry key to store its encryption key.

### S0019 - Regin

Regin appears to have functionality to modify remote Registry information.

### S0332 - Remcos

Remcos has full control of the Registry, including the ability to modify it.

### S0090 - Rover

Rover has functionality to remove Registry Run key persistence as a cleanup procedure.

### S0692 - SILENTTRINITY

SILENTTRINITY can modify registry keys, including to enable or disable Remote Desktop Protocol (RDP).

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA can add, modify, and/or delete registry keys. It has changed the proxy configuration of a victim system by modifying the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap</code> registry.

### S0649 - SMOKEDHAM

SMOKEDHAM has modified registry keys for persistence, to enable credential caching for credential access, and to facilitate lateral movement via RDP.

### S0157 - SOUNDBITE

SOUNDBITE is capable of modifying the Registry.

### S0559 - SUNBURST

SUNBURST had commands that allow an attacker to write or delete registry keys, and was observed stopping services by setting their <code>HKLM\SYSTEM\CurrentControlSet\services\\[service_name]\\Start</code> registry entries to value 4. It also deleted previously-created Image File Execution Options (IFEO) Debugger registry values and registry keys related to HTTP proxy to clean up traces of its activity.

### S1099 - Samurai

The Samurai loader component can create multiple Registry keys to force the svchost.exe process to load the final backdoor.

### S0596 - ShadowPad

ShadowPad can modify the Registry to store and maintain a configuration block and virtual file system.

### S0140 - Shamoon

Once Shamoon has access to a network share, it enables the RemoteRegistry service on the target system. It will then connect to the system with RegConnectRegistryW and modify the Registry to disable UAC remote restrictions by setting <code>SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy</code> to 1.

### S0444 - ShimRat

ShimRat has registered two registry keys for shim databases.

### S1178 - ShrinkLocker

ShrinkLocker modifies various registry keys associated with system logon and BitLocker functionality to effectively lock-out users following disk encryption.

### S0589 - Sibot

Sibot has modified the Registry to install a second-stage script in the <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\sibot</code>.

### S0142 - StreamEx

StreamEx has the ability to modify the Registry.

### S0603 - Stuxnet

Stuxnet can create registry keys to load driver files.

### S0242 - SynAck

SynAck can manipulate Registry keys.

### S0663 - SysUpdate

SysUpdate can write its configuration file to <code>Software\Classes\scConfig</code> in either <code>HKEY_LOCAL_MACHINE</code> or <code>HKEY_CURRENT_USER</code>.

### S0560 - TEARDROP

TEARDROP modified the Registry to create a Windows service for itself on a compromised host.

### S1201 - TRANSLATEXT

TRANSLATEXT has modified the following registry key to install itself as the value, granting permission to install specified extensions: ` HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist`.

### S0263 - TYPEFRAME

TYPEFRAME can install encrypted configuration data under the Registry key <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications\laxhost.dll</code> and <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PrintConfigs</code>.

### S0011 - Taidoor

Taidoor has the ability to modify the Registry on compromised hosts using <code>RegDeleteValueA</code> and <code>RegCreateKeyExA</code>.

### S0467 - TajMahal

TajMahal can set the <code>KeepPrintedJobs</code> attribute for configured printers in <code>SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers</code> to enable document stealing.

### S1011 - Tarrask

Tarrask is able to delete the Security Descriptor (`SD`) registry subkey in order to “hide” scheduled tasks.

### S0665 - ThreatNeedle

ThreatNeedle can modify the Registry to save its configuration data as the following RC4-encrypted Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameCon`.

### S0668 - TinyTurla

TinyTurla can set its configuration parameters in the Registry.

### S0266 - TrickBot

TrickBot can modify registry entries.

### S0022 - Uroburos

Uroburos can store configuration information in the Registry including the initialization vector and AES key needed to find and decrypt other Uroburos components.

### S0386 - Ursnif

Ursnif has used Registry modifications as part of its installation routine.

### S0476 - Valak

Valak has the ability to modify the Registry key <code>HKCU\Software\ApplicationContainer\Appsw64</code> to store information regarding the C2 server and downloads.

### S0180 - Volgmer

Volgmer modifies the Registry to store an encoded configuration file in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security</code>.

### S0670 - WarzoneRAT

WarzoneRAT can create `HKCU\Software\Classes\Folder\shell\open\command` as a new registry key during privilege escalation.

### S0612 - WastedLocker

WastedLocker can modify registry values within the <code>Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap</code> registry key.

### S0579 - Waterbear

Waterbear has deleted certain values from the Registry to load a malicious DLL.

### S0330 - Zeus Panda

Zeus Panda modifies several Registry keys under <code>HKCU\Software\Microsoft\Internet Explorer\ PhishingFilter\</code> to disable phishing filters.

### S0412 - ZxShell

ZxShell can create Registry entries to enable services to run.

### S0032 - gh0st RAT

gh0st RAT has altered the InstallTime subkey.

### S1059 - metaMain

metaMain can write the process ID of a target process into the `HKEY_LOCAL_MACHINE\SOFTWARE\DDE\tpid` Registry value as part of its reflective loading activity.

### S0385 - njRAT

njRAT can create, delete, or modify a specified Registry key or value.

### S0350 - zwShell

zwShell can modify the Registry.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0028 - 2015 Ukraine Electric Power Attack

During the 2015 Ukraine Electric Power Attack, Sandworm Team modified in-registry Internet settings to lower internet security before launching `rundll32.exe`, which in-turn launches the malware and communicates with C2 servers over the Internet..

### C0002 - Night Dragon

During Night Dragon, threat actors used zwShell to establish full remote control of the connected machine and manipulate the Registry.

### C0006 - Operation Honeybee

During Operation Honeybee, the threat actors used batch files that modified registry keys.

### C0014 - Operation Wocao

During Operation Wocao, the threat actors enabled Wdigest by changing the `HKLM\SYSTEM\\ControlSet001\\Control\\SecurityProviders\\WDigest` registry value from 0 (disabled) to 1 (enabled).

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors, including Storm-2603, disabled security services via Registry modifications.
