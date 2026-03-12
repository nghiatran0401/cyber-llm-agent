# T1012 - Query Registry

**Tactic:** Discovery
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1012

## Description

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

## Detection

### Detection Analytics

**Analytic 0589**

Registry read access associated with suspicious or non-interactive processes querying system config, installed software, or security settings.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0045 - ADVSTORESHELL

ADVSTORESHELL can enumerate registry keys.

### S0438 - Attor

Attor has opened the registry and performed query searches.

### S0344 - Azorult

Azorult can check for installed software on the system under the Registry key <code>Software\Microsoft\Windows\CurrentVersion\Uninstall</code>.

### S0031 - BACKSPACE

BACKSPACE is capable of enumerating and making modifications to an infected system's Registry.

### S0414 - BabyShark

BabyShark has executed the <code>reg query</code> command for <code>HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default</code>.

### S0239 - Bankshot

Bankshot searches for certain Registry keys to be configured before executing the payload.

### S0534 - Bazar

Bazar can query <code>Windows\CurrentVersion\Uninstall</code> for installed applications.

### S0574 - BendyBear

BendyBear can query the host's Registry key at <code>HKEY_CURRENT_USER\Console\QuickEdit</code> to retrieve data.

### S0268 - Bisonal

Bisonal has used the RegQueryValueExA function to retrieve proxy information in the Registry.

### S0570 - BitPaymer

BitPaymer can use the RegEnumKeyW to iterate through Registry keys.

### S1180 - BlackByte Ransomware

BlackByte Ransomware enumerates the Registry, specifically the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` key.

### S0252 - Brave Prince

Brave Prince gathers information about the Registry.

### S1039 - Bumblebee

Bumblebee can check the Registry for specific keys.

### S0023 - CHOPSTICK

CHOPSTICK provides access to the Windows Registry, which can be used to gather information.

### S0030 - Carbanak

Carbanak checks the Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings</code> for proxy configurations information.

### S0484 - Carberp

Carberp has searched the Image File Execution Options registry key for "Debugger" within every subkey.

### S0335 - Carbon

Carbon enumerates values in the Registry.

### S0348 - Cardinal RAT

Cardinal RAT contains watchdog functionality that periodically ensures <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load</code> is set to point to its executable.

### S0674 - CharmPower

CharmPower has the ability to enumerate `Uninstall` registry values.

### S0660 - Clambling

Clambling has the ability to enumerate Registry keys, including <code>KEY_CURRENT_USER\Software\Bitcoin\Bitcoin-Qt\strDataDir</code> to search for a bitcoin wallet.

### S0154 - Cobalt Strike

Cobalt Strike can query <code>HKEY_CURRENT_USER\Software\Microsoft\Office\<Excel Version>\Excel\Security\AccessVBOM\</code>  to determine if the security setting for restricting default programmatic access is enabled.

### S0126 - ComRAT

ComRAT can check the default browser by querying <code>HKCR\http\shell\open\command</code>.

### S0115 - Crimson

Crimson can check the Registry for the presence of <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\last_edate</code> to determine how long it has been installed on a host.

### S1159 - DUSTTRAP

DUSTTRAP can enumerate Registry items.

### S0673 - DarkWatchman

DarkWatchman can query the Registry to determine if it has already been installed on the system.

### S0354 - Denis

Denis queries the Registry for keys and values.

### S0021 - Derusbi

Derusbi is capable of enumerating Registry keys and values.

### S0186 - DownPaper

DownPaper searches and reads the value of the Windows Update Registry Run key.

### S0567 - Dtrack

Dtrack can collect the RegisteredOwner, RegisteredOrganization, and InstallDate registry values.

### S0091 - Epic

Epic uses the <code>rem reg query</code> command to obtain values from Registry keys.

### S0267 - FELIXROOT

FELIXROOT queries the Registry for specific keys for potential privilege escalation and proxy information. FELIXROOT has also used WMI to query the Windows Registry.

### S0512 - FatDuke

FatDuke can get user agent strings for the default browser from <code>HKCU\Software\Classes\http\shell\open\command</code>.

### S0182 - FinFisher

FinFisher queries Registry values as part of its anti-sandbox checks.

### S1044 - FunnyDream

FunnyDream can check `Software\Microsoft\Windows\CurrentVersion\Internet Settings` to extract the `ProxyServer` string.

### S0666 - Gelsemium

Gelsemium can open random files and Registry keys to obscure malware behavior from sandbox analysis.

### S0249 - Gold Dragon

Gold Dragon enumerates registry keys with the command <code>regkeyenum</code> and obtains information for the Registry key <code>HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code>.

### S0376 - HOPLIGHT

A variant of HOPLIGHT hooks lsass.exe, and lsass.exe then checks the Registry for the data value 'rdpproto' under the key <code>SYSTEM\CurrentControlSet\Control\Lsa Name</code>.

### S0203 - Hydraq

Hydraq creates a backdoor through which remote attackers can retrieve system information, such as CPU speed, from Registry keys.

### S0604 - Industroyer

Industroyer has a data wiper component that enumerates keys in the Registry <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</code>.

### S0260 - InvisiMole

InvisiMole can enumerate Registry values, keys, and data.

### S0201 - JPIN

JPIN can enumerate Registry keys.

### S1190 - Kapeka

Kapeka queries registry values for stored configuration information.

### S0513 - LiteDuke

LiteDuke can query the Registry to check for the presence of <code>HKCU\Software\KasperskyLab</code>.

### S0680 - LitePower

LitePower can query the Registry for keys added to execute COM hijacking.

### S0532 - Lucifer

Lucifer can check for existing stratum cryptomining information in <code>HKLM\Software\Microsoft\Windows\CurrentVersion\spreadCpuXmr – %stratum info%</code>.

### S1060 - Mafalda

Mafalda can enumerate Registry keys with all subkeys and values.

### S1015 - Milan

Milan can query `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography MachineGuid` to retrieve the machine GUID.

### S1047 - Mori

Mori can read data from the Registry including from `HKLM\Software\NFC\IPA` and
`HKLM\Software\NFC\`.

### S0165 - OSInfo

OSInfo queries the registry to look for information about Terminal Services.

### S0145 - POWERSOURCE

POWERSOURCE queries Registry keys in preparation for setting Run keys to achieve persistence.

### S0184 - POWRUNER

POWRUNER may query the Registry by running <code>reg query</code> on a victim.

### S1228 - PUBLOAD

PUBLOAD has queried Registry values to identify software using `reg query`.

### S1050 - PcShare

PcShare can search the registry files of a compromised host.

### S0517 - Pillowmint

Pillowmint has used shellcode which reads code stored in the registry keys <code>\REGISTRY\SOFTWARE\Microsoft\DRM</code> using the native Windows API as well as read <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces</code> as part of its C2.

### S0013 - PlugX

PlugX can enumerate and query for information contained within the Windows Registry.

### S0194 - PowerSploit

PowerSploit contains a collection of Privesc-PowerUp modules that can query Registry keys for potential opportunities.

### S0238 - Proxysvc

Proxysvc gathers product names from the Registry key: <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion ProductName</code> and the processor description from the Registry key <code>HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 ProcessorNameString</code>.

### S0269 - QUADAGENT

QUADAGENT checks if a value exists within a Registry key in the HKCU hive whose name is the same as the scheduled task it has created.

### S1076 - QUIETCANARY

QUIETCANARY has the ability to retrieve information from the Registry.

### S1242 - Qilin

Qilin can check `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control SystemStartOptions` to determine if a machine is running in safe mode.

### S0241 - RATANKBA

RATANKBA uses the command <code>reg query “HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\InternetSettings”</code>.

### S0496 - REvil

REvil can query the Registry to get random file extensions to append to encrypted files.

### S0240 - ROKRAT

ROKRAT can access the <code>HKLM\System\CurrentControlSet\Services\mssmbios\Data\SMBiosData</code> Registry key to obtain the System manufacturer value to identify the machine type.

### S1148 - Raccoon Stealer

Raccoon Stealer queries the Windows Registry to fingerprint the infected host via the `HKLM:\SOFTWARE\Microsoft\Cryptography\MachineGuid` key.

### S0172 - Reaver

Reaver queries the Registry to determine the correct Startup path to use for persistence.

### S1240 - RedLine Stealer

RedLine Stealer can query the Windows Registry.

### S0075 - Reg

Reg may be used to gather details from the Windows Registry of a local or remote system at the command-line interface.

### S0448 - Rising Sun

Rising Sun has identified the OS product name from a compromised host by searching the registry for `SOFTWARE\MICROSOFT\Windows NT\ CurrentVersion | ProductName`.

### S0692 - SILENTTRINITY

SILENTTRINITY can use the `GetRegValue` function to check Registry keys within `HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` and `HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`. It also contains additional modules that can check software AutoRun values and use the Win32 namespace to get values from HKCU, HKLM, HKCR, and HKCC hives.

### S0559 - SUNBURST

SUNBURST collected the registry value <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid</code> from compromised hosts.

### S1064 - SVCReady

SVCReady can search for the `HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System` Registry key to gather system information.

### S1018 - Saint Bot

Saint Bot has used `check_registry_keys` as part of its environmental checks.

### S1099 - Samurai

Samurai can query `SOFTWARE\Microsoft\.NETFramework\policy\v2.0` for discovery.

### S0140 - Shamoon

Shamoon queries several Registry keys to identify hard disk partitions to overwrite.

### S1019 - Shark

Shark can query `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography MachineGuid` to retrieve the machine GUID.

### S0589 - Sibot

Sibot has queried the registry for proxy server information.

### S0627 - SodaMaster

SodaMaster has the ability to query the Registry to detect a key specific to VMware.

### S0380 - StoneDrill

StoneDrill has looked in the registry to find the default browser path.

### S0603 - Stuxnet

Stuxnet searches the Registry for indicators of security programs.

### S0242 - SynAck

SynAck enumerates Registry keys associated with event logs.

### S0560 - TEARDROP

TEARDROP checked that <code>HKU\SOFTWARE\Microsoft\CTF</code> existed before decoding its embedded payload.

### S1201 - TRANSLATEXT

TRANSLATEXT has queried the following registry key to check for installed Chrome extensions: ` HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist `.

### S0011 - Taidoor

Taidoor can query the Registry on compromised hosts using <code>RegQueryValueExA</code>.

### S0668 - TinyTurla

TinyTurla can query the Registry for its configuration information.

### S0022 - Uroburos

Uroburos can query the Registry, typically `HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds`, to find the key and path to decrypt and load its kernel driver and kernel driver loader.

### S0386 - Ursnif

Ursnif has used Reg to query the Registry for installed programs.

### S0476 - Valak

Valak can use the Registry for code updates and to collect credentials.

### S0180 - Volgmer

Volgmer checks the system for certain Registry keys.

### S0155 - WINDSHIELD

WINDSHIELD can gather Registry values.

### S0612 - WastedLocker

WastedLocker checks for specific registry keys related to the <code>UCOMIEnumConnections</code> and <code>IActiveScriptParseProcedure32</code> interfaces.

### S0579 - Waterbear

Waterbear can query the Registry key <code>"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\MTxOCI"</code> to see if the value `OracleOcilib` exists.

### S1065 - Woody RAT

Woody RAT can search registry keys to identify antivirus programs on an compromised host.

### S0251 - Zebrocy

Zebrocy executes the <code>reg query</code> command to obtain information in the Registry.

### S0330 - Zeus Panda

Zeus Panda checks for the existence of a Registry key and if it contains certain values.

### S0412 - ZxShell

ZxShell can query the netsvc group value data located in the svchost group Registry key.

### S1013 - ZxxZ

ZxxZ can search the registry of a compromised host.

### S0032 - gh0st RAT

gh0st RAT has checked for the existence of a Service key to determine if it has already been installed on the system.

### S0385 - njRAT

njRAT can read specific registry values.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0014 - Operation Wocao

During Operation Wocao, the threat actors executed `/c cd /d c:\windows\temp\ & reg query HKEY_CURRENT_USER\Software\<username>\PuTTY\Sessions\` to detect recent PuTTY sessions, likely to further lateral movement.
