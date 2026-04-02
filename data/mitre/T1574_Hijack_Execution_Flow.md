# T1574 - Hijack Execution Flow

**Tactic:** Defense Evasion, Persistence, Privilege Escalation
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1574

## Description

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

## Detection

### Detection Analytics

**Analytic 0609**

Unusual modifications to service binary paths, registry keys, or DLL load paths resulting in alternate execution flow. Defender observes registry key modifications, suspicious file writes into system directories, and processes loading libraries from abnormal paths.

**Analytic 0610**

Adversary manipulation of shared library paths, environment variables, or replacement of service binaries. Defender observes suspicious modifications in /etc/ld.so.preload, service config changes, or file writes replacing existing executables.

**Analytic 0611**

Abuse of DYLD_INSERT_LIBRARIES or hijacking framework paths for malicious libraries. Defender observes processes invoking abnormal dylibs, modified plist files, or persistence entries pointing to altered binaries.


## Mitigations

### M1013 - Application Developer Guidance

When possible, include hash values in manifest files to help prevent side-loading of malicious libraries.

### M1047 - Audit

Use auditing tools capable of detecting hijacking opportunities on systems within an enterprise and correct them. Toolkits like the PowerSploit framework contain PowerUp modules that can be used to explore systems for hijacking weaknesses.

Use the program sxstrace.exe that is included with Windows along with manual inspection to check manifest files for side-loading vulnerabilities in software.

Find and eliminate path interception weaknesses in program configuration files, scripts, the PATH environment variable, services, and in shortcuts by surrounding PATH variables with quotation marks when functions allow for them. Be aware of the search order Windows uses for executing or loading binaries and use fully qualified paths wherever appropriate.

Clean up old Windows Registry keys when software is uninstalled to avoid keys with no associated legitimate binaries. Periodically search for and correct or report path interception weaknesses on systems that may have been introduced using custom or available tools that report software using insecure path configurations.

### M1040 - Behavior Prevention on Endpoint

Some endpoint security solutions can be configured to block some types of behaviors related to process injection/memory tampering based on common sequences of indicators (ex: execution of specific API functions).

### M1038 - Execution Prevention

Adversaries may use new payloads to execute this technique. Identify and block potentially malicious software executed through hijacking by using application control solutions also capable of blocking libraries loaded by legitimate software.

### M1022 - Restrict File and Directory Permissions

Install software in write-protected locations. Set directory access controls to prevent file writes to the search paths for applications, both in the folders where applications are run from and the standard library folders.

### M1044 - Restrict Library Loading

Disallow loading of remote DLLs. This is included by default in Windows Server 2012+ and is available by patch for XP+ and Server 2003+.

Enable Safe DLL Search Mode to force search for system DLLs in directories with greater restrictions (e.g. <code>%SYSTEMROOT%</code>)to be used before local directory DLLs (e.g. a user's home directory)

The Safe DLL Search Mode can be enabled via Group Policy at Computer Configuration > [Policies] > Administrative Templates > MSS (Legacy): MSS: (SafeDllSearchMode) Enable Safe DLL search mode. The associated Windows Registry key for this is located at <code>HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDLLSearchMode</code>

### M1024 - Restrict Registry Permissions

Ensure proper permissions are set for Registry hives to prevent users from modifying keys for system components that may lead to privilege escalation.

### M1051 - Update Software

Update software regularly to include patches that fix DLL side-loading vulnerabilities.

### M1052 - User Account Control

Turn off UAC's privilege elevation for standard users <code>[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]</code> to automatically deny elevation requests, add: <code>"ConsentPromptBehaviorUser"=dword:00000000</code>. Consider enabling installer detection for all users by adding: <code>"EnableInstallerDetection"=dword:00000001</code>. This will prompt for a password for installation and also log the attempt. To disable installer detection, instead add: <code>"EnableInstallerDetection"=dword:00000000</code>. This may prevent potential elevation of privileges through exploitation during the process of UAC detecting the installer, but will allow the installation process to continue without being logged.

### M1018 - User Account Management

Limit privileges of user accounts and groups so that only authorized administrators can interact with service changes and service binary target path locations. Deny execution from user directories such as file download directories and temp directories where able.

Ensure that proper permissions and directory access control are set to deny users the ability to write files to the top-level directory <code>C:</code> and system directories, such as <code>C:\Windows\</code>, to reduce places where malicious files could be placed for execution.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1105 - COATHANGER

COATHANGER will remove and write malicious shared objects associated with legitimate system functions such as `read(2)`.

### S1111 - DarkGate

DarkGate edits the Registry key <code>HKCU\Software\Classes\mscfile\shell\open\command</code> to execute a malicious AutoIt script. When eventvwr.exe is executed, this will call the Microsoft Management Console (mmc.exe), which in turn references the modified Registry key.

### S0354 - Denis

Denis replaces the nonexistent Windows DLL "msfte.dll" with its own malicious version, which is loaded by the SearchIndexer.exe and SearchProtocolHost.exe.

### S0567 - Dtrack

One of Dtrack can replace the normal flow of a program execution with malicious code.

### S1147 - Nightdoor

Nightdoor uses a legitimate executable to load a malicious DLL file for installation.

### S1130 - Raspberry Robin

Raspberry Robin will drop a copy of itself to a subfolder in <code>%Program Data%</code> or <code>%Program Data%\\Microsoft\\</code> to attempt privilege elevation and defense evasion if not running in Session 0.

### S1018 - Saint Bot

Saint Bot will use the malicious file <code>slideshow.mp4</code> if present to load the core API provided by <code>ntdll.dll</code> to avoid any hooks placed on calls to the original <code>ntdll.dll</code> file by endpoint detection and response or antimalware software.

### S0444 - ShimRat

ShimRat can hijack the cryptbase.dll within migwiz.exe to escalate privileges and bypass UAC controls.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0017 - C0017

During C0017, APT41 established persistence by loading malicious libraries via modifications to the Import Address Table (IAT) within legitimate Microsoft binaries.

### C0036 - Pikabot Distribution February 2024

Pikabot Distribution February 2024 utilized a tampered legitimate executable, `grepWinNP3.exe`, for its first stage Pikabot loader, modifying the open-source tool to execute malicious code when launched.
