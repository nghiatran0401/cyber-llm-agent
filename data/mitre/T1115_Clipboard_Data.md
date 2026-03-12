# T1115 - Clipboard Data

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1115

## Description

Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

For example, on Windows adversaries can access clipboard data by using <code>clip.exe</code> or <code>Get-Clipboard</code>. Additionally, adversaries may monitor then replace users’ clipboard with their data (e.g., Transmitted Data Manipulation).

macOS and Linux also have commands, such as <code>pbpaste</code>, to grab clipboard contents.

## Detection

### Detection Analytics

**Analytic 0965**

Detection of clipboard access via OS utilities (e.g., clip.exe, Get-Clipboard) by non-interactive or abnormal parent processes, potentially chained with staging or exfiltration commands.

**Analytic 0966**

Detection of pbpaste/pbcopy clipboard access by processes without terminal sessions or linked to launch agents, potentially staged for collection.

**Analytic 0967**

Detection of xclip or xsel access to clipboard buffers outside of user terminal context, especially when chained to staging (gzip, base64) or network exfiltration (curl, scp).


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla can steal data from the victim’s clipboard.

### S0373 - Astaroth

Astaroth collects information from the clipboard by using the OpenClipboard() and GetClipboardData() libraries.

### S0438 - Attor

Attor has a plugin that collects data stored in the Windows clipboard by using the OpenClipboard and GetClipboardData APIs.

### S1226 - BOOKWORM

BOOKWORM has used its KBLogger.dll module to steal data saved to the clipboard.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can capture content from the clipboard.

### S0454 - Cadelspy

Cadelspy has the ability to steal data from the clipboard.

### S0261 - Catchamas

Catchamas steals data stored in the clipboard.

### S0660 - Clambling

Clambling has the ability to capture and store clipboard data.

### S0050 - CosmicDuke

CosmicDuke copies and exfiltrates the clipboard contents every 30 seconds.

### S0334 - DarkComet

DarkComet can steal data from the clipboard.

### S1111 - DarkGate

DarkGate starts a thread on execution that captures clipboard data and logs it to a predefined log file.

### S1066 - DarkTortilla

DarkTortilla can download a clipboard information stealer module.

### S0363 - Empire

Empire can harvest clipboard data on both Windows and macOS systems.

### S0569 - Explosive

Explosive has a function to use the OpenClipboard wrapper.

### S0381 - FlawedAmmyy

FlawedAmmyy can collect clipboard data.

### S0531 - Grandoreiro

Grandoreiro can capture clipboard data from a compromised host.

### S0170 - Helminth

The executable version of Helminth has a module to log clipboard contents.

### S1245 - InvisibleFerret

InvisibleFerret has stolen data from the clipboard using the Python project “pyperclip”. InvisibleFerret has also captured clipboard contents during copy and paste operations.

### S0044 - JHUHUGIT

A JHUHUGIT variant accesses a screenshot saved in the clipboard and converts it to a JPG image.

### S0356 - KONNI

KONNI had a feature to steal data from the clipboard.

### S0250 - Koadic

Koadic can retrieve the current content of the user clipboard.

### S0282 - MacSpy

MacSpy can steal clipboard contents.

### S0409 - Machete

Machete hijacks the clipboard data by creating an overlapped window that listens to keyboard events.

### S0652 - MarkiRAT

MarkiRAT can capture clipboard content.

### S0530 - Melcoz

Melcoz can monitor content saved to the clipboard.

### S0455 - Metamorfo

Metamorfo has a function to hijack data from the clipboard by monitoring the contents of the clipboard and replacing the cryptocurrency wallet with the attacker's.

### S1146 - MgBot

MgBot can capture clipboard data.

### S1122 - Mispadu

Mispadu has the ability to capture and replace Bitcoin wallet data in the clipboard on a compromised host.

### S1233 - PAKLOG

PAKLOG has monitored and extracted clipboard contents.

### S0240 - ROKRAT

ROKRAT can extract clipboard data from a compromised host.

### S0148 - RTM

RTM collects data from the clipboard.

### S0332 - Remcos

Remcos steals and modifies data from the clipboard.

### S0375 - Remexi

Remexi collects text from the clipboard.

### S0253 - RunningRAT

RunningRAT contains code to open and copy data from the clipboard.

### S0692 - SILENTTRINITY

SILENTTRINITY can monitor Clipboard text and can use `System.Windows.Forms.Clipboard.GetText()` to collect data from the clipboard.

### S0467 - TajMahal

TajMahal has the ability to steal data from the clipboard of an infected host.

### S0004 - TinyZBot

TinyZBot contains functionality to collect information from the clipboard.

### S0257 - VERMIN

VERMIN collects data stored in the clipboard.

### S1207 - XLoader

XLoader can collect data stored in the victim's clipboard.

### S0330 - Zeus Panda

Zeus Panda can hook GetClipboardData function to watch for clipboard pastes to collect.

### S0283 - jRAT

jRAT can capture clipboard data.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0014 - Operation Wocao

During Operation Wocao, threat actors collected clipboard data in plaintext.
