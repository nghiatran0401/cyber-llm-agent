# T1010 - Application Window Discovery

**Tactic:** Discovery
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1010

## Description

Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used identify potential data to collect as well as identifying security tooling (Security Software Discovery) to evade.

Adversaries typically abuse system features for this type of enumeration. For example, they may gather information through native system features such as Command and Scripting Interpreter commands and Native API functions.

## Detection

### Detection Analytics

**Analytic 0271**

Processes using Win32 API calls (e.g., EnumWindows, GetForegroundWindow) or scripting tools (e.g., PowerShell, VBScript) to enumerate open windows. These often appear with reconnaissance or data collection TTPs.

**Analytic 0272**

Scripted or binary usage of X11 utilities (e.g., xdotool, wmctrl) or direct /proc/*/window mappings to discover open GUI windows and active desktops.

**Analytic 0273**

Processes that utilize AppleScript, `CGWindowListCopyWindowInfo`, or `NSRunningApplication` APIs to list active application windows and foreground processes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0456 - Aria-body

Aria-body has the ability to identify the titles of running windows on a compromised host.

### S0438 - Attor

Attor can obtain application window titles and then determines which windows to perform Screen Capture on.

### S0454 - Cadelspy

Cadelspy has the ability to identify open windows on the compromised host.

### S0261 - Catchamas

Catchamas obtains application windows titles and then determines which windows to perform Screen Capture on.

### S1159 - DUSTTRAP

DUSTTRAP can enumerate running application windows.

### S1111 - DarkGate

DarkGate will search for cryptocurrency wallets by examining application window names for specific strings. DarkGate extracts information collected via NirSoft tools from the hosting process's memory by first identifying the window through the <code>FindWindow</code> API function.

### S0673 - DarkWatchman

DarkWatchman reports window names along with keylogger information to provide application context.

### S0038 - Duqu

The discovery modules used with Duqu can collect information on open windows.

### S0696 - Flagpro

Flagpro can check the name of the window displayed on the system.

### S1044 - FunnyDream

FunnyDream has the ability to discover application windows via execution of `EnumWindows`.

### S0531 - Grandoreiro

Grandoreiro can identify installed security tools based on window names.

### S0431 - HotCroissant

HotCroissant has the ability to list the names of all open windows on the infected host.

### S0260 - InvisiMole

InvisiMole can enumerate windows and child windows on a compromised host.

### S0265 - Kazuar

Kazuar gathers information about opened windows.

### S0409 - Machete

Machete saves the window names.

### S0455 - Metamorfo

Metamorfo can enumerate all windows on the victim’s machine.

### S0198 - NETWIRE

NETWIRE can discover and close windows on controlled systems.

### S0033 - NetTraveler

NetTraveler reports window names along with keylogger information to provide application context.

### S1090 - NightClub

NightClub can use `GetForegroundWindow` to enumerate the active window.

### S1233 - PAKLOG

PAKLOG has used `GetForegroundWindow` to access the foreground window.  PAKLOG has also captured text from the foreground windows.

### S0435 - PLEAD

PLEAD has the ability to list open windows on the compromised host.

### S0012 - PoisonIvy

PoisonIvy captures window titles.

### S0139 - PowerDuke

PowerDuke has a command to get text of the current foreground window.

### S0650 - QakBot

QakBot has the ability to enumerate windows on a compromised host.

### S0240 - ROKRAT

ROKRAT can use  the `GetForegroundWindow` and `GetWindowText` APIs to discover where the user is typing.

### S0375 - Remexi

Remexi has a command to capture active windows on the machine and retrieve window titles.

### S0692 - SILENTTRINITY

SILENTTRINITY can enumerate the active Window during keylogging through execution of `GetActiveWindowTitle`.

### S0157 - SOUNDBITE

SOUNDBITE is capable of enumerating application windows.

### S1239 - TONESHELL

TONESHELL has used `GetForegroundWindow` to detect virtualization or sandboxes by calling the API twice and comparing each window handle.

### S0094 - Trojan.Karagany

Trojan.Karagany can monitor the titles of open windows to identify specific keywords.

### S0219 - WINERACK

WINERACK can enumerate active windows.

### S0385 - njRAT

njRAT gathers information about opened windows during the initial infection.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
