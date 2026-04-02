# T1113 - Screen Capture

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1113

## Description

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.

## Detection

### Detection Analytics

**Analytic 0980**

Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk.

**Analytic 0981**

Invocation of built-in commands like screencapture or use of undocumented APIs from suspicious parent processes.

**Analytic 0982**

Use of tools like xwd or import to generate screenshots, especially under non-GUI parent processes.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla can capture screenshots of the victim’s desktop.

### S0622 - AppleSeed

AppleSeed can take screenshots on a compromised host by calling a series of APIs.

### S0456 - Aria-body

Aria-body has the ability to capture screenshots on compromised hosts.

### S1087 - AsyncRAT

AsyncRAT has the ability to view the screen on compromised hosts.

### S0438 - Attor

Attor's has a plugin that captures screenshots of the target applications.

### S0344 - Azorult

Azorult can capture screenshots of the victim’s machines.

### S1081 - BADHATCH

BADHATCH can take screenshots and send them to an actor-controlled C2 server.

### S0128 - BADNEWS

BADNEWS has a command to take a screenshot and send it to the C2 server.

### S0017 - BISCUIT

BISCUIT has a command to periodically take screenshots of the system.

### S0657 - BLUELIGHT

BLUELIGHT has captured a screenshot of the display every 30 seconds for the first 5 minutes after initiating a C2 loop, and then once every five minutes thereafter.

### S0337 - BadPatch

BadPatch captures screenshots in .jpg format and then exfiltrates them.

### S0234 - Bandook

Bandook is capable of taking an image of and uploading the current desktop.

### S0089 - BlackEnergy

BlackEnergy is capable of taking screenshots.

### S1063 - Brute Ratel C4

Brute Ratel C4 can take screenshots on compromised hosts.

### S1149 - CHIMNEYSWEEP

CHIMNEYSWEEP can capture screenshots on targeted systems using a timer and either upload them or store them to disk.

### S0023 - CHOPSTICK

CHOPSTICK has the capability to capture screenshots.

### S0454 - Cadelspy

Cadelspy has the ability to capture screenshots and webcam photos.

### S0351 - Cannon

Cannon can take a screenshot of the desktop.

### S0030 - Carbanak

Carbanak performs desktop video recording and captures screenshots of the desktop and sends it to the C2 server.

### S0484 - Carberp

Carberp can capture display screenshots with the screens_dll.dll plugin.

### S0348 - Cardinal RAT

Cardinal RAT can capture screenshots.

### S0261 - Catchamas

Catchamas captures screenshots based on specific keywords in the window’s title.

### S0631 - Chaes

Chaes can capture screenshots of the infected machine.

### S0674 - CharmPower

CharmPower has the ability to capture screenshots.

### S0667 - Chrommme

Chrommme has the ability to capture screenshots.

### S0660 - Clambling

Clambling has the ability to capture screenshots.

### S0154 - Cobalt Strike

Cobalt Strike's Beacon payload is capable of capturing screenshots.

### S0338 - Cobian RAT

Cobian RAT has a feature to perform screen capture.

### S0591 - ConnectWise

ConnectWise can take screenshots on remote hosts.

### S0050 - CosmicDuke

CosmicDuke takes periodic screenshots and exfiltrates them.

### S0115 - Crimson

Crimson contains a command to perform screen captures.

### S0235 - CrossRAT

CrossRAT is capable of taking screen captures.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can run `screencapture` to collect screenshots from compromised hosts.

### S0213 - DOGCALL

DOGCALL is capable of capturing screenshots of the victim's machine.

### S1159 - DUSTTRAP

DUSTTRAP can capture screenshots.

### S0187 - Daserf

Daserf can take screenshots.

### S0021 - Derusbi

Derusbi is capable of performing screen captures.

### S0062 - DustySky

DustySky captures PNG screenshots of the main screen.

### S0593 - ECCENTRICBANDWAGON

ECCENTRICBANDWAGON can capture screenshots and store them locally.

### S0363 - Empire

Empire is capable of capturing screenshots on Windows and macOS systems.

### S0152 - EvilGrab

EvilGrab has the capability to capture screenshots.

### S0182 - FinFisher

FinFisher takes a screenshot of the screen and displays it on top of all other windows for few seconds in an apparent attempt to hide some messages showed by the system during the setup process.

### S0143 - Flame

Flame can take regular screenshots when certain applications are open that are sent to the command and control server.

### S0381 - FlawedAmmyy

FlawedAmmyy can capture screenshots.

### S0277 - FruitFly

FruitFly takes screenshots of the user's desktop.

### S1044 - FunnyDream

The FunnyDream ScreenCap component can take screenshots on a compromised host.

### S0417 - GRIFFON

GRIFFON has used a screenshot module that can be used to take a screenshot of the remote system.

### S0151 - HALFBAKED

HALFBAKED can obtain screenshots from the victim.

### S1229 - Havoc

Havoc can capture screenshots.

### S0431 - HotCroissant

HotCroissant has the ability to do real time screen viewing on an infected host.

### S0203 - Hydraq

Hydraq includes a component based on the code of VNC that can stream a live feed of the desktop of an infected host.

### S0398 - HyperBro

HyperBro has the ability to take screenshots.

### S0260 - InvisiMole

InvisiMole can capture screenshots of not only the entire screen, but of each separate window open, in case they are overlapping.

### S0044 - JHUHUGIT

A JHUHUGIT variant takes screenshots by simulating the user pressing the "Take Screenshot" key (VK_SCREENSHOT), accessing the screenshot saved in the clipboard, and converting it to a JPG image.

### S0163 - Janicab

Janicab captured screenshots and sent them out to a C2 server.

### S0271 - KEYMARBLE

KEYMARBLE can capture screenshots of the victim’s machine.

### S0356 - KONNI

KONNI can take screenshots of the victim’s machine.

### S0088 - Kasidet

Kasidet has the ability to initiate keylogging and screen captures.

### S0265 - Kazuar

Kazuar captures screenshots of the victim’s screen.

### S0387 - KeyBoy

KeyBoy has a command to perform screen grabbing.

### S0437 - Kivars

Kivars has the ability to capture screenshots on the infected host.

### S1185 - LightSpy

LightSpy uses Apple's built-in AVFoundation Framework library to access the user's camera and screen. It uses the `AVCaptureStillImage` to take a picture using the user's camera and the `AVCaptureScreen` to take a screenshot or record the user's screen for a specified period of time.

### S0680 - LitePower

LitePower can take system screenshots and save them to `%AppData%`.

### S0681 - Lizar

Lizar can take JPEG screenshots of an infected system. Lizar has also used a plugin to take a screenshot of the infected system.

### S0582 - LookBack

LookBack can take desktop screenshots.

### S1213 - Lumma Stealer

Lumma Stealer has taken screenshots of victim machines.

### S1142 - LunarMail

LunarMail can capture screenshots from compromised hosts.

### S1016 - MacMa

MacMa has used Apple’s Core Graphic APIs, such as `CGWindowListCreateImageFromArray`, to capture the user's screen and open windows.

### S0282 - MacSpy

MacSpy can capture screenshots of the desktop over multiple monitors.

### S0409 - Machete

Machete captures screenshots.

### S1060 - Mafalda

Mafalda can take a screenshot of the target machine and save it to a file.

### S1156 - Manjusaka

Manjusaka can take screenshots of the victim desktop.

### S0652 - MarkiRAT

MarkiRAT can capture screenshots that are initially saved as ‘scr.jpg’.

### S0167 - Matryoshka

Matryoshka is capable of performing screen captures.

### S0455 - Metamorfo

Metamorfo can collect screenshots of the victim’s machine.

### S0339 - Micropsia

Micropsia takes screenshots every 90 seconds by calling the Gdi32.BitBlt API.

### S1122 - Mispadu

Mispadu has the ability to capture screenshots on compromised hosts.

### S0198 - NETWIRE

NETWIRE can capture the victim's screen.

### S1107 - NKAbuse

NKAbuse can take screenshots of the victim machine.

### S1090 - NightClub

NightClub can load a module to call `CreateCompatibleDC` and `GdipSaveImageToStream` for screen capture.

### S0644 - ObliqueRAT

ObliqueRAT can capture a screenshot of the current screen.

### S0340 - Octopus

Octopus can capture screenshots of the victims’ machine.

### S0216 - POORAIM

POORAIM can perform screen capturing.

### S0223 - POWERSTATS

POWERSTATS can retrieve screenshots from compromised hosts.

### S0184 - POWRUNER

POWRUNER can capture a screenshot from a victim.

### S1050 - PcShare

PcShare can take screen shots of a compromised machine.

### S0643 - Peppy

Peppy can take screenshots on targeted systems.

### S0013 - PlugX

PlugX allows the operator to capture screenshots.

### S0428 - PoetRAT

PoetRAT has the ability to take screen captures.

### S0194 - PowerSploit

PowerSploit's <code>Get-TimedScreenshot</code> Exfiltration module can take screenshots at regular intervals.

### S0113 - Prikormka

Prikormka contains a module that captures screenshots of the victim's desktop.

### S0279 - Proton

Proton captures the content of the desktop with the screencapture binary.

### S0147 - Pteranodon

Pteranodon can capture screenshots at a configurable interval.

### S0192 - Pupy

Pupy can drop a mouse-logger that will take small screenshots around at each click and then send back to the server.

### S1209 - Quick Assist

Quick Assist allows for the remote administrator to take screenshots of the running system.

### S0686 - QuietSieve

QuietSieve has taken screenshots every five minutes and saved them to the user's local Application Data folder under `Temp\SymbolSourceSymbols\icons` or `Temp\ModeAuto\icons`.

### S0662 - RCSession

RCSession can capture screenshots from a compromised host.

### S0495 - RDAT

RDAT can take a screenshot on the infected system.

### S0240 - ROKRAT

ROKRAT can capture screenshots of the infected system using the `gdi32` library.

### S0148 - RTM

RTM can capture screenshots.

### S1148 - Raccoon Stealer

Raccoon Stealer can capture screenshots from victim systems.

### S0629 - RainyDay

RainyDay has the ability to capture screenshots.

### S0458 - Ramsay

Ramsay can take screenshots every 30 seconds as well as when an external removable storage device is connected.

### S0153 - RedLeaves

RedLeaves can capture screenshots.

### S1240 - RedLine Stealer

RedLine Stealer can capture screenshots on a compromised host.

### S0332 - Remcos

Remcos takes automated screenshots of the infected machine.

### S0375 - Remexi

Remexi takes screenshots of windows of interest.

### S0592 - RemoteUtilities

RemoteUtilities can take screenshots on a compromised host.

### S0379 - Revenge RAT

Revenge RAT has a plugin for screen capture.

### S0270 - RogueRobin

RogueRobin has a command named <code>$screenshot</code> that may be responsible for taking screenshots of the victim machine.

### S0090 - Rover

Rover takes screenshots of the compromised system's desktop and saves them to <code>C:\system\screenshot.bmp</code> for exfiltration every 60 minutes.

### S0217 - SHUTTERSPEED

SHUTTERSPEED can capture screenshots.

### S0692 - SILENTTRINITY

SILENTTRINITY can take a screenshot of the current desktop.

### S0533 - SLOTHFULMEDIA

SLOTHFULMEDIA has taken a screenshot of a victim's desktop, named it "Filter3.jpg", and stored it in the local directory.

### S0649 - SMOKEDHAM

SMOKEDHAM can capture screenshots of the victim’s desktop.

### S1064 - SVCReady

SVCReady can take a screenshot from an infected host.

### S0546 - SharpStage

SharpStage has the ability to capture the victim's screen.

### S0633 - Sliver

Sliver can take screenshots of the victim’s active display.

### S0273 - Socksbot

Socksbot can take screenshots.

### S0380 - StoneDrill

StoneDrill can take screenshots.

### S1034 - StrifeWater

StrifeWater has the ability to take screen captures.

### S0663 - SysUpdate

SysUpdate has the ability to capture screenshots.

### S0098 - T9000

T9000 can take screenshots of the desktop and target application windows, saving them to user directories as one byte XOR encrypted .dat files.

### S1239 - TONESHELL

TONESHELL has conducted screen capturing.

### S1201 - TRANSLATEXT

TRANSLATEXT has the ability to capture screenshots of new browser tabs, based on the presence of the `Capture` flag.

### S0199 - TURNEDUP

TURNEDUP is capable of taking screenshots.

### S0467 - TajMahal

TajMahal has the ability to take screenshots on an infected host including capturing content from windows of instant messaging applications.

### S0004 - TinyZBot

TinyZBot contains screen capture functionality.

### S0094 - Trojan.Karagany

Trojan.Karagany can take a desktop screenshot and save the file into <code>\ProgramData\Mail\MailAg\shot.png</code>.

### S1196 - Troll Stealer

Troll Stealer can capture screenshots from victim machines.

### S0647 - Turian

Turian has the ability to take screenshots.

### S0275 - UPPERCUT

UPPERCUT can capture desktop screenshots in the PNG format and send them to the C2 server.

### S0386 - Ursnif

Ursnif has used hooked APIs to take screenshots.

### S0257 - VERMIN

VERMIN can perform screen captures of the victim’s machine.

### S0476 - Valak

Valak has the ability to take screenshots on a compromised host.

### S1065 - Woody RAT

Woody RAT has the ability to take a screenshot of the infected host desktop using Windows GDI+.

### S0161 - XAgentOSX

XAgentOSX contains the takeScreenShot (along with startTakeScreenShot and stopTakeScreenShot) functions to take screenshots using the CGGetActiveDisplayList, CGDisplayCreateImage, and NSImage:initWithCGImage methods.

### S0658 - XCSSET

XCSSET saves a screen capture of the victim's system with a numbered filename and <code>.jpg</code> extension. Screen captures are taken at specified intervals based on the system.

### S1207 - XLoader

XLoader can capture screenshots on compromised hosts.

### S0086 - ZLib

ZLib has the ability to obtain screenshots of the compromised system.

### S0251 - Zebrocy

A variant of Zebrocy captures screenshots of the victim’s machine in JPEG and BMP format.

### S0330 - Zeus Panda

Zeus Panda can take screenshots of the victim’s machine.

### S0412 - ZxShell

ZxShell can capture screenshots.

### S0032 - gh0st RAT

gh0st RAT can capture the victim’s screen remotely.

### S0283 - jRAT

jRAT has the capability to take screenshots of the victim’s machine.

### S1059 - metaMain

metaMain can take and save screenshots.

### S0385 - njRAT

njRAT can capture screenshots of the victim’s machines.

### S0248 - yty

yty collects screenshots of the victim machine.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
