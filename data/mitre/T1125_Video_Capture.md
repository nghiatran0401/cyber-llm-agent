# T1125 - Video Capture

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1125

## Description

An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from Screen Capture due to use of specific devices or applications for video recording rather than capturing the victim's screen.

In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton.

## Detection

### Detection Analytics

**Analytic 0568**

A non-standard process (or script-hosted process) loads camera/video-capture libraries (e.g., avicap32.dll, mf.dll, ksproxy.ax), opens the Camera Frame Server/device, writes video/image artifacts (e.g., .mp4/.avi/.yuv) to unusual locations, and optionally initiates outbound transfer shortly after.

**Analytic 0569**

A process opens/reads /dev/video* (V4L2), performs ioctl/read loops, writes large/continuous video artifacts to disk, and/or quickly establishes outbound connections for exfiltration.

**Analytic 0570**

A non-whitelisted process receives TCC camera entitlement (kTCCServiceCamera), opens AppleCamera/AVFoundation device handles, writes .mov/.mp4 artifacts to unusual locations, and/or beacons/exfiltrates soon after.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0331 - Agent Tesla

Agent Tesla can access the victim’s webcam and record video.

### S1087 - AsyncRAT

AsyncRAT can record screen content on targeted systems.

### S0234 - Bandook

Bandook has modules that are capable of capturing video from a victim's webcam.

### S0660 - Clambling

Clambling can record screen content in AVI format.

### S0338 - Cobian RAT

Cobian RAT has a feature to access the webcam on the victim’s machine.

### S0591 - ConnectWise

ConnectWise can record video on remote hosts.

### S0115 - Crimson

Crimson can capture webcam video on targeted systems.

### S0334 - DarkComet

DarkComet can access the victim’s webcam to take pictures.

### S0021 - Derusbi

Derusbi is capable of capturing video.

### S0363 - Empire

Empire can capture webcam data on Windows and macOS systems.

### S0152 - EvilGrab

EvilGrab has the capability to capture video from a victim machine.

### S0434 - Imminent Monitor

Imminent Monitor has a remote webcam monitoring capability.

### S0260 - InvisiMole

InvisiMole can remotely activate the victim’s webcam to capture content.

### S0265 - Kazuar

Kazuar captures images from the webcam.

### S0409 - Machete

Machete takes photos from the computer’s web camera.

### S0336 - NanoCore

NanoCore can access the victim's webcam and capture data.

### S0644 - ObliqueRAT

ObliqueRAT can capture images from webcams on compromised hosts.

### S1050 - PcShare

PcShare can capture camera video as part of its collection process.

### S0428 - PoetRAT

PoetRAT has used a Python tool named Bewmac to record the webcam on compromised hosts.

### S0192 - Pupy

Pupy can access a connected webcam and capture pictures.

### S0262 - QuasarRAT

QuasarRAT can perform webcam viewing.

### S1209 - Quick Assist

Quick Assist allows for the remote administrator to view the interactive session of the running machine, including full screen activity.

### S0332 - Remcos

Remcos can access a system’s webcam and take pictures.

### S0379 - Revenge RAT

Revenge RAT has the ability to access the webcam.

### S0461 - SDBbot

SDBbot has the ability to record video on a compromised host.

### S0098 - T9000

T9000 uses the Skype API to record audio and video calls. It writes encrypted data to <code>%APPDATA%\Intel\Skype</code>.

### S0467 - TajMahal

TajMahal has the ability to capture webcam video.

### S0670 - WarzoneRAT

WarzoneRAT can access the webcam on a victim's machine.

### S0412 - ZxShell

ZxShell has a command to perform video device spying.

### S0283 - jRAT

jRAT has the capability to capture video from a webcam.

### S0385 - njRAT

njRAT can access the victim's webcam.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
