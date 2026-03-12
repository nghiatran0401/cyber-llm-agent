# T1123 - Audio Capture

**Tactic:** Collection
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1123

## Description

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.

## Detection

### Detection Analytics

**Analytic 0619**

Unusual or unauthorized processes accessing microphone APIs (e.g., winmm.dll, avrt.dll) followed by audio file writes to user-accessible or temp directories.

**Analytic 0620**

Processes accessing ALSA/PulseAudio devices or executing audio capture binaries like 'arecord', followed by file creation or suspicious child process spawning.

**Analytic 0621**

Processes invoking AVFoundation or CoreAudio frameworks, accessing input devices via TCC logs or Unified Logs, followed by writing AIFF/WAV/MP3 files to disk.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0438 - Attor

Attor's has a plugin that is capable of recording audio using available input sound devices.

### S0234 - Bandook

Bandook has modules that are capable of capturing audio.

### S0454 - Cadelspy

Cadelspy has the ability to record audio from the compromised host.

### S0338 - Cobian RAT

Cobian RAT has a feature to perform voice recording on the victim’s machine.

### S0115 - Crimson

Crimson can perform audio surveillance using microphones.

### S0213 - DOGCALL

DOGCALL can capture microphone data from the victim's machine.

### S0334 - DarkComet

DarkComet can listen in to victims' conversations through the system’s microphone.

### S0021 - Derusbi

Derusbi is capable of performing audio captures.

### S0152 - EvilGrab

EvilGrab has the capability to capture audio from a victim machine.

### S0143 - Flame

Flame can record audio using any existing hardware recording devices.

### S0434 - Imminent Monitor

Imminent Monitor has a remote microphone monitoring capability.

### S0260 - InvisiMole

InvisiMole can record sound using input audio devices.

### S0163 - Janicab

Janicab captured audio and sent it out to a C2 server.

### S1185 - LightSpy

LightSpy uses Apple's built-in AVFoundation Framework library to capture and manage audio recordings then transform them to JSON blobs for exfiltration.

### S1016 - MacMa

MacMa has the ability to record audio.

### S0282 - MacSpy

MacSpy can record the sounds from microphones on a computer.

### S0409 - Machete

Machete captures audio from the computer’s microphone.

### S1146 - MgBot

MgBot can capture input and output audio streams from infected devices.

### S0339 - Micropsia

Micropsia can perform microphone recording.

### S0336 - NanoCore

NanoCore can capture audio feeds from the system.

### S1090 - NightClub

NightClub can load a module to leverage the LAME encoder and `mciSendStringW` to control and capture audio.

### S0194 - PowerSploit

PowerSploit's <code>Get-MicrophoneAudio</code> Exfiltration module can record system microphone audio.

### S0192 - Pupy

Pupy can record sound with the microphone.

### S0240 - ROKRAT

ROKRAT has an audio capture and eavesdropping module.

### S0332 - Remcos

Remcos can capture data from the system’s microphone.

### S0379 - Revenge RAT

Revenge RAT has a plugin for microphone interception.

### S0098 - T9000

T9000 uses the Skype API to record audio and video calls. It writes encrypted data to <code>%APPDATA%\Intel\Skype</code>.

### S0467 - TajMahal

TajMahal has the ability to capture VoiceIP application audio on an infected host.

### S0257 - VERMIN

VERMIN can perform audio capture.

### S0283 - jRAT

jRAT can capture microphone recordings.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
