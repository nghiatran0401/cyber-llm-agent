# T1189 - Drive-by Compromise

**Tactic:** Initial Access
**Platforms:** Identity Provider, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1189

## Description

Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Multiple ways of delivering exploit code to a browser exist (i.e., Drive-by Target), including:

* A legitimate website is compromised, allowing adversaries to inject malicious code
* Script files served to a legitimate website from a publicly writeable cloud storage bucket are modified by an adversary
* Malicious ads are paid for and served through legitimate ad providers (i.e., Malvertising)
* Built-in web application interfaces that allow user-controllable content are leveraged for the insertion of malicious scripts or iFrames (e.g., cross-site scripting)

Browser push notifications may also be abused by adversaries and leveraged for malicious code injection via User Execution. By clicking "allow" on browser push notifications, users may be granting a website permission to run JavaScript code on their browser.

Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or a particular region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is often referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.

Typical drive-by compromise process:

1. A user visits a website that is used to host the adversary controlled content.
2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. The user may be required to assist in this process by enabling scripting, notifications, or active website components and ignoring warning dialog boxes.
3. Upon finding a vulnerable version, exploit code is delivered to the browser.
4. If exploitation is successful, the adversary will gain code execution on the user's system unless other protections are in place. In some cases, a second visit to the website after the initial scan is required before exploit code is delivered.

Unlike Exploit Public-Facing Application, the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.

## Detection

### Detection Analytics

**Analytic 0498**

Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file drops. Defender sees network requests to previously unseen/suspicious domains or resources + browser process spawning unusual children or loading unsigned modules + file writes or registry changes shortly after those requests.

**Analytic 0499**

Correlated evidence of browser or webview fetches to uncommon domains or mutated JS resources (proxy/NGFW logs + Zeek/HTTP logs) followed by unexpected interpreters or script engines executing (python, ruby, sh) spawned from browser processes or user sessions, rapid on-disk staging in /tmp, and outbound connections that deviate from baseline. Defender sees: uncommon resource fetch → short-lived child process executions from user browser context → file writes in temp directories → anomalous outbound C2-like connections.

**Analytic 0500**

Correlated evidence where Safari/Chrome/WebKit-based processes issue network requests for uncommon or obfuscated JS resources followed by spawning of script interpreters, launchd or ad-hoc binaries, unusual child processes, or dynamic library loads into browser processes. Defender sees: proxy/HTTP logs with suspicious resource content + unifiedlogs/ASL showing browser/plugin crashes or extension loads + process events indicating child process creation and file writes to /var/folders or /tmp shortly after the fetch.

**Analytic 0501**

Post-compromise identity & session anomalies that follow a drive-by compromise: token reuse from new/unfamiliar IPs, anomalous sign-in patterns for previously inactive users, unexpected consent/grant events, or provisioning changes. Defender sees an endpoint/browser compromise (network + endpoint signals) followed by unusual IdP events: new refresh token issuance, consent/consent-grant events, odd MFA bypass patterns, or unusual OAuth client registrations.


## Mitigations

### M1048 - Application Isolation and Sandboxing

Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist.

Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist for these types of systems.

### M1050 - Exploit Protection

Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. Many of these protections depend on the architecture and target application binary for compatibility.

### M1021 - Restrict Web-Based Content

Adblockers can help prevent malicious code served through ads from executing in the first place. Script blocking extensions can also help to prevent the execution of JavaScript. 

Consider disabling browser push notifications from certain applications and browsers.

### M1051 - Update Software

Ensuring that all browsers and plugins are kept updated can help prevent the exploit phase of this technique. Use modern browsers with security features turned on.

### M1017 - User Training

Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other techniques that involve user interaction.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0606 - Bad Rabbit

Bad Rabbit spread through watering holes on popular sites by injecting JavaScript into the HTML body or a <code>.js</code> file.

### S0482 - Bundlore

Bundlore has been spread through malicious advertisements on websites.

### S0531 - Grandoreiro

Grandoreiro has used compromised websites and Google Ads to bait victims into downloading its installer.

### S0483 - IcedID

IcedID has cloned legitimate websites/applications to distribute the malware.

### S0215 - KARAE

KARAE was distributed through torrent file-sharing websites to South Korean victims, using a YouTube video downloader application as a lure.

### S0451 - LoudMiner

LoudMiner is typically bundled with pirated copies of Virtual Studio Technology (VST) for Windows and macOS.

### S0216 - POORAIM

POORAIM has been delivered through compromised sites acting as watering holes.

### S0496 - REvil

REvil has infected victim machines through compromised websites and exploit kits.

### S1086 - Snip3

Snip3 has been delivered to targets via downloads from malicious domains.

### S1124 - SocGholish

SocGholish has been distributed through compromised websites with malicious content often masquerading as browser updates.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0057 - 3CX Supply Chain Attack

During the 3CX Supply Chain Attack, AppleJeus compromised the `www.tradingtechnologies[.]com` website hosting a hidden IFRAME to exploit visitors, two months before the site was known to deliver a compromised version of the X_TRADER software package.

### C0010 - C0010

During C0010, UNC3890 actors likely established a watering hole that was hosted on a login page of a legitimate Israeli shipping company that was active until at least November 2021.

### C0016 - Operation Dust Storm

During Operation Dust Storm, the threat actors used a watering hole attack on a popular software reseller to exploit the then-zero-day Internet Explorer vulnerability CVE-2014-0322.
