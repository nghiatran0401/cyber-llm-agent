# T1176 - Software Extensions

**Tactic:** Persistence
**Platforms:** Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1176

## Description

Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms. Extensions are typically installed via official marketplaces, app stores, or manually loaded by users, and they often inherit the permissions and access levels of the host application. 

  
Malicious extensions can be introduced through various methods, including social engineering, compromised marketplaces, or direct installation by users or by adversaries who have already gained access to a system. Malicious extensions can be named similarly or identically to benign extensions in marketplaces. Security mechanisms in extension marketplaces may be insufficient to detect malicious components, allowing adversaries to bypass automated scanners or exploit trust established during the installation process. Adversaries may also abuse benign extensions to achieve their objectives, such as using legitimate functionality to tunnel data or bypass security controls. 

The modular nature of extensions and their integration with host applications make them an attractive target for adversaries seeking to exploit trusted software ecosystems. Detection can be challenging due to the inherent trust placed in extensions during installation and their ability to blend into normal application workflows.

## Detection

### Detection Analytics

**Analytic 0251**

Installation or execution of a malicious browser or IDE extension, followed by abnormal registry entries or outbound network connections from the host application

**Analytic 0252**

Installation of configuration profiles or plist entries associated with malicious or unauthorized browser extensions

**Analytic 0253**

Manual or script-based installation of extension-like modules into browser config directories or IDE plugin paths, followed by suspicious network activity


## Mitigations

### M1047 - Audit

Ensure extensions that are installed are the intended ones, as many malicious extensions may masquerade as legitimate ones.

### M1038 - Execution Prevention

Set an extension allow or deny list as appropriate for your security policy.

### M1033 - Limit Software Installation

Only install extensions from trusted sources that can be verified.

### M1051 - Update Software

Ensure operating systems and software are using the most current version.

### M1017 - User Training

Train users to minimize extension use, and to only install trusted extensions.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
