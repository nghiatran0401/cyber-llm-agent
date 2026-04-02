# T1592 - Gather Victim Host Information

**Tactic:** Reconnaissance
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1592

## Description

Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).

Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about hosts may also be exposed to adversaries via online or other accessible data sets (ex: Social Media or Search Victim-Owned Websites). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: Supply Chain Compromise or External Remote Services).

Adversaries may also gather victim host information via User-Agent HTTP headers, which are sent to a server to identify the application, operating system, vendor, and/or version of the requesting user agent. This can be used to inform the adversary’s follow-on action. For example, adversaries may check user agents for the requesting operating system, then only serve malware for target operating systems while ignoring others.

## Detection

### Detection Analytics

**Analytic 1958**

Internet scanners may be used to look for patterns associated with malicious content designed to collect host information from visitors.
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.


## Mitigations

### M1056 - Pre-compromise

This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
