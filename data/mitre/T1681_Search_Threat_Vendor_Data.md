# T1681 - Search Threat Vendor Data

**Tactic:** Reconnaissance
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1681

## Description

Threat actors may seek information/indicators from closed or open threat intelligence sources gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns. These reports may include descriptions of behavior, detailed breakdowns of attacks, atomic indicators such as malware hashes or IP addresses, timelines of a group’s activity, and more. Adversaries may change their behavior when planning their future operations. 

Adversaries have been observed replacing atomic indicators mentioned in blog posts in under a week. Adversaries have also been seen searching for their own domain names in threat vendor data and then taking them down, likely to avoid seizure or further investigation.

This technique is distinct from Threat Intel Vendors in that it describes threat actors performing reconnaissance on their own activity, not in search of victim information.

## Detection

### Detection Analytics

**Analytic 1998**

Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.


## Mitigations

### M1056 - Pre-compromise

This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on designing defenses that are not reliant on atomic indicators.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
