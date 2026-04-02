# T1593 - Search Open Websites/Domains

**Tactic:** Reconnaissance
**Platforms:** PRE
**Reference:** https://attack.mitre.org/techniques/T1593

## Description

Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.

Adversaries may search in different online sites depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Phishing for Information or Search Open Technical Databases), establishing operational resources (ex: Establish Accounts or Compromise Accounts), and/or initial access (ex: External Remote Services or Phishing).

## Detection

### Detection Analytics

**Analytic 1988**

Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.


## Mitigations

### M1013 - Application Developer Guidance

Application developers uploading to public code repositories should be careful to avoid publishing sensitive information such as credentials and API keys.

### M1047 - Audit

Scan public code repositories for exposed credentials or other sensitive information before making commits. Ensure that any leaked credentials are removed from the commit history, not just the current latest version of the code.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

_No known malware or tools documented._

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
