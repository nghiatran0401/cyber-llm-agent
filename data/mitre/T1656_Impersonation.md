# T1656 - Impersonation

**Tactic:** Defense Evasion
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1656

## Description

Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf. For example, adversaries may communicate with victims (via Phishing for Information, Phishing, or Internal Spearphishing) while impersonating a known sender such as an executive, colleague, or third-party vendor. Established trust can then be leveraged to accomplish an adversary’s ultimate goals, possibly against multiple victims. 
 
In many cases of business email compromise or email fraud campaigns, adversaries use impersonation to defraud victims -- deceiving them into sending money or divulging information that ultimately enables Financial Theft.

Adversaries will often also use social engineering techniques such as manipulative and persuasive language in email subject lines and body text such as `payment`, `request`, or `urgent` to push the victim to act quickly before malicious activity is detected. These campaigns are often specifically targeted against people who, due to job roles and/or accesses, can carry out the adversary’s goal.   
 
Impersonation is typically preceded by reconnaissance techniques such as Gather Victim Identity Information and Gather Victim Org Information as well as acquiring infrastructure such as email domains (i.e. Domains) to substantiate their false identity.
 
There is the potential for multiple victims in campaigns involving impersonation. For example, an adversary may Compromise Accounts targeting one organization which can then be used to support impersonation against other entities.

## Detection

### Detection Analytics

**Analytic 0792**

Monitor for anomalous email activity originating from Windows-hosted applications (e.g., Outlook) where the sending account name or display name does not match the underlying SMTP address. Detect abnormal volume of outbound messages containing sensitive keywords (e.g., 'payment', 'wire transfer') or anomalous login locations for accounts associated with email sending activity.

**Analytic 0793**

Monitor mail server logs (Postfix, Sendmail, Exim) for anomalous From headers mismatching authenticated SMTP identities. Detect abnormal relay attempts, spoofed envelope-from values, or large-scale outbound campaigns targeting internal users.

**Analytic 0794**

Monitor Mail.app activity or unified logs for anomalous SMTP usage, including mismatches between display name and authenticated AppleID or Exchange credentials. Detect use of third-party mail utilities that attempt to send on behalf of corporate identities.

**Analytic 0795**

Monitor SaaS mail platforms (Google Workspace, M365, Okta-integrated apps) for SendAs/SendOnBehalfOf operations where the delegated permissions are unusual or newly granted. Detect impersonation attempts where adversaries configure rules to auto-forward or auto-reply with impersonated content.

**Analytic 0796**

Monitor Office Suite applications (Outlook, Word mail merge, Excel macros) for abnormal automated message sending, especially when macros or scripts trigger email delivery. Detect patterns of impersonation language (urgent, payment, executive request) combined with anomalous execution of Office macros.


## Mitigations

### M1019 - Threat Intelligence Program

Threat intelligence helps defenders and users be aware of and defend against common lures and active campaigns that have been used for impersonation.

### M1017 - User Training

Train users to be aware of impersonation tricks and how to counter them, for example confirming incoming requests through an independent platform like a phone call or in-person, to reduce risk.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1131 - NPPSPY

NPPSPY creates a network listener using the misspelled label <code>logincontroll</code> recorded to the Registry key <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order</code>.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0027 - C0027

During C0027, Scattered Spider impersonated legitimate IT personnel in phone calls and text messages either to direct victims to a credential harvesting site or getting victims to run commercial remote monitoring and management (RMM) tools.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group impersonated HR hiring personnel through LinkedIn messages and conducted interviews with victims in order to deceive them into downloading malware.

### C0059 - Salesforce Data Exfiltration

During Salesforce Data Exfiltration, threat actors impersonated IT support personnel in voice calls with victims at times claiming to be addressing enterprise-wide connectivity issues.
