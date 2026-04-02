# T1657 - Financial Theft

**Tactic:** Impact
**Platforms:** Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1657

## Description

Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware, business email compromise (BEC) and fraud, "pig butchering," bank hacking, and exploiting cryptocurrency networks. 

Adversaries may Compromise Accounts to conduct unauthorized transfers of funds. In the case of business email compromise or email fraud, an adversary may utilize Impersonation of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary. This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft.

Extortion by ransomware may occur, for example, when an adversary demands payment from a victim after Data Encrypted for Impact and Exfiltration of data, followed by threatening to leak sensitive data to the public unless payment is made to the adversary. Adversaries may use dedicated leak sites to distribute victim data.

Due to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as Data Destruction and business disruption.

## Detection

### Detection Analytics

**Analytic 1361**

Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard data exfiltration tied to cryptocurrency wallet addresses.

**Analytic 1362**

Monitor server and endpoint logs for unusual outbound network connections to cryptocurrency nodes, unauthorized scripts accessing financial systems, or automation targeting payment file formats. Detect curl/wget activity aimed at exfiltrating transaction data or credentials from financial apps.

**Analytic 1363**

Monitor unified logs for access to payment applications, browser plug-ins, or Apple Pay services from non-standard processes. Detect anomalous use of Automator scripts or keychain extraction targeting financial account credentials.

**Analytic 1364**

Monitor SaaS financial systems (e.g., QuickBooks, Workday, SAP S/4HANA cloud) for unauthorized access, rule changes, or mass export of financial data. Detect anomalous transfers initiated via SaaS APIs or new MFA-disabled logins targeting finance apps.

**Analytic 1365**

Monitor email and document management systems for fraudulent invoices, impersonation of vendors, or BEC-style payment redirections. Detect abnormal editing of invoice templates, or emails containing known fraud language combined with attachment delivery.


## Mitigations

### M1018 - User Account Management

Limit access/authority to execute sensitive transactions, and switch to systems and procedures designed to authenticate/approve payments and purchase requests outside of insecure communication lines such as email.

### M1017 - User Training

Train and encourage users to identify social engineering techniques used to enable financial theft. Also consider training users on procedures to prevent and respond to swatting and doxing, acts increasingly deployed by financially motivated groups to further coerce victims into satisfying ransom/extortion demands.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1246 - BeaverTail

BeaverTail has searched the victim device for browser extensions commonly associated with cryptocurrency wallets.

### S1111 - DarkGate

DarkGate can deploy payloads capable of capturing credentials related to cryptocurrency wallets.

### S1247 - Embargo

Embargo has been leveraged in double-extortion ransomware, exfiltrating files then encrypting them, to prompt victims to pay a ransom.

### S1245 - InvisibleFerret

InvisibleFerret has searched the victim device credentials and files commonly associated with cryptocurrency wallets.

### S1240 - RedLine Stealer

RedLine Stealer has collected data from cryptocurrency wallets and harvested credit cards details from browsers.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors demanded ransom payments to unencrypt filesystems and to refrain from publishing sensitive data exfiltrated from victim networks.
