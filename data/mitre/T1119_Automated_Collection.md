# T1119 - Automated Collection

**Tactic:** Collection
**Platforms:** IaaS, Linux, Office Suite, SaaS, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1119

## Description

Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. 

In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data. 

This functionality could also be built into remote access tools. 

This technique may incorporate use of other techniques such as File and Directory Discovery and Lateral Tool Transfer to identify and move files, as well as Cloud Service Dashboard and Cloud Storage Object Discovery to identify resources in cloud environments.

## Detection

### Detection Analytics

**Analytic 0531**

Automated execution of native utilities and scripts to discover, enumerate, and exfiltrate files and clipboard content. Focus is on detecting repeated file access, scripting engine use, and use of command-line utilities commonly leveraged by collection scripts.

**Analytic 0532**

Repeated or automated access to user document directories or clipboard using shell scripts or utilities like xclip/pbpaste. Detectable via auditd syscall logs or osquery file events.

**Analytic 0533**

Use of pbpaste, AppleScript, or third-party automation frameworks (e.g., Automator) to collect clipboard or file content in bursts. Observable via unified logs.

**Analytic 0534**

Suspicious sign-ins to Graph API or sensitive resources using non-browser scripting agents (e.g., Python, PowerShell), often for programmatic access to mailbox or OneDrive content.


## Mitigations

### M1041 - Encrypt Sensitive Information

Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means. Strong passwords should be used on certain encrypted documents that use them to prevent offline cracking through Brute Force techniques.

### M1029 - Remote Data Storage

Encryption and off-system storage of sensitive information may be one way to mitigate collection of files, but may not stop an adversary from acquiring the information if an intrusion persists over a long period of time and the adversary is able to discover and access the data through other means.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0622 - AppleSeed

AppleSeed has automatically collected data from USB drives, keystrokes, and screen images before exfiltration.

### S0438 - Attor

Attor has automatically collected data about the compromised system.

### S0128 - BADNEWS

BADNEWS monitors USB devices and copies files with certain extensions to a predefined directory.

### S0239 - Bankshot

Bankshot recursively generates a list of files within a directory and sends them back to the control server.

### S0244 - Comnie

Comnie executes a batch script to store discovery information in %TEMP%\info.dat and then uploads the temporarily file to the remote C2 server.

### S0538 - Crutch

Crutch can automatically monitor removable drives in a loop and copy interesting files.

### S1111 - DarkGate

DarkGate searches for stored credentials associated with cryptocurrency wallets and notifies the command and control server when identified.

### S0363 - Empire

Empire can automatically gather the username, domain name, machine name, and other information from a compromised system.

### S1044 - FunnyDream

FunnyDream can monitor files for changes and automatically collect them.

### S0597 - GoldFinder

GoldFinder logged and stored information related to the route or hops a packet took from a compromised machine to a hardcoded C2 server, including the target C2 URL, HTTP response/status code, HTTP response headers and values, and data received from the C2 node.

### S0170 - Helminth

A Helminth VBScript receives a batch script to execute a set of commands in a command prompt.

### S0260 - InvisiMole

InvisiMole can sort and collect specific documents as well as generate a list of all files on a newly inserted drive and store them in an encrypted file.

### S0395 - LightNeuron

LightNeuron can be configured to automatically collect files under a specified directory.

### S1101 - LoFiSe

LoFiSe can collect all the files from the working directory every three hours and place them into a password-protected archive for further exfiltration.

### S1213 - Lumma Stealer

Lumma Stealer has automated collection of various information including cryptocurrency wallet details.

### S0443 - MESSAGETAP

MESSAGETAP checks two files, keyword_parm.txt and parm.txt, for instructions on how to target and save data parsed and extracted from SMS message data from the network traffic. If an SMS message contained either a phone number, IMSI number, or keyword that matched the predefined list, it is saved to a CSV file for later theft by the threat actor.

### S0455 - Metamorfo

Metamorfo has automatically collected mouse clicks, continuous screenshots on the machine, and set timers to collect the contents of the clipboard and website browsing.

### S0339 - Micropsia

Micropsia executes an RAR tool to recursively archive files based on a predefined list of file extensions (*.xls, *.xlsx, *.csv, *.odt, *.doc, *.docx, *.ppt, *.pptx, *.pdf, *.mdb, *.accdb, *.accde, *.txt).

### S0699 - Mythic

Mythic supports scripting of file downloads from agents.

### S0198 - NETWIRE

NETWIRE can automatically archive collected data.

### S1131 - NPPSPY

NPPSPY collection is automatically recorded to a specified file on the victim machine.

### S1017 - OutSteel

OutSteel can automatically scan for and collect files with specific extensions.

### S1109 - PACEMAKER

PACEMAKER can enter a loop to read `/proc/` entries every 2 seconds in order to read a target application's memory.

### S1091 - Pacu

Pacu can automatically collect data, such as CloudFormation templates, EC2 user data, AWS Inspector reports, and IAM credential reports.

### S0428 - PoetRAT

PoetRAT used file system monitoring to track modification and enable automatic exfiltration.

### S0378 - PoshC2

PoshC2 contains a module for recursively parsing through files and directories to gather valid credit card numbers.

### S0238 - Proxysvc

Proxysvc automatically collects data about the victim and sends it to the control server.

### S0684 - ROADTools

ROADTools automatically gathers data from Azure AD environments using the Azure Graph API.

### S0148 - RTM

RTM monitors browsing activity and automatically captures screenshots if a victim browses to a URL matching one of a list of strings.

### S1148 - Raccoon Stealer

Raccoon Stealer collects files and directories from victim systems based on configuration data downloaded from command and control servers.

### S0458 - Ramsay

Ramsay can conduct an initial scan for Microsoft Word documents on the local system, removable media, and connected network drives, before tagging and collecting them. It can continue tagging documents to collect with follow up scans.

### S1078 - RotaJakiro

Depending on the Linux distribution, RotaJakiro executes a set of commands to collect device information and sends the collected information to the C2 server.

### S0090 - Rover

Rover automatically collects files from the local system and removable drives based on a predefined list of file extensions on a regular timeframe.

### S0445 - ShimRatReporter

ShimRatReporter gathered information automatically, without instruction from a C2, related to the user and host machine that is compiled into a report and sent to the operators.

### S1183 - StrelaStealer

StrelaStealer attempts to identify and collect mail login data from Thunderbird and Outlook following execution.

### S0491 - StrongPity

StrongPity has a file searcher component that can automatically collect and archive files based on a predefined list of file extensions.

### S0098 - T9000

T9000 searches removable storage devices for files with a pre-defined list of file extensions (e.g. * .doc, *.ppt, *.xls, *.docx, *.pptx, *.xlsx). Any matching files are encrypted and written to a local user directory.

### S0467 - TajMahal

TajMahal has the ability to index and compress files into a send queue for exfiltration.

### S0136 - USBStealer

For all non-removable drives on a victim, USBStealer executes automated collection of certain files for later exfiltration.

### S0257 - VERMIN

VERMIN saves each collected file with the automatically generated format {0:dd-MM-yyyy}.txt .

### S0476 - Valak

Valak can download a module to search for and build a report of harvested credential data.

### S0466 - WindTail

WindTail can identify and add files that possess specific file extensions to an array for archiving.

### S0251 - Zebrocy

Zebrocy scans the system and automatically collects files with the following extensions: .doc, .docx, ,.xls, .xlsx, .pdf, .pptx, .rar, .zip, .jpg, .jpeg, .bmp, .tiff, .kum, .tlg, .sbx, .cr, .hse, .hsf, and .lhz.

### S1043 - ccf32

ccf32 can be used to automatically collect files from a compromised host.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0040 - APT41 DUST

APT41 DUST used tools such as SQLULDR2 and PINEGROVE to gather local system and database information.

### C0046 - ArcaneDoor

ArcaneDoor included collection of packet capture and system configuration information.

### C0001 - Frankenstein

During Frankenstein, the threat actors used Empire to automatically gather the username, domain name, machine name, and other system information.

### C0014 - Operation Wocao

During Operation Wocao, threat actors used a script to collect information about the infected system.

### C0058 - SharePoint ToolShell Exploitation

During SharePoint ToolShell Exploitation, threat actors used a command shell to automatically iterate through web.config files to expose and collect machineKey settings.
