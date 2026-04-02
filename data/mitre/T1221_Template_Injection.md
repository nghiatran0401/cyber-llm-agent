# T1221 - Template Injection

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1221

## Description

Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.

Properties within parts may reference shared public resources accessed via online URLs. For example, template properties may reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.

Adversaries may abuse these templates to initially conceal malicious code to be executed via user documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded. These documents can be delivered via other techniques such as Phishing and/or Taint Shared Content and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. Examples have been seen in the wild where template injection was used to load malicious code containing an exploit.

Adversaries may also modify the <code>*\template</code> control word within an .rtf file to similarly conceal then download malicious code. This legitimate control word value is intended to be a file destination of a template file resource that is retrieved and loaded when an .rtf file is opened. However, adversaries may alter the bytes of an existing .rtf file to insert a template control word field to include a URL resource of a malicious payload.

This technique may also enable Forced Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt.

## Detection

### Detection Analytics

**Analytic 1564**

Detection of Office or document viewer processes (e.g., winword.exe) initiating network connections to remote templates or executing scripts due to manipulated template references (e.g., embedded in .docx, .rtf, or .dotm files), followed by suspicious child process creation (e.g., PowerShell).


## Mitigations

### M1049 - Antivirus/Antimalware

Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.

### M1042 - Disable or Remove Feature or Program

Consider disabling Microsoft Office macros/active content to prevent the execution of malicious payloads in documents, though this setting may not mitigate the Forced Authentication use for this technique.

### M1031 - Network Intrusion Prevention

Network/Host intrusion prevention systems, antivirus, and detonation chambers can be employed to prevent documents from fetching and/or executing malicious payloads.

### M1017 - User Training

Train users to identify social engineering techniques and spearphishing emails that could be used to deliver malicious documents.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0631 - Chaes

Chaes changed the template target of the settings.xml file embedded in the Word document and populated that field with the downloaded URL of the next payload.

### S0670 - WarzoneRAT

WarzoneRAT has been install via template injection through a malicious DLL embedded within a template RTF in a Word document.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0001 - Frankenstein

During Frankenstein, the threat actors used trojanized documents that retrieved remote templates from an adversary-controlled website.

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used DOCX files to retrieve a malicious document template/DOTM file.
