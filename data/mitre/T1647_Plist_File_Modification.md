# T1647 - Plist File Modification

**Tactic:** Defense Evasion
**Platforms:** macOS
**Reference:** https://attack.mitre.org/techniques/T1647

## Description

Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the <code>info.plist</code> file, to store properties and configuration settings that inform the operating system how to handle the application at runtime. Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD. Plist files can be saved in text or binary format. 

Adversaries can modify key-value pairs in plist files to influence system behaviors, such as hiding the execution of an application (i.e. Hidden Window) or running additional commands for persistence (ex: Launch Agent/Launch Daemon or Re-opened Applications).

For example, adversaries can add a malicious application path to the `~/Library/Preferences/com.apple.dock.plist` file, which controls apps that appear in the Dock. Adversaries can also modify the <code>LSUIElement</code> key in an application’s <code>info.plist</code> file  to run the app in the background. Adversaries can also insert key-value pairs to insert environment variables, such as <code>LSEnvironment</code>, to enable persistence via Dynamic Linker Hijacking.

## Detection

### Detection Analytics

**Analytic 0306**

Monitor for unexpected modifications of plist files in persistence or configuration directories (e.g., ~/Library/LaunchAgents, ~/Library/Preferences, /Library/LaunchDaemons). Detect when modifications are followed by execution of new or unexpected binaries. Track use of utilities such as defaults, plutil, or text editors making changes to Info.plist files. Correlate file modifications with subsequent process launches or service starts that reference the altered plist.


## Mitigations

### M1013 - Application Developer Guidance

Ensure applications are using Apple's developer guidance which enables hardened runtime.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1153 - Cuckoo Stealer

Cuckoo Stealer can create and populate property list (plist) files to enable execution.

### S0658 - XCSSET

In older versions, XCSSET uses the <code>plutil</code> command to modify the <code>LSUIElement</code>, <code>DFBundleDisplayName</code>, and <code>CFBundleIdentifier</code> keys in the <code>/Contents/Info.plist</code> file to change how XCSSET is visible on the system. In later versions, XCSSET leverages a third-party notarized `dockutil` tool to modify the `.plist` file responsible for presenting applications to the user in the Dock and LaunchPad to point to a malicious application.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
