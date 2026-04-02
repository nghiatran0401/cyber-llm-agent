# T1187 - Forced Authentication

**Tactic:** Credential Access
**Platforms:** Windows
**Reference:** https://attack.mitre.org/techniques/T1187

## Description

Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.

The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.

Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443.

Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary  (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource, it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary-controlled server. With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials.

There are several different ways this can occur. Some specifics from in-the-wild use include:

* A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. Template Injection). The document can include, for example, a request similar to <code>file[:]//[remote address]/Normal.dotm</code> to trigger the SMB request.
* A modified .LNK or .SCF file with the icon filename pointing to an external reference such as <code>\\[remote address]\pic.png</code> that will force the system to load the resource when the icon is rendered to repeatedly gather credentials.

Alternatively, by leveraging the <code>EfsRpcOpenFileRaw</code> function, an adversary can send SMB requests to a remote system's MS-EFSRPC interface and force the victim computer to initiate an authentication procedure and share its authentication details. The Encrypting File System Remote Protocol (EFSRPC) is a protocol used in Windows networks for maintenance and management operations on encrypted data that is stored remotely to be accessed over a network. Utilization of <code>EfsRpcOpenFileRaw</code> function in EFSRPC is used to open an encrypted object on the server for backup or restore. Adversaries can collect this data and abuse it as part of a NTLM relay attack to gain access to remote systems on the same internal network.

## Detection

### Detection Analytics

**Analytic 0065**

Adversary stages a lure that references a remote resource (e.g., LNK/SCF/Office template). When the user opens/renders the file or a shell enumerates icons, the host automatically attempts SMB or WebDAV authentication to the attacker host. The chain is: (1) lure file is created or modified in a user-exposed location → (2) user or system accesses the lure → (3) host makes outbound NTLM (SMB 139/445 or WebDAV over 80/443) to an untrusted destination → (4) repeated attempts from multiple users/hosts or from privileged workstations.


## Mitigations

### M1037 - Filter Network Traffic

Block SMB traffic from exiting an enterprise network with egress filtering or by blocking TCP ports 139, 445 and UDP port 137. Filter or block WebDAV protocol traffic from exiting the network. If access to external resources over SMB and WebDAV is necessary, then traffic should be tightly limited with allowlisting.

### M1027 - Password Policies

Use strong passwords to increase the difficulty of credential hashes from being cracked if they are obtained.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0634 - EnvyScout

EnvyScout can use protocol handlers to coax the operating system to send NTLMv2 authentication responses to attacker-controlled infrastructure.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
