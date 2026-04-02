# T1528 - Steal Application Access Token

**Tactic:** Credential Access
**Platforms:** Containers, IaaS, Identity Provider, Office Suite, SaaS
**Reference:** https://attack.mitre.org/techniques/T1528

## Description

Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.

Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and software-as-a-service (SaaS).  Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment.

For example, in Kubernetes environments, processes running inside a container may communicate with the Kubernetes API server using service account tokens. If a container is compromised, an adversary may be able to steal the container’s token and thereby gain access to Kubernetes API commands.  

Similarly, instances within continuous-development / continuous-integration (CI/CD) pipelines will often use API tokens to authenticate to other services for testing and deployment. If these pipelines are compromised, adversaries may be able to steal these tokens and leverage their privileges. 

In Azure, an adversary who compromises a resource with an attached Managed Identity, such as an Azure VM, can request short-lived tokens through the Azure Instance Metadata Service (IMDS). These tokens can then facilitate unauthorized actions or further access to other Azure services, bypassing typical credential-based authentication.

Token theft can also occur through social engineering, in which case user action may be required to grant access. OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow. An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. 
 
Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls. Then, they can send a Spearphishing Link to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through Application Access Token.

Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token. However, in some cases, adversaries can also steal application refresh tokens, allowing them to obtain new access tokens without prompting the user.

## Detection

### Detection Analytics

**Analytic 1423**

Access and retrieval of container service account tokens followed by unauthorized API requests using those tokens to interact with the Kubernetes API server or internal services.

**Analytic 1424**

Token retrieval from instance metadata endpoints such as AWS IMDS or Azure IMDS, followed by API usage using the obtained token from non-standard applications.

**Analytic 1425**

Unusual OAuth app registration followed by user-granted OAuth tokens and subsequent high-privilege resource access via those tokens.

**Analytic 1426**

Use of OAuth tokens by third-party apps to access user mail, calendar, or SharePoint resources where the token was granted recently or via spearphishing.

**Analytic 1427**

Programmatic access to user content via stolen access tokens in platforms like Slack, GitHub, Google Workspace — especially from new IPs, apps, or excessive resource access.


## Mitigations

### M1047 - Audit

Administrators should audit all cloud and container accounts to ensure that they are necessary and that the permissions granted to them are appropriate.  Additionally, administrators should perform an audit of all OAuth applications and the permissions they have been granted to access organizational data. This should be done extensively on all applications in order to establish a baseline, followed up on with periodic audits of new or updated applications. Suspicious applications should be investigated and removed.

### M1021 - Restrict Web-Based Content

Administrators can block end-user consent to OAuth applications, disabling users from authorizing third-party apps through OAuth 2.0 and forcing administrative consent for all requests. They can also block end-user registration of applications by their users, to reduce risk. A Cloud Access Security Broker can also be used to ban applications.

Azure offers a couple of enterprise policy settings in the Azure Management Portal that may help:

"Users -> User settings -> App registrations: Users can register applications" can be set to "no" to prevent users from registering new applications. 
"Enterprise applications -> User settings -> Enterprise applications: Users can consent to apps accessing company data on their behalf" can be set to "no" to prevent users from consenting to allow third-party multi-tenant applications

### M1018 - User Account Management

Enforce role-based access control to limit accounts to the least privileges they require. A Cloud Access Security Broker (CASB) can be used to set usage policies and manage user permissions on cloud applications to prevent access to application access tokens. In Kubernetes applications, set “automountServiceAccountToken: false” in the YAML specification of pods that do not require access to service account tokens.

### M1017 - User Training

Users need to be trained to not authorize third-party applications they don’t recognize. The user should pay particular attention to the redirect URL: if the URL is a misspelled or convoluted sequence of words related to an expected service or SaaS application, the website is likely trying to spoof a legitimate service. Users should also be cautious about the permissions they are granting to apps. For example, offline access and access to read emails should excite higher suspicions because adversaries can utilize SaaS APIs to discover credentials and other sensitive communications.

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S0677 - AADInternals

AADInternals can steal users’ access tokens via phishing emails containing malicious links.

### S0683 - Peirates

Peirates gathers Kubernetes service account tokens using a variety of techniques.

## Threat Groups

_No threat groups documented._

## Campaigns

### C0049 - Leviathan Australian Intrusions

Leviathan abused access to compromised appliances to collect JSON Web Tokens (JWTs), used for creating virtual desktop sessions, during Leviathan Australian Intrusions.
