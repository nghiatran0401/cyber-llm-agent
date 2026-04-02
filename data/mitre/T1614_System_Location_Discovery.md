# T1614 - System Location Discovery

**Tactic:** Discovery
**Platforms:** IaaS, Linux, Windows, macOS
**Reference:** https://attack.mitre.org/techniques/T1614

## Description

Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings. Windows API functions such as <code>GetLocaleInfoW</code> can also be used to determine the locale of the host. In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance.

Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services.

## Detection

### Detection Analytics

**Analytic 0119**

Unusual process or API usage attempting to query system locale, timezone, or keyboard layout (e.g., calls to GetLocaleInfoW, GetTimeZoneInformation). Detection can be enhanced by correlating with processes not typically associated with system configuration queries, such as unknown binaries or scripts.

**Analytic 0120**

Detection of commands accessing locale, timezone, or language settings such as 'locale', 'timedatectl', or parsing /etc/timezone. Anomalous execution by unusual users or automation scripts should be flagged.

**Analytic 0121**

Detection of system calls or commands accessing system locale (e.g., 'defaults read -g AppleLocale', 'systemsetup -gettimezone'). Correlate with unusual parent processes or execution contexts.

**Analytic 0122**

Detection of queries to instance metadata services (e.g., AWS IMDS, Azure Metadata Service) for availability zone, region, or network geolocation details. Correlation with non-management accounts or non-standard workloads may indicate adversary reconnaissance.


## Mitigations

_No mitigations documented._

## Targeted Assets

_No specific assets identified._

## Malware / Tools That Use This Technique

### S1025 - Amadey

Amadey does not run any tasks or install additional malware if the victim machine is based in Russia.

### S0115 - Crimson

Crimson can identify the geographical location of a victim host.

### S1153 - Cuckoo Stealer

Cuckoo Stealer can determine the geographical location of a victim host by checking the language.

### S1111 - DarkGate

DarkGate queries system locale information during execution. Later versions of DarkGate query <code>GetSystemDefaultLCID</code> for locale information to determine if the malware is executing in Russian-speaking countries.

### S0673 - DarkWatchman

DarkWatchman can identity the OS locale of a compromised host.

### S1138 - Gootloader

Gootloader  can use IP geolocation to determine if the person browsing to a compromised site is within a targeted territory such as the US, Canada, Germany, and South Korea.

### S0632 - GrimAgent

GrimAgent can identify the country code on a compromised host.

### S1249 - HexEval Loader

HexEval Loader has a function where the C2 endpoint can identify the geographical location of a victim host based on request headers, execution environment and runtime conditions.

### S1245 - InvisibleFerret

InvisibleFerret has collected the internal IP address, IP geolocation information of the infected host and sends the data to a C2 server. InvisibleFerret has also leveraged the “pay” module to obtain region name, country, city, zip code, ISP, latitude and longitude using “http://ip-api.com/json”.

### S0013 - PlugX

PlugX has obtained the location of the victim device by leveraging `GetSystemDefaultLCID`.

### S0262 - QuasarRAT

QuasarRAT can determine the country a victim host is located in.

### S1148 - Raccoon Stealer

Raccoon Stealer collects the `Locale Name` of the infected device via `GetUserDefaultLocaleName` to determine whether the string `ru` is included, but in analyzed samples no action is taken if present.

### S0481 - Ragnar Locker

Before executing malicious code, Ragnar Locker checks the Windows API <code>GetLocaleInfoW</code> and doesn't encrypt files if it finds a former Soviet country.

### S1240 - RedLine Stealer

RedLine Stealer has gathered detailed information about victims’ systems, such as IP addresses, and geolocation. RedLine Stealer has also checked the IP from where it was being executed and leveraged an opensource geolocation IP-lookup service.

### S0461 - SDBbot

SDBbot can collected the country code of a compromised machine.

### S1018 - Saint Bot

Saint Bot has conducted system locale checks to see if the compromised host is in Russia, Ukraine, Belarus, Armenia, Kazakhstan, or Moldova.

### S1124 - SocGholish

SocGholish can use IP-based geolocation to limit infections to victims in North America, Europe, and a small number of Asian-Pacific nations.

### S1248 - XORIndex Loader

XORIndex Loader can identify the geographical location of a victim host.

## Threat Groups

_No threat groups documented._

## Campaigns

_No campaigns documented._
