**Cybersecurity Threat Detection Workshop**

*Student Lab Workbook (English)*

|Version|2\.0|
| :- | :- |
|Scenario date|13 January 2026|
|Classification|Training Use Only|

# **Workshop Overview**
This lab set provides hands-on practice across three common banking scenarios: phishing, credential leak triage, and contactless payment fraud (GhostTap / NFC relay). All domains, IPs, and data samples are synthetic and provided strictly for training.
# **Rules of Engagement**
**Do:**

Use only the provided artifacts. Work offline.

Focus on detection, analysis, and defensive recommendations.

Document assumptions and uncertainty. If you are not sure, say so.

**Don't:**

Do not scan, visit, or interact with external infrastructure.

Do not attempt to build or deploy phishing kits or malware.

Do not use real customer data. Keep everything within the lab pack.
# **How You Will Be Graded**
Your instructor will grade based on technical accuracy, analytical reasoning, actionable recommendations, and communication clarity.

Tip: A smaller set of correct, well-explained findings is better than a long list of guesses.
# **What to Submit**
**For each lab, submit:**

\1) Your completed tables (IoCs, mappings, matrices, rules)\.

\2) A short written report or memo (templates included)\.

\3) Any detection logic you propose (in plain English; pseudocode allowed)\.


# **Lab A: Phishing Campaign Analysis**
Scenario: The SOC receives multiple customer reports about a suspicious email claiming to be from "VCB Security". Your job is to extract indicators of compromise (IoCs), map the behavior to MITRE ATT&CK, and produce a short Threat Intelligence Report that security and fraud teams can act on.
## **Provided Artifacts**
\- A1\_phishing\_email\_core.eml

\- A2\_phishing\_email\_variant.eml

\- A3\_benign\_newsletter.eml

\- mail\_gateway\_logs.csv

\- landing\_page\_source\_excerpt.txt

\- web\_server\_access\_core.log

\- web\_server\_access\_extended.log

\- server\_outbound\_http\_core.log

\- dns\_whois\_core.txt
## **Task 1: IoC Extraction (Core)**
Extract IoCs from the core artifacts. Focus on high-confidence, high-impact indicators first. Include where you found each IoC (artifact + line or field).

|Indicator Type|Value|Where Found|Why It Matters|Recommended Control|Confidence (L/M/H)|
| :- | :- | :- | :- | :- | :- |
|||||||
|||||||
|||||||
|||||||
|||||||
|||||||
|||||||
|||||||
|||||||
|||||||
## **Task 2: MITRE ATT&CK Mapping (Core)**
Map the observed behavior to MITRE ATT&CK. Provide evidence for each mapping.

|Tactic|Technique ID|Technique Name|Evidence (artifact + snippet)|
| :- | :- | :- | :- |
|||||
|||||
|||||
|||||
|||||
|||||
|||||
|||||
## **Task 3: Threat Intelligence Report (Core)**
Write a 1-page Threat Intelligence Report using the template below.

Template:

• Report ID / Date / Classification (e.g., TLP)

• Executive Summary (3-5 sentences)

• Technical Analysis (attack chain + infrastructure)

• Threat Actor Assessment (what you can/cannot infer)

• Recommended Actions (specific, prioritized)

• Appendix: IoC table reference
## **Stretch Tasks (Optional)**
\1) Use the extended web logs to identify additional patterns (e\.g\., scanning, repeat victims, timing)\.

\2) Propose 2-3 detection ideas for email gateway and web proxy (plain English is fine)\.

\3) Identify what would be the fastest containment actions in the first 30 minutes\.


# **Lab B: Credential Leak Investigation**
Scenario: A credential dump is discovered, potentially containing bank customer emails and passwords. You must determine impact, classify the risk, propose a response workflow, and draft customer-safe communications.
## **Provided Artifacts**
\- leaked\_credentials\_core.txt

\- leaked\_credentials\_extended.txt

\- customer\_export.csv

\- login\_attempts\_sample.jsonl

\- breach\_posting\_excerpt.txt
## **Task 1: Data Triage & Classification (Core)**
Using leaked\_credentials\_core.txt and customer\_export.csv, answer the questions below. Show your working (counts, matching logic, or small notes).

|Question|Your Answer|Evidence / Notes|
| :- | :- | :- |
||||
||||
||||
||||
||||
||||
||||
||||
## **Task 2: Risk Assessment Matrix (Core)**
Build a simple risk matrix for the affected customer types. Use Impact + Likelihood -> Risk Level.

|Customer Type|Impact (Low/Med/High)|Likelihood (Low/Med/High)|Risk Level|Notes|
| :- | :- | :- | :- | :- |
||||||
||||||
||||||
||||||
||||||
||||||
## **Task 3: Response Workflow (Core)**
Propose a response workflow with priority, owner, and timeline.

|Priority|Action|Responsible Team|Target Timeline|Notes|
| :- | :- | :- | :- | :- |
||||||
||||||
||||||
||||||
||||||
||||||
||||||
||||||
## **Task 4: Customer Notification Draft (Core)**
Draft (a) one short SMS and (b) one email. Keep tone calm and actionable. Do NOT include unverified claims.

SMS draft:

[Write your SMS here...]

Email draft:

Subject: ...

Dear ...

[Write your email here...]
## **Stretch Tasks (Optional)**
\1) Using leaked\_credentials\_extended\.txt, describe what changes in your risk posture (if any)\.

\2) Using login\_attempts\_sample\.jsonl, propose two SIEM detections for credential stuffing / ATO attempts\.

\3) Draft an internal incident ticket summary (one paragraph) for executives\.


# **Lab C: GhostTap / NFC Relay Analysis**
Scenario: Fraud operations detect a burst of contactless transactions that appear geographically impossible. You must analyze the pattern, propose detection rules, suggest mitigations, and produce an investigation checklist.
## **Provided Artifacts**
\- transactions\_core.csv

\- transactions\_extended.csv

\- nfc\_timing\_core.csv

\- authorization\_log\_core.jsonl

\- device\_location\_sample.csv

\- airline\_checkin\_log.csv

\- case\_notes.txt
## **Task 1: Fraud Pattern Analysis (Core)**
Answer the questions below using transactions\_core.csv and supporting artifacts.

|Question|Your Answer|Evidence / Notes|
| :- | :- | :- |
||||
||||
||||
||||
||||
||||
||||
||||
## **Task 2: Detection Rules (Core)**
Propose detection rules that balance fraud reduction and customer experience.

|Rule ID|Logic / Condition|Risk Score (0-100)|Action|False Positive Considerations|
| :- | :- | :- | :- | :- |
||||||
||||||
||||||
||||||
||||||
||||||
||||||
||||||
## **Task 3: Mitigation Strategies (Core)**
Provide mitigation strategies by stakeholder.

|Stakeholder|Mitigation Measure|Difficulty (Easy/Med/Hard)|Notes|
| :- | :- | :- | :- |
|||||
|||||
|||||
|||||
|||||
|||||
## **Task 4: Investigation Checklist (Core)**
List evidence sources and prioritize collection.

|Evidence Type|Source|Priority (Low/Med/High/Critical)|Notes|
| :- | :- | :- | :- |
|||||
|||||
|||||
|||||
|||||
|||||
|||||
|||||
## **Stretch Tasks (Optional)**
\1) Use transactions\_extended\.csv to test false positives and propose threshold tuning\.

\2) Discuss privacy constraints for location-based rules and propose safer alternatives\.

\3) Propose a real-time step-up authentication flow for high-risk NFC events\.


# **Appendix: Data Dictionary (Quick Reference)**
## **Email / Mail Gateway**
\- spf/dkim/dmarc: pass/fail outcomes from the mail gateway.

\- url\_domains: domains extracted from URLs in the message body.
## **Web Logs**
\- Combined log format: client\_ip, timestamp, method, path, status, bytes, referrer, user\_agent.
## **Credential Dumps**
\- Format: email:password\_or\_hash. Hashes may be prefixed (e.g., sha1$...).
## **Payments**
\- entry\_mode: NFC/CHIP indicates contactless vs EMV chip.

\- nfc\_duration\_ms: measured tap time; longer durations can suggest relay latency (not a standalone proof).
