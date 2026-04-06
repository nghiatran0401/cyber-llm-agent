## Demo 1: "Help, is this an active attack?"

### User prompt

```text
I need quick help triaging this:
- lots of failed logins from 185.220.101.45
- then one successful VPN login from the same IP
- PowerShell launched from Word on FIN-LAPTOP-22
- weird outbound traffic from DB-PROD-01

Can you tell me how serious this is, what attack this might be, and what I should do in the next 30 minutes?
```

### Follow-up

```text
Can you rewrite that for my CISO in plain English?
```

---

## Demo 2: Suspected Ransomware

### User prompt

```text
I think we might have ransomware.
One endpoint is renaming lots of files quickly, someone found a ransom note, and EDR shows winword -> cmd -> powershell.

What should I isolate immediately, and what evidence should I preserve before we touch anything?
```

### Follow-up

```text
Give me a 45-minute incident response checklist I can execute right now.
```

---

## Demo 3: Phishing + Account Takeover

### User prompt

```text
I suspect a phishing compromise:
- user opened an invoice attachment
- mailbox forwarding rule was created
- impossible travel login happened
- strange OAuth app was approved

Can you map the likely attack flow and tell me the top containment actions by priority?
```

### Follow-up

```text
Split the actions by team: SOC, IAM, Email, and Endpoint.
```

---

## Demo 4: Cloud Security Incident

### User prompt

```text
Can you help me investigate a possible AWS account compromise?
We saw CreateAccessKey on old IAM users, unusual S3 access spikes, and GuardDuty alerts around credential misuse.

What is the likely attacker objective, and what credentials or access should I revoke first?
```

### Follow-up

```text
Give me a rollback-safe containment plan so we don't break production.
```

---

## Demo 5: Threat Hunting Assistant

### User prompt

```text
I want to run a threat hunt for credential stuffing and internal recon.
We saw repeated failed auth, one successful login, and then suspicious internal scanning.

Can you give me hunt hypotheses and practical queries for auth logs, EDR, DNS, and proxy data?
```

### Follow-up

```text
Turn your recommendations into ticket-ready tasks with acceptance criteria.
```
