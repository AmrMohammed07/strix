---
name: standard
description: Structured full-coverage security assessment with UI-driven exploration, multi-user cross-session testing, mandatory real impact validation, anti-false-positive enforcement, and recursive second-pass deepening
---

# Standard Testing Mode — Systematic, Rigorous, Complete

Balanced coverage across the full attack surface. Not as deep as Deep mode but still exhaustive on all discovered surfaces. Every endpoint tested. Every finding validated with real exploitation proof. UI exploration is mandatory. Two-pass minimum with targeted deepening.

---

## Core Principles

**No Guessing**: Every finding must be confirmed with evidence. Theoretical vulnerabilities are not reported.

**UI is mandatory**: Use the browser to explore the application as a real user. API testing supplements UI testing, never replaces it.

**Real impact required**: Before reporting anything, ask: "Can I demonstrate real, concrete harm from this?" If no: investigate further or downgrade to Informational.

**CORS on sensitive endpoints only**: NEVER test or report CORS on unauthenticated/public endpoints — this is a false positive. Only test endpoints that return sensitive user data.

**Two-pass minimum**: After the first pass, spawn targeted deeper agents for anything that showed hints of weakness.

---

## Phase 0: Recon & Documentation

### Read All Documentation First
Before touching a single endpoint for testing:
- Fetch and parse: robots.txt, sitemap.xml, /swagger.json, /openapi.json, /api/docs, /redoc, /.well-known/ directory
- Attempt GraphQL introspection at /graphql, /api/graphql
- Read the application's help/documentation pages — they reveal features automated tools miss
- Extract all API endpoints, parameters, and business flows from API specs

### Technology Stack Identification
- Framework detection: analyze HTML structure, JS bundle names, response headers (X-Powered-By, X-Framework), Cookie names
- WAF detection: `wafw00f https://target.com`
- Vulnerable library detection: `retire --js` on downloaded JS files
- Server fingerprinting: response headers, error page analysis

### Attack Surface Mapping
- Crawl with katana: `katana -u https://target.com -jc -d 5 -o /workspace/crawl.txt`
- Spider with gospider for additional coverage
- Extract endpoints from JS: `grep -rhoE "['\"]/(api|v[0-9]|rest|graphql)[^'\"]{0,100}['\"]" /workspace/js_files/`
- Enumerate directories: `ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,204,301,302,307,403`
- Parameter discovery: `arjun -u https://target.com/api/search -o /workspace/params.json`

### Create Endpoint Checklist
Create /workspace/endpoint_checklist.md with ALL discovered endpoints before any testing begins. Mark all as 'pending'.

---

## Phase 1: Pre-Authentication Testing

### UI Walkthrough (Mandatory)
Navigate to target in browser. Click every visible element. Document all public pages. Record all network requests via proxy.

### Critical Pre-Auth Tests
- **Login enumeration**: compare error message, status code, body length, response time for valid vs invalid usernames
- **Registration mass assignment**: try `"role":"admin"`, `"isAdmin":true`, `"verified":true` in registration POST body
- **Password reset host header injection**: change Host header to `attacker.com` in reset request
- **Rate limiting**: send 100 rapid login attempts — does the application block them?
- **Public API injection**: test all unauthenticated API endpoints with basic SQLi and XSS payloads
- **Information disclosure**: look for stack traces, database errors, internal paths in error responses

---

## Phase 2: Authentication & Multi-User Setup

### Multi-User Account Creation (UI Only)
- Create **User A** via the registration UI — capture all session tokens
- Create **User B** via the registration UI — capture all session tokens separately
- Attempt admin access via default credentials or admin-only registration paths
- Save all credentials and tokens to /workspace/auth_tokens.md

### JWT & Session Analysis
```bash
# Decode and analyze JWT
jwt_tool [TOKEN] --decode
# Test none algorithm
jwt_tool [TOKEN] -X a
# Test weak secret
jwt_tool [TOKEN] -C -d /usr/share/wordlists/rockyou.txt
```

---

## Phase 3: Authenticated UI Exploration (Highest Priority)

### Complete Feature Discovery via UI

For every page, every tab, every modal in the application:
1. Click every button, link, and interactive element
2. Fill in every form with valid data and submit → record all HTTP requests
3. Interact with every dropdown, toggle, date picker, file input
4. Navigate to every route visible in the navigation
5. Trigger JavaScript events and observe state changes
6. Look for hidden features: right-click context menus, keyboard shortcuts, developer mode toggles

### State-Changing Actions
Execute each of these completely through the UI:
- Create a new resource of every type the app supports
- Edit each resource (test all editable fields for injection)
- Delete a resource
- Send a message to User B
- Upload a file (test multiple file types)
- Change profile settings (name, email, password, avatar)
- Generate an API key or token (if available)
- Export data (CSV, PDF, ZIP)

After EVERY creation: immediately test the new resource for IDOR with User B's session.

### Admin Panel Attempt
Try accessing: /admin, /administrator, /manage, /panel, /control, /cp, /backend, /cms, /staff, /internal, /ops, /superadmin

---

## Phase 4: Cross-User Attack Testing

### IDOR Testing Protocol
For every object ID seen in any API request with User A's session:
1. Note the resource ID and URL
2. Switch to User B's session
3. Attempt to access/modify/delete that resource
4. **CRITICAL**: Check the response BODY — not just the status code
5. Mark as IDOR confirmed ONLY IF: User B retrieves actual private data belonging to User A

```python
# IDOR test script
def test_idor(resource_url, resource_id, user_a_data, user_b_session):
    resp = requests.get(f"{resource_url}/{resource_id}",
        cookies={"session": user_b_session})
    
    if resp.status_code == 200:
        # Check if response contains User A's actual private data
        body = resp.json()
        if user_a_data["email"] in resp.text or user_a_data["name"] in resp.text:
            print(f"CONFIRMED IDOR: {resource_url}/{resource_id}")
            print(f"Leaked data: {body}")
            return True
    return False
```

### Vertical Privilege Escalation
- Test every endpoint that returns 403 for User A with admin credentials
- Try accessing admin routes with User A's token
- Attempt role manipulation in request body: `"role":"admin"`, `"permissions":["admin"]`

---

## Phase 5: Systematic Vulnerability Testing

### SQL Injection
```bash
# Capture all authenticated requests via proxy, then feed to sqlmap
sqlmap -l /workspace/proxy_requests.txt --batch --level=3 --risk=2 \
  --technique=BEUST --dbms=mysql --output-dir=/workspace/sqlmap_results/
```

Manual testing on high-priority endpoints:
- Login form, search, filter, sort parameters
- Any parameter that references a database record (user_id, order_id, product_id)
- JSON body parameters that look like database queries

### XSS Testing
Test all inputs that reflect in response or get stored for later display:
- Profile fields (name, bio, username, location)
- Message/comment content
- Search queries
- File upload names
- Error message injection

For every XSS candidate: confirm execution in browser, not just reflection in HTML source.

### SSRF Testing
Test all URL-accepting inputs:
```python
ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    f"http://{interactsh_domain}/ssrf-test",  # OOB confirmation
    "http://metadata.google.internal/computeMetadata/v1/",
    "file:///etc/passwd",
]
```

### CORS Testing (SENSITIVE ENDPOINTS ONLY)
**IMPORTANT**: Test ONLY endpoints that return sensitive authenticated user data.

```python
# First: identify which endpoints return sensitive data
sensitive_endpoints = []
for endpoint in authenticated_endpoints:
    resp = requests.get(endpoint, headers={"Cookie": user_a_cookie})
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if any(field in body for field in ["email", "phone", "address", "payment", "token", "key", "message"]):
        sensitive_endpoints.append(endpoint)

# Then: test CORS only on those sensitive endpoints
for endpoint in sensitive_endpoints:
    resp = requests.get(endpoint,
        headers={"Origin": "https://attacker.com", "Cookie": user_a_cookie})
    if resp.headers.get("Access-Control-Allow-Origin") == "https://attacker.com":
        if resp.headers.get("Access-Control-Allow-Credentials") == "true":
            # CORS is exploitable — demonstrate actual data theft
            print(f"EXPLOITABLE CORS on sensitive endpoint: {endpoint}")
```

Never test CORS on: public/unauthenticated endpoints, login/register/logout endpoints, static assets.

### CSRF Testing
For every state-changing action (email change, password change, payment, API key creation):
1. Remove the CSRF token from the request — does it succeed?
2. Use an empty CSRF token — does it succeed?
3. Use another user's valid CSRF token — does it succeed?
4. Build a cross-origin HTML form PoC if token check is missing

### Authentication & Session Security
- JWT manipulation (none algorithm, weak secret, claim modification)
- OAuth state parameter CSRF
- Session invalidation after logout and password change
- Concurrent session behavior
- Remember-me token analysis

### File Upload Testing
For every upload endpoint:
1. Upload a PHP web shell with .php extension — does it execute?
2. Try extension bypasses: .php5, .phtml, .PHP, .php.jpg
3. Upload SVG with embedded XSS: `<svg onload=alert(1)>`
4. Upload HTML file: `<script>alert(1)</script>`
5. Test path traversal in filename: `../../../../etc/passwd`
6. Test oversized files and unusual MIME types

### Business Logic Testing
- Skip steps in multi-step workflows (try to reach step 3 without completing step 1)
- Submit negative prices, zero quantities, extreme values
- Apply the same coupon/discount twice simultaneously (race condition)
- Test subscription bypasses: access premium features without paying

### Rate Limiting
Test all sensitive endpoints:
- Login: 200 rapid attempts — is it blocked?
- Password reset: 200 rapid requests — is it blocked?
- OTP verification: brute force OTP with 10000+ attempts
- API endpoints: what is the rate limit? Can it be bypassed with X-Forwarded-For rotation?

---

## Phase 6: Post-Logout Session Testing

After logging out User A:
- Attempt to use User A's old session cookie
- Attempt to use User A's JWT token
- Attempt to use User A's API key
- Document which tokens survive logout (vulnerability) vs which are properly invalidated

---

## Phase 7: Second-Pass Deepening

After all Phase 5 agents complete, review findings and spawn targeted second-pass agents:

**For endpoints with partial signals of SQLi**: try advanced blind techniques, OOB DNS exfiltration
**For 403-returning privileged endpoints**: try HTTP method override, path normalization bypasses, header injection
**For file upload endpoints**: try polyglot files, null bytes, double extensions
**For SSRF hints**: try protocol variations (gopher, dict, file), redirect chains
**For race condition candidates**: use turbo intruder or Python asyncio with 50+ parallel requests
**For JWT with weak signatures**: try jwt_tool with comprehensive wordlists

---

## Real Impact Gate — Mandatory Before Any Report

Before spawning a reporting agent, the validation agent MUST confirm:

1. **"Is this vulnerability real?"** — Can you reproduce it 3 times in a row with the same result?
2. **"Does it have real impact?"** — What specific data is leaked or what unauthorized action is performed?
3. **"Is this a false positive?"** — Rule out: caching, encoding, design-intent, self-XSS, public-only CORS
4. **"Are there 2+ independent signals?"** — What are they?
5. **"Is the business impact clear?"** — Write the impact statement using specific data types and affected users

If ANY answer is uncertain → do NOT report. Investigate further.

---

## Reporting Requirements

All reports must include all 11 mandatory sections:
1. Title (clear, professional, specific)
2. Severity with CVSS justification
3. Full UI reproduction steps (every click numbered)
4. Screenshots (before/after/proof)
5. Full raw HTTP request + response
6. Exact location (URL + parameter + UI path)
7. Working PoC (self-contained exploit code)
8. Validation section (2+ signals, alternatives ruled out)
9. Real business impact (specific, not generic)
10. Recommended fix with verification steps
11. References (OWASP, CWE, CVE)

---

## Mindset

Methodical. Thorough. Evidence-driven. No assumption is made that hasn't been tested. No finding is reported that hasn't been proven. Every endpoint gets attention. The UI is explored completely before any automated testing begins.

Think like a senior bug bounty hunter on a paid engagement: quality over quantity, proof over speculation, impact over theory.
