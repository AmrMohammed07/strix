---
name: session-management
description: Session management vulnerabilities — fixation, token prediction, concurrent session abuse, and logout bypass
---

# Session Management

Session management vulnerabilities allow attackers to impersonate authenticated users by stealing, fixing, predicting, or reusing session tokens. Session security is foundational — a weak session means all other security controls can be bypassed.

## Attack Surface

**Session Token Locations**
- HTTP cookies (`Set-Cookie: session=TOKEN`)
- URL parameters (`?session=TOKEN`, `?token=TOKEN`, `?PHPSESSID=TOKEN`)
- HTTP headers (`Authorization: Bearer TOKEN`, `X-Auth-Token: TOKEN`)
- Hidden form fields, local/sessionStorage
- JWT in various locations

**Vulnerable Areas**
- Login flow (token generation and issuance)
- Logout flow (token invalidation)
- Password change / account recovery (old sessions)
- Role changes (privilege escalation without re-auth)
- Concurrent sessions (multiple active sessions)
- Token rotation frequency

## Key Vulnerabilities

### Session Fixation

Attacker sets victim's session ID before authentication:

```
1. Attacker visits: GET /login → Set-Cookie: PHPSESSID=ATTACKER_CHOSEN_ID
2. Attacker sends victim a link with their session ID:
   https://target.com/login?PHPSESSID=ATTACKER_CHOSEN_ID
3. Victim logs in using the attacker's session ID
4. Session is now authenticated with attacker's known ID
5. Attacker uses the same session ID → accesses victim's account

# Test: Set-Cookie: session=FIXED_VALUE before login
# After login, check if session ID changed (it should)
# If session ID unchanged → session fixation
```

**Session ID in URL**
```
# If session in URL, test fixation via:
https://target.com/login?session=FIXED_VALUE
# Click login → check if new session issued
```

### Weak Token Entropy

```python
# Predictable session tokens:
# Sequential: session1, session2, session3
# Timestamp: 1620000000, 1620000001
# Low entropy: 4-char hex = 65536 possibilities
# Base64-encoded: admin_1234 → YWRtaW5fMTIzNA==

# Test entropy:
# Collect 50+ tokens, analyze patterns
# Base64 decode tokens
# Check for time-based patterns
# Analyze token length (< 128 bits entropy = weak)

import math
tokens = ["COLLECTED_TOKENS"]
# Calculate entropy per token
```

### Insufficient Token Invalidation After Logout

```
1. Log in → record session token
2. Log out
3. Replay old session token
4. If still authenticated → session not invalidated on logout

# Test with:
GET /api/profile
Cookie: session=OLD_TOKEN
# After logout → should return 401, not user data
```

### Insufficient Invalidation After Password Change

```
1. Login session A = TOKEN_A
2. Open second session B = TOKEN_B
3. In session A: change password
4. Test session B: should be invalidated
5. If session B still works → old sessions survive password change
# This enables: attacker who had old token stays logged in after victim changes password
```

**Same test applies to email change** — verify old sessions are invalidated after an
email change, not just a password change. Email change is a security-relevant action
(it can redirect account recovery to the attacker) and frequently skips session
invalidation. Run the identical two-session test: change the email in session A, then
confirm session B is dead.

### Session Not Invalidated After Role Change

```
# If user is demoted from admin → session should lose admin privileges immediately
# Test: capture admin session token, remove admin role via another session
# Replay old admin token → should return 403
```

### Concurrent Session Abuse

```
# Test if multiple simultaneous sessions allowed
# If no concurrent session limit, attacker who obtains session token can stay active
# Check: does new login invalidate old sessions?
# Does the app enforce session limits?
```

### Cookie Attribute Issues

```
# Missing Secure flag → session cookie sent over HTTP
# Missing HttpOnly → document.cookie readable by XSS
# Missing SameSite → CSRF possible to use session

# Domain scope too broad:
Set-Cookie: session=TOKEN; Domain=.target.com
# Any subdomain can read this cookie → subdomain takeover → cookie theft

# Path scope too broad:
Set-Cookie: session=TOKEN; Path=/
# Third-party apps at subdirectories can access
```

### Session Timeout Issues

```
# No absolute timeout:
# Session never expires → stolen tokens valid forever

# No idle timeout:
# Inactive session valid indefinitely

# Test: capture session token, wait 24h, replay
# Session should expire after reasonable idle time

# Check "remember me" functionality:
# Persistent tokens should have longer expiry than session tokens
# Test if remember-me token invalidated on logout
```

### JWT-Specific Issues

```
# alg: none — covered in jwt.md
# Short expiry not enforced → old JWT tokens work
# Missing jti (JWT ID) → replay attacks
# Sensitive data in payload → readable without secret
# Symmetric vs asymmetric confusion
```

### Token Storage Location — Determine and Record First
Before testing anything else, determine and record WHERE the session/auth token is
stored — this dictates which downstream attack vectors even apply:
- **Cookie** — record the flags: `HttpOnly` (blocks `document.cookie` theft via XSS),
  `Secure` (blocks plaintext-HTTP leakage), `SameSite` (CSRF exposure). Inspect via
  DevTools → Application → Cookies or the `Set-Cookie` response headers.
- **localStorage / sessionStorage** — readable by ANY same-origin JavaScript, so any
  XSS = token theft (no `HttpOnly` protection possible). Inspect via DevTools →
  Application → Local/Session Storage.
Note it explicitly in your findings: a token in localStorage makes XSS→ATO trivial;
a cookie without `HttpOnly` is equivalent; an `HttpOnly` cookie shifts the attack
toward CSRF/fixation instead. The storage choice changes the whole threat model.

## Testing Methodology

1. **Token collection** — Collect 100+ session tokens, analyze entropy and patterns
2. **Fixation test** — Visit login page, note session ID, log in, check if session ID changed
3. **Logout test** — Log out, replay old session token, verify invalidation
4. **Password change test** — Change password, test if other sessions invalidated
5. **Cookie flags** — Inspect all Set-Cookie headers for Secure/HttpOnly/SameSite
6. **Domain scope** — Check if cookie domain is too broad (e.g., `.target.com`)
7. **Timeout test** — Wait for idle timeout, replay token
8. **Concurrent sessions** — Login from two browsers, test if both active simultaneously

## Bypass Techniques

**Session Token Theft Vectors**
```
# XSS → document.cookie exfiltration
# Network sniffing (no HTTPS, no Secure flag)
# Log injection → tokens in logs → log exposure
# Referer header leakage (token in URL)
# Browser history (token in URL)
# Cross-subdomain cookie theft via XSS on subdomain
```

**Forced Session Expiry Bypass**
```
# Keep session alive with periodic requests
# Modify token timestamp component to extend validity
# Use refresh token to get new access token after expiry
```

## Validation

1. For fixation: show same session ID before and after login with different user
2. For logout bypass: show 200 response with user data using old session after logout
3. For weak entropy: show two sequential/patterned tokens proving predictability
4. For cookie flags: show cookie accessible via `document.cookie` (HttpOnly missing)

## False Positives

- Session ID rotation implemented correctly on login
- Proper invalidation on logout verified (401 returned)
- Tokens generated with cryptographically secure PRNG
- `HttpOnly` set but XSS still possible (flag doesn't prevent all abuse)

## Impact

- Session hijacking → full account takeover
- Session fixation → ATO with attacker-controlled session
- Persistent access after logout → ongoing unauthorized access
- Cookie theft via subdomain XSS → access to main application

## Pro Tips

1. Session fixation is common in PHP apps using `PHPSESSID` in URL parameters
2. Always test logout → replay — it's a quick win often missed in code reviews
3. `SameSite=Lax` (default in Chrome) doesn't protect POST requests on initial navigation
4. JWT tokens in localStorage are readable by any same-origin JS — prefer HttpOnly cookies
5. Refresh token leakage is worse than access token leakage (longer-lived)
6. Password change without invalidating all sessions = automatic ATO continuation
7. Check `/api/auth/logout` vs `/logout` — different endpoints may have different logout logic
8. `regenerate_id()` must be called on privilege level change, not just login

## Summary

Session management is the foundation of authentication. Test token entropy, fixation, logout invalidation, and cookie flags systematically. A single weakness — a predictable token or surviving session after logout — gives attackers full account access without needing credentials.


## Additional Techniques — ported from WebSkills (session-fixation-test)

Deepens the Session Fixation section above. The one question: *does the server bind a session to a user without first issuing a brand-new session identifier?*

### The decisive test: old-value survival (not "did the cookie change")
Many apps set a new cookie on login yet never invalidate the old server-side record. Always **replay the pre-auth value in Repeater** after login — authenticated response = the old SID is still alive = vulnerable. Disable Burp's Cookie Jar for this test (its silent auto-update can mask or fake the bug). Screenshot three states: pre-auth value, post-auth value (unchanged), and old-value replay returning authenticated content.

### Test at every privilege boundary (not just form login)
Rotation is frequently done on plain login but skipped on:
- **MFA / 2FA step-up** — if the SID is fixed *before* the second factor and unchanged after, you've **bypassed MFA**; report it as such.
- **OAuth / SSO callback** — form-login may rotate while `/callback` reuses the pre-auth app session; diff the cookie across the IdP round-trip specifically.
- **"Remember me" / persistent login** — a long-lived token minted from a fixed pre-auth SID widens the window dramatically.
- **Registration auto-login, role/tenant/org switch, "confirm password to continue" re-auth, invite acceptance.**

### Remote fixation primitives (how the attacker plants the SID)
- **URL / path acceptance:** `?Set-Cookie=SID` or `;jsessionid=SID` written into a cookie — classic, high-impact.
- **CRLF → Set-Cookie injection:** an unsanitized reflected header lets you smuggle `%0d%0aSet-Cookie:%20SESSION=ATTACKER_SID` (pairs with `crlf_injection.md`).
- **Subdomain cookie scoping:** a foothold on `*.target.com` sets `Domain=.target.com; SESSION=...` that the apex app then upgrades on login.
- **Header injection:** `Host` / `X-Forwarded-Host` reflected into `Set-Cookie` Domain/Path.
- **Meta/HTML injection:** `<meta http-equiv="Set-Cookie" ...>` on legacy parsers.
- **XSS-assisted:** `document.cookie="SESSION=ATTACKER_SID; path=/"` turns a low-impact XSS into clean ATO.

### Rotation edge cases to probe
- **Partial rotation:** auth cookie rotates but a secondary session/identity cookie stays fixed and is sufficient to ride the session.
- **Multi-cookie sessions** (session + signature): both must rotate.
- **Rotate-on-first-write, not on auth:** verify rotation is actually tied to the privilege change (use old-value replay, not the immediate `Set-Cookie`).

### Fixation-specific false positives
- One browser profile = contaminated cookie jar → always use two isolated contexts.
- A CSRF/analytics cookie stayed constant but the *real* auth cookie rotated — identify the actual authorizing cookie first.
- Stateless/JWT "session" cookie *is* the identity and changes claims on login — sameness of a non-session cookie is irrelevant.
- New cookie issued **and** the old value is truly dead on replay = correct behaviour, not a bug.
