# OAuth 2.0 / SSO Vulnerabilities

## Overview
OAuth 2.0 and Single Sign-On (SSO) implementation flaws that lead to account takeover, authentication bypass, and privilege escalation.

## OAuth Flow Overview
```
Authorization Code Flow:
1. Client → /authorize?client_id=X&redirect_uri=Y&state=Z&scope=S
2. User authenticates at provider
3. Provider → redirect_uri?code=ABC&state=Z
4. Client → /token (code=ABC, client_secret)
5. Provider returns access_token
```

## Redirect URI Attacks
```
# Open redirect in redirect_uri
redirect_uri=https://attacker.com
redirect_uri=https://target.com@attacker.com
redirect_uri=https://attacker.com/target.com
redirect_uri=https://target.com.attacker.com

# Path traversal in redirect_uri
redirect_uri=https://target.com/callback/../evil

# Wildcard abuse (if allowed)
redirect_uri=https://sub.target.com  (if *.target.com allowed)

# URL fragment trick
redirect_uri=https://target.com/page#

# Localhost bypass
redirect_uri=http://localhost/callback

# Test with unregistered URIs — some providers don't validate strictly
```

## State Parameter Attacks (CSRF on OAuth)
```
# Missing state parameter → CSRF possible
# Predictable state → CSRF possible
# State not validated → CSRF possible

# Attack: craft link with attacker-controlled code, victim clicks
# → victim's account linked to attacker's OAuth account
https://target.com/auth/callback?code=ATTACKER_CODE&state=VICTIM_STATE
```

## Authorization Code Attacks
```
# Code reuse: try replaying authorization code
# Code leakage via Referer header
# Code in browser history/logs

# Steal code via redirect_uri open redirect:
/authorize?...&redirect_uri=https://attacker.com%2Fcallback%23

# PKCE bypass (if PKCE not enforced)
```

## Token Attacks
```
# Access token in URL (logged in server logs, Referer)
# Bearer token leak in JS files
# Token not expiring (test old tokens)
# Insufficient scope validation

# Token substitution: use token from app A in app B
# If same OAuth provider with multiple clients

# JWT access tokens: test algorithm confusion, weak signing
```

## SSO-Specific Attacks

### SAML Attacks
```
# XML signature wrapping (XSW)
# Inject unsigned assertion alongside signed one
# Comment injection in NameID: admin<!---->@target.com
# XML external entity in SAML response

# SAML response replay
# Missing InResponseTo validation → replay old responses

# Recipient validation bypass
# NotOnOrAfter not validated
```

### OpenID Connect
```
# nonce not validated → replay attacks
# ID token not validated (signature, iss, aud)
# Implicit flow token leakage via fragment

# Email as identifier: register attacker@target.com with victim email
# If provider trusts email without verification
```

## Account Linking Attacks
```
# Link attacker account to victim via CSRF on linking endpoint
# Pre-account takeover: register with victim email before they sign up
# OAuth account merge without verification

# Test: can you link an OAuth account to existing account without re-auth?
# Test: can another user's OAuth account be linked via CSRF?
```

## Scope Escalation
```
# Request more scopes than originally granted
# scope=read → scope=read+write+admin
# Increment scope in subsequent requests
# Check if scope is validated on token use vs token issuance
```

## Provider Misconfiguration
```
# Check /.well-known/openid-configuration for endpoints
# Check supported grant types (implicit flow = dangerous)
# Dynamic client registration open to public
# Missing PKCE requirement for public clients
```

## Testing Methodology
1. Map OAuth/SSO flow completely
2. Test redirect_uri validation (try variations)
3. Check state parameter presence and validation
4. Test authorization code reuse
5. Inspect tokens (JWT decode, scope, expiry)
6. Test CSRF on account linking
7. Try account pre-takeover
8. Check for token leakage in logs/headers/JS
9. Test SAML if used (XSW, replay)

## Tools
- Burp Suite OAuth Scanner
- `jwt_tool` for JWT analysis
- SAML Raider (Burp extension)
- Manual proxy inspection


## Additional Techniques — ported from WebSkills (oauth-misconfigurations-testing)

Most OAuth ATOs come from redirect_uri validation gaps, missing/static state, cross-app token reuse, and custom SSO trusting unverified emails. The overview above is the baseline; these are the specific request-level moves.

### Identity / scope tampering (steal or elevate the account)
- **`hd=` tampering** — on "Connect with Google", change `hd=company.com` → `hd=gmail.com` to link a personal email where a corporate one is expected.
- **Remove `email` from `scope`** — drop `email` from the scope on signup/login; some providers then let you set/link any email → ATO.
- **Inject `admin@company.com` in the scope/callback body** — `...&email=admin@company.com&access_token=***` to inherit an admin identity.
- **IDOR via `id=`** — change the `id` param in the connect/callback POST to another account's id.
- **Cross-app access-token reuse (Facebook/Google login):** create your own app with the same provider, generate a token, and swap it into the target's `auth_token`/`access_token` at login. If the target doesn't verify the token was issued *for its* client → ATO. Same root cause as **nOAuth** and the Salt "Oh-Auth" token-reuse class.
- **OAuth account without email** — register at the provider with a phone number only, use it to register on target, then add the victim's email in settings.

### Token / code leak channels
- **`.json` / `.xml` extension** — request `/oauth/Connect.json`; the token may be reflected in the response body.
- **`response_mode` tricks** — flip `query`→`fragment` (code lands after `#`, leaks via Referer) or `form_post` (auto-POST form whose `code`/`state` an XSS on the auth server can read).
- **Referer / browser-history leakage** — check whether `code`+`state` survive in the `Referer` when the user navigates onward.
- **postMessage theft** — a whitelisted subdomain that does `postMessage(location.href.split("#")[1], "*")` with no `X-Frame-Options` lets an iframe steal the token.

### redirect_uri validation bypass (whitelist evasion)
Beyond the basics, run the full pattern list against the `redirect_uri`:
```
https://me.com\@company.com          https://company.com\@me.com
https://me.com/.company.com          me.com%ff@company.com%2F
me.com%252f@company.com%2F           //me.com%0a%2523.company.com
me.com://company.com                 company.com.evil.com
evil.com#company.com                 evil.com?company.com
/%09/me.com     me.com%09company.com     /\me.com
company.com%252f@me.com%2fpath%2f%3   //me.com:%252525252f@company.com
```
Also try **IDN homograph** (`www.cṍmpany.com`), **black/invisible chars** (`%00`–`%FF`, e.g. `me.com%5bcompany.com`), **path traversal → open redirect** (`.../..%2f..%2fredirect_uri=https://me.com`), and **XSS/SSTI in `redirect_uri`/`scope`/`code`** (`data:` URI, `${T(java.lang.Runtime)...}`, reflected `code=,%2520alert(123))%253B//`).

### CSRF / forced linking
- **Missing or static `state`** → login CSRF and **forced profile linking**: capture the connect URL (with `redirect_uri`), drop it, send it to the victim (or iframe it); their browser completes the flow and links *your* social profile to *their* account.
- **`prompt=none`** minimises interaction for silent token reuse / automation.
- **Change request method** (GET/POST/HEAD/PUT) on the connect endpoint to find inconsistent routing/validation.

### Secrets & race
- **`client_secret` disclosure / brute-force at `/token`** — fuzz the `client_secret` param on the code-exchange request; a hit lets you mint tokens for any user.
- **Race conditions** on the callback / code-exchange (Turbo Intruder) — codes accepted more than once, or OTP checks bypassed.

### Custom SSO org-switch ATO (Okta / Auth0 — no email verification)
- **Okta org-switch:** victim ∈ VictimOrg on target.com. Attacker creates AttackerOrg, invites victim's email, wires their **own** Okta with a user `victim@gmail.com` (no verification), logs into target.com as the victim, then **switches org** to VictimOrg → accesses victim data.
- **Auth0 0/1-click account linking:** victim signs up via "Log in with Google"; attacker registers the *same email* with a password → if pre-linked, logged in (0-click), or logs in after victim clicks the confirm link (1-click).
- **Auth0 self-registration on login-only targets:** intercept the login request, change endpoint `/co/authenticate` → `/dbconnections/signup`, send `email`/`password`/`connection`; a `200` with `"email_verified":false` means you just created an account on a "login-only" app.
- **Auth0 Unicode email-normalization ATO:** register `victim@domain.com`, then register the dotless-i variant `vıctim@domain.com`; if the Get-User script doesn't normalize, both map to one user and you overwrite the credential.
