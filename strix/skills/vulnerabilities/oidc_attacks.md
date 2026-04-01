---
name: oidc-attacks
description: OpenID Connect attack techniques — nonce bypass, token leakage, provider confusion, and hybrid flow abuse
---

# OpenID Connect (OIDC) Attacks

OpenID Connect extends OAuth 2.0 with identity — adding ID tokens (JWTs), UserInfo endpoints, and discovery documents. Its complexity creates attack surface beyond standard OAuth: nonce bypass, ID token confusion, provider switching, and hybrid flow token leakage.

## OIDC Flow Overview

```
1. Client sends Authorization Request to IdP
   → includes: client_id, redirect_uri, scope (openid...), state, nonce, response_type

2. IdP authenticates user, returns Authorization Response
   → includes: code (auth code flow) OR tokens (implicit/hybrid)

3. Client exchanges code for tokens at /token endpoint
   → receives: id_token (JWT), access_token, refresh_token

4. Client validates id_token (signature, iss, aud, nonce, exp)

5. Optional: Client calls /userinfo with access_token
```

## Key Vulnerabilities

### Nonce Bypass

Nonce prevents replay of ID tokens. Missing/weak nonce validation = token replay attack:

```
# 1. Obtain a valid ID token from your own session
# 2. Replay it in a different session or for a different user

# Test: log in, capture id_token, log out, replay id_token
# If accepted without nonce validation → replay attack

# Nonce in id_token payload should match nonce sent in auth request
# Some apps skip nonce validation entirely
```

### State Parameter Missing/Bypass (CSRF)

```
# state not validated → CSRF on OAuth/OIDC login
# 1. Attacker initiates auth flow but doesn't complete it
# 2. Captures the ?code=X&state=Y in their callback URL
# 3. Tricks victim into visiting that callback URL
# 4. Victim's browser exchanges attacker's code → victim logged into attacker's account

# Test: initiate login, get code, inject that code into victim's browser
# state=: try empty state, common values ("abc", "state", "1"), remove it entirely
```

### ID Token Audience Bypass

```
# id_token contains aud (audience) claim
# If RP doesn't validate aud, any id_token from the same IdP works for any app

# Attacker registers their own app with same IdP
# Gets id_token from IdP with their app as aud
# Submits to target app → target app should reject (wrong aud) but may not

# Also: aud as array — some parsers use first/last
{"aud": ["attacker-app", "target-app"]}  # Does target app accept this?
```

### Issuer (iss) Confusion

```
# If multiple IdPs used, check issuer validation
# Target accepts tokens from IdP-A and IdP-B
# Attacker controls IdP-C (e.g., by registering on a shared IdP)
# Crafts token with iss matching target's expected format

# OpenID Connect provider switcheroo:
# If app allows any OIDC provider, attacker creates their own
# Issues tokens claiming to be victim@target.com
```

### Hybrid Flow Token Leakage

Hybrid flow returns tokens in the URL (fragment or query):

```
response_type=code id_token  # Hybrid: code + id_token in redirect
response_type=token id_token # Implicit: both tokens in redirect

# Tokens in URL → in browser history, logs, Referer header
GET /callback#id_token=eyJXXX&access_token=xxx

# Test: does app use response_type that returns tokens in URL?
# Check: does page load third-party resources (analytics) that receive Referer?
```

### PKCE Bypass (Code Interception)

```
# PKCE protects authorization code from interception
# Without PKCE, intercepted code usable by attacker

# Test: initiate flow without code_challenge
# If accepted → PKCE not enforced → code interception possible (mobile apps especially)
```

### UserInfo Endpoint Attacks

```
# /userinfo with access_token
GET /oauth2/userinfo
Authorization: Bearer ACCESS_TOKEN

# Test: use another user's access_token (IDOR)
# Test: expired access_token still accepted
# Test: access_token from different scope grants access to sensitive claims
# Test: sub claim manipulation in access_token
```

### Discovery Document Manipulation

```
# /.well-known/openid-configuration exposes endpoints
# If app fetches this dynamically and doesn't pin:
# SSRF → app fetches attacker-controlled discovery document
# → attacker redirects token endpoint to capture tokens

# Test: can the OIDC provider URL be user-controlled?
# SSRF via: ?iss=http://169.254.169.254/...
```

### Token Substitution

```
# App accepts access_token as id_token (or vice versa)
# Access tokens are not always JWTs and may not have iss/aud validation
# Substitute access_token where id_token is expected
```

### Scope Elevation via OIDC

```
# Request additional scopes that shouldn't be granted
openid email profile offline_access admin:read

# Test: add undocumented/admin scopes to authorization request
# Check if consent screen shows scope you requested
# Test if token grants those scopes even if consent not properly validated
```

## Provider-Specific Attacks

### Google

```
# hd (hosted domain) parameter bypass:
/oauth2/auth?hd=attacker.com vs target app expects hd=targetcorp.com
# If app validates hd on frontend but not when processing id_token → bypass

# Client email enumeration via oauth
```

### Apple Sign In

```
# Email relay service — each app gets different email
# app-specific-relay@privaterelay.appleid.com
# User merging: if app merges by email, different apps share account?
```

### Auth0

```
# /authorize?connection=bypass
# Test switching connection to bypass MFA or policy
# Universal Login bypass via legacy lock parameters
```

## Testing Methodology

1. **Map OIDC flows** — Which response_types? Code, implicit, hybrid?
2. **Check state validation** — Remove state param, replay state across sessions
3. **Check nonce validation** — Capture and replay id_token in new session
4. **Validate iss and aud** — Submit id_token from your own registered app
5. **Test scope enumeration** — Add undocumented/admin scopes
6. **Test PKCE enforcement** — Initiate flow without code_challenge
7. **Check UserInfo endpoint** — Test with invalid/expired tokens, other users' tokens
8. **Check token leakage** — Does response_type put tokens in URL?
9. **Provider confusion** — Can you switch providers? Is issuer validated strictly?

## Validation

1. Demonstrate authentication as a different user using the attack technique
2. Show the specific claim (sub, email, iss, aud) that was manipulated or bypassed
3. For token replay: show same id_token used across multiple sessions
4. Provide the authorization request and token payload before/after manipulation

## False Positives

- nonce properly validated on server side before creating session
- aud strictly compared to registered client_id only
- PKCE enforced with server-side code_verifier validation
- state entropy sufficient and validated per-session

## Impact

- Authentication bypass → account takeover
- Cross-application token reuse → access to other integrated apps
- Session fixation via CSRF on login
- PII exposure via over-scoped access tokens

## Pro Tips

1. OIDC discovery document (`/.well-known/openid-configuration`) is your first stop
2. Decode id_token with jwt.io — check iss, aud, nonce, sub, exp claims
3. `state` bypass in OAuth/OIDC is still commonly found — test every SSO integration
4. Multi-tenant apps often trust iss from any tenant → cross-tenant token abuse
5. Check if app supports multiple OIDC providers and whether iss is strictly pinned per-provider
6. hybrid flow response_type putting tokens in URL is automatic P2/P3 finding
7. Auth0 misconfigurations in multi-application setups are a frequent source of bugs

## Summary

OIDC builds identity on OAuth's authorization layer. Each additional component (nonce, iss, aud, state, PKCE) is a potential bypass point. Validate the full token: signature, expiry, issuer, audience, nonce, and session binding. Provider confusion and state bypass are the most commonly missed.
