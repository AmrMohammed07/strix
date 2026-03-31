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
