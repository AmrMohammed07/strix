---
name: http-parameter-pollution
description: HTTP parameter pollution — exploiting inconsistent duplicate parameter handling across components
---

# HTTP Parameter Pollution (HPP)

HTTP Parameter Pollution exploits inconsistencies in how different components (WAF, backend app, middleware, proxies) parse duplicate or repeated parameters. When the same parameter appears multiple times, different parsers use different resolution strategies — first, last, concat, or array — creating security bypass opportunities.

## Attack Surface

**Locations**
- Query string: `GET /search?q=a&q=b`
- POST body: `q=a&q=b` (URL-encoded)
- JSON arrays: `{"q": ["a","b"]}`
- XML with repeated elements
- HTTP headers with duplicate names
- Cookie headers: `Cookie: a=1; a=2`
- Path parameters in REST APIs

**Vulnerable Architectures**
- WAF in front of app with different parser
- API gateway + microservice with different framework
- Reverse proxy + backend using different language
- Load balancer rewriting parameters

## Parameter Parsing Behavior

| Technology | Duplicate param behavior |
|-----------|------------------------|
| PHP | Last value wins (`$_GET['x']` = last) |
| ASP.NET | First and last concatenated with comma |
| JSP/Servlet | First value wins |
| Python (Flask/Django) | Last value wins (Flask), first (Django) |
| Node (express) | Array `['a','b']` |
| Ruby (Rails) | Last value wins |
| Perl (CGI) | First value wins |
| ModSecurity WAF | First value |
| Cloudflare WAF | First value |

## Key Vulnerabilities

### WAF Bypass

WAF checks first value, app uses last (or vice versa):
```
GET /search?q=legitimate&q=<script>alert(1)</script>
# WAF sees: q=legitimate (safe)
# App uses: q=<script>alert(1)</script> (malicious)
```

```
POST /login
username=admin&password=x&password=INJECTED_SQL
# WAF scans first password value
# App uses last → SQLi bypass
```

### Authentication Bypass

```
GET /api/user?id=VICTIM&id=OWN_ID
# Backend uses first = VICTIM, auth check uses last = OWN_ID
```

### SSRF via HPP

```
GET /proxy?url=http://internal&url=http://allowed.com
# Allowlist checks url=http://allowed.com (last)
# Proxy uses url=http://internal (first)
```

### OAuth/Redirect HPP

```
GET /oauth/authorize?redirect_uri=https://legit.com&redirect_uri=https://attacker.com&client_id=X
# Validation: checks first = legit.com ✓
# Redirect: uses last = attacker.com → token leakage
```

### Signature Bypass

```
POST /api/transfer
amount=100&recipient=friend&amount=10000&mac=VALID_MAC_OF_FIRST_VALUES
# MAC computed on first values (small transfer)
# App executes last values (large transfer)
```

### Server-Side HPP

When server constructs a backend query using user params:
```
# App: http://backend/api?user=INPUT&admin=false
# Attacker input: user=alice&admin=true
# Result: http://backend/api?user=alice&admin=false&admin=true
# Backend may use last admin=true
```

### Content-Type HPP

```
POST /api/data
Content-Type: application/x-www-form-urlencoded; charset=utf-8&boundary=attacker
# Some parsers use boundary from Content-Type (multipart) instead of body
```

## Bypass Techniques

**URL Encoding**
```
param=val1%26param=val2    # %26 = &, creates second param after decode
param=val1&param%3dval2    # %3d = = sign
```

**Array Notation**
```
param[]=val1&param[]=val2  # PHP array notation
param[0]=val1&param[1]=val2
```

**JSON Body**
```json
{"param": "safe", "param": "malicious"}
# Some parsers use last key in duplicate JSON object
```

**HTTP/2 Pseudo-headers**
```
# HTTP/2 allows duplicate header names
# Exploit inconsistency between H2 and H1 backends
```

## Testing Methodology

1. **Baseline** — Identify target parameters, document normal behavior
2. **Duplicate injection** — Add second copy of each parameter with malicious payload
3. **Swap order** — Test malicious=first, safe=last and safe=first, malicious=last
4. **Component mapping** — Identify WAF, proxy, and app technologies
5. **Auth parameters** — Focus on `user`, `id`, `role`, `admin`, `token`, `redirect_uri`
6. **Compare parsers** — Send same request through direct access (bypassing WAF) to see app behavior
7. **Client-side HPP** — If app constructs URLs with user data, test if it appends params the app already sends

### Client-Side HPP

```javascript
// App constructs: /search?category=SAFE&sort=SAFE
// If category input is: books&admin=true
// Result: /search?category=books&admin=true&sort=SAFE
```

## Validation

1. Show that the malicious value bypassed the WAF/middleware check
2. Demonstrate different behavior vs. single legitimate parameter
3. Prove which component used which value via response differences

## False Positives

- App and WAF use same parser behavior
- Backend correctly rejects duplicate parameters
- WAF configured to reject requests with duplicate params

## Impact

- WAF/IPS bypass enabling SQLi, XSS, command injection
- Authorization bypass (role/admin parameter injection)
- OAuth token theft via redirect_uri pollution
- Business logic bypass via amount/value manipulation

## Pro Tips

1. `HPP Finder` Burp plugin automatically tests parameter pollution
2. Always test POST body AND query string — frameworks often parse them differently
3. Cookie duplication is often overlooked: `Cookie: session=a; session=b`
4. Check JSON with duplicate keys — JavaScript JSON.parse uses last, Python uses last
5. HTTP/2 → HTTP/1.1 downgrade by reverse proxy creates parameter injection opportunities
6. In OAuth flows, `redirect_uri` duplication is a classic finding
7. Test both orderings: malicious-first and malicious-last for each parameter

## Summary

HTTP Parameter Pollution exploits the fact that different components in a stack handle duplicate parameters differently. The attacker provides two values — one that passes security checks and one that gets executed — exploiting the component that uses the other value. Test every parameter in security-sensitive operations.
