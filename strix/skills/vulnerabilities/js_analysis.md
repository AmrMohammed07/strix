# JavaScript Analysis for Security Testing

## Overview
Techniques for analyzing JavaScript files to discover hidden endpoints, API keys, secrets, and vulnerabilities.

## Finding JS Files
```
# From browser DevTools (Sources tab)
# From spider/crawl
# Common paths:
/static/js/, /assets/js/, /js/, /dist/, /build/
/webpack.js, /chunk-vendors.js, /main.js, /app.js

# Wayback Machine for old JS
https://web.archive.org/web/*/target.com/js/*

# Fetch all JS from page
curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
```

## Secret Discovery
```
# API Keys, tokens, credentials in JS

# Common patterns to search:
grep -iE "(api[_-]?key|apikey|access[_-]?token|secret|password|passwd|credential|auth[_-]?token)" *.js
grep -iE "(aws_access|s3[_-]?key|firebase|stripe|twilio|sendgrid|mailgun)" *.js

# Regex for common secrets:
# AWS: AKIA[0-9A-Z]{16}
# GitHub: ghp_[0-9a-zA-Z]{36}
# Stripe: sk_live_[0-9a-zA-Z]{24}
# Google API: AIza[0-9A-Za-z-_]{35}

# Tools:
# truffleHog, gitleaks, secretfinder
python3 SecretFinder.py -i https://target.com/app.js -o cli

# JS BeautifierBeautify minified files first
```

## API Endpoint Discovery
```
# Extract API endpoints from JS
grep -oE '["'"'"'][/][a-zA-Z0-9_/.-]+["'"'"']' app.js | sort -u
grep -oE '"(GET|POST|PUT|DELETE|PATCH)[^"]*"' app.js

# Path patterns
grep -oE '`[^`]*\$\{[^}]+\}[^`]*`' app.js  # template literals with vars

# URL patterns
grep -oE 'https?://[a-zA-Z0-9._/-]+' app.js

# Fetch/axios calls
grep -iE "(fetch|axios|http\.get|http\.post|ajax)\s*\(" app.js

# React/Angular route files
# router.js, routes.js, app-routing.module.ts
# Look for path: '/endpoint' or component: AdminComponent
```

## Source Map Exploitation
```
# Source maps expose original unminified source
# Check for: bundle.js.map, app.js.map, main.chunk.js.map

# Download and analyze:
curl https://target.com/static/js/main.chunk.js.map -o main.map

# Tools:
# source-map-explorer
# node-source-map-support
# Extract with: https://github.com/paazmaya/shuji

# Source maps may reveal:
# Full application source code
# Internal file paths
# Comments and debug info
# Hardcoded secrets
```

## JavaScript Security Analysis
```
# DOM XSS sinks
grep -E "(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\()" app.js
grep -E "(location\.href|location\.hash|location\.search)" app.js

# Postmessage issues
grep -E "addEventListener\(['\"]message" app.js
# Check: is origin validated? window.addEventListener('message', handler) without origin check

# Prototype pollution
grep -E "(Object\.assign|merge\(|extend\(|deepmerge)" app.js
# Check if user-controlled keys reach merge operations

# Client-side storage
grep -E "(localStorage|sessionStorage|indexedDB)\.(setItem|getItem)" app.js
# What sensitive data is stored client-side?

# Hardcoded credentials
grep -iE "(password|secret|key|token)\s*[:=]\s*['\"][^'\"]{6,}" app.js
```

## Web Worker & Service Worker Analysis
```
# Service worker files:
/sw.js, /service-worker.js, /serviceworker.js

# Check for:
# Cache poisoning opportunities
# Intercept/modify fetch requests
# Stored data accessible to SW

# Web workers: same analysis as regular JS
```

## WebPack Bundle Analysis
```
# Identify webpack:
# __webpack_require__, webpackJsonp, /static/js/chunk-

# List all modules:
# Open in browser DevTools → Sources → webpack://

# webpack-bundle-analyzer for visual analysis
# Look for: node_modules with known vulns, custom business logic
```

## Dynamic Analysis
```
# Monitor XHR/fetch during app usage
# Browser DevTools → Network tab → XHR filter

# Intercept and modify API calls
# Discover undocumented endpoints during normal app usage

# Check browser storage:
localStorage, sessionStorage, cookies, indexedDB
# In DevTools → Application tab
```

## Testing Methodology
1. Collect all JS files (crawl, Wayback, DevTools)
2. Beautify/deobfuscate minified JS
3. Check for source maps
4. Run secret scanning tools
5. Extract all API endpoints and routes
6. Analyze for DOM XSS sinks
7. Check postMessage handlers
8. Look for hardcoded credentials
9. Analyze client-side storage usage
10. Check for sensitive data in localStorage/sessionStorage

## Tools
- `SecretFinder` — secrets in JS
- `LinkFinder` — endpoints in JS
- `JSParser` — endpoint extraction
- `getJS` — collect all JS files
- `subjs` — JS files from subdomains
- `truffleHog` — secret scanning
- Source Map Explorer
