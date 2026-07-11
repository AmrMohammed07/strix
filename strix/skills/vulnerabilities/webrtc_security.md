---
name: webrtc_security
description: WebRTC security testing — STUN/TURN server misconfiguration, private/local IP leakage via ICE candidates, SDP munging, unauthenticated TURN relay abuse (internal port scanning / SSRF-style pivots), and media/data-channel injection. Use when a target has video/voice/screen-share/live-chat, a peer-to-peer feature, or exposes stun:/turns: endpoints.
---

# WebRTC Security

WebRTC powers browser video/voice/screen-share, P2P file transfer, and live chat. Its
signaling and NAT-traversal machinery (STUN/TURN/ICE, SDP) exposes attack surface most
web testing misses: internal IP disclosure, an open relay that can be turned into an
internal port scanner, and injectable media/data channels. Trigger on any "call",
"meet", "live", "screen share", "P2P", or when JS references `RTCPeerConnection`,
`stun:`, `turn:`, or `iceServers`.

## Attack Surface — Where to Look

- **`RTCPeerConnection` config in JS** — grep bundles for `iceServers`, `stun:`,
  `turn:`, `turns:`, `RTCPeerConnection`, `createOffer`, `setRemoteDescription`.
  Extract every STUN/TURN URL and any embedded TURN `username` / `credential`.
- **Signaling channel** — the WebSocket/HTTP that exchanges SDP offers/answers and ICE
  candidates. This is where SDP munging and candidate injection land (pairs with
  `websocket_security.md`).
- **TURN server** (`turn:`/`turns:` on 3478/5349) — the relay. Static or leaked
  long-term credentials here are the highest-impact finding.
- **Media/data channels** — `RTCDataChannel` messages and media tracks once the peer
  connection is established.

## Key Issues

### 1. Local / private IP leakage via ICE candidates
Even behind a VPN/proxy, `RTCPeerConnection` gathers host candidates that expose the
client's local (RFC1918) and sometimes public IP — a classic de-anonymization /
info-disclosure vector. Enumerate candidates directly in the browser:
```javascript
const pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
pc.onicecandidate = e => { if (e.candidate) console.log(e.candidate.candidate); };
pc.createDataChannel("x");
pc.createOffer().then(o => pc.setLocalDescription(o));
// candidate lines reveal: 192.168.x.x (host), the public srflx IP, mDNS .local names
```
Report when the app leaks a private/internal IP it shouldn't, or defeats an
anonymity guarantee. Modern browsers use mDNS `.local` obfuscation for host
candidates — note whether it's enabled; if the app forces `iceTransportPolicy` off
mDNS or reads raw candidates server-side, the real IP is exposed.

### 2. TURN misconfiguration — unauthenticated / static credentials
TURN should require short-lived, per-session credentials (REST API `username` =
`timestamp:user`, `credential` = HMAC). Failures to test:
- **Open relay (no auth):** connect to `turn:host:3478` with empty/any credentials and
  see if allocations succeed.
- **Static long-term credentials:** the same `username`/`credential` hard-coded in the
  JS for every user → anyone can relay through it indefinitely.
- **Leaked creds in the bundle:** grep the JS for `credential:` — often a static secret.
Probe allocations with `turnutils_uclient` (coturn) or a minimal ICE client:
```bash
# coturn's own client — attempt an allocation with the discovered creds
turnutils_uclient -u <username> -w <credential> -y <turn-host>
# no creds accepted / allocation granted anonymously = open relay
```

### 3. TURN relay abuse → internal port scan / SSRF-style pivot
An open or credential-leaked TURN server will `CreatePermission` + `ChannelBind` to an
arbitrary peer address and relay traffic to it — including **internal** addresses. That
turns the relay into an SSRF-style internal port scanner: request allocations toward
`127.0.0.1`, `169.254.169.254` (cloud metadata), and RFC1918 hosts and infer
open/closed from allocation success/latency. This is the WebRTC analogue of SSRF —
frame impact accordingly (internal service reach / metadata = High/Critical). Confirm
with a controlled internal listener you own before claiming reach; never pivot into
out-of-scope infrastructure.

### 4. SDP munging / ICE candidate injection
If the signaling channel doesn't authenticate or integrity-check SDP, an attacker on
the signaling path (or exploiting a signaling IDOR) can rewrite the offer/answer:
- Swap the `c=`/`a=candidate:` lines to redirect media to an attacker relay
  (man-in-the-middle of the call).
- Inject extra `m=` sections or codecs to trigger parser bugs / DoS on the peer.
- Downgrade `a=fingerprint` / DTLS-SRTP params to weaken media encryption.
Test by intercepting the signaling WS and mutating the SDP before it reaches the peer;
watch whether the peer accepts an offer whose ICE/DTLS parameters you changed.

### 5. Media / data-channel injection & missing authz
- **`RTCDataChannel`** messages are just application data — apply the same input-
  validation / XSS / injection tests you would to any WS message; a data-channel
  message rendered into the DOM is a stored/DOM XSS sink.
- **Room / peer authorization:** can you join a call/room you were not invited to by
  guessing or enumerating the room ID on the signaling channel (IDOR)? Can a
  participant receive media/data after being "removed"? Test cross-tenant room joins.

## Testing Methodology
1. Grep JS for `RTCPeerConnection` / `iceServers` / `stun:` / `turn:` — extract all
   STUN/TURN URLs and any embedded credentials.
2. Run the ICE-candidate enumeration snippet — record any private/internal IP leaked.
3. Against each TURN server: attempt anonymous and static-credential allocations
   (`turnutils_uclient`); if granted, attempt an allocation toward an internal
   address you control to prove relay-based internal reach.
4. Intercept the signaling channel; attempt SDP munging and candidate injection.
5. Test data-channel messages as injection sinks and enumerate room/peer authz (IDOR).

## Validation
- IP leak: show the actual private/public IP in a `candidate:` line and explain the
  anonymity/scope it breaks.
- Open/static TURN: show the granted allocation with the (missing or static) creds.
- Relay abuse: show relayed traffic reaching an internal host/port you control.
- SDP munging: show the peer accepting an attacker-modified offer/answer.

## False Positives
- mDNS `.local` host candidates with no real IP exposed = working as intended.
- TURN requiring valid short-lived HMAC credentials that you could not forge = secure.
- Candidate gathering that only reveals the already-public server IP = not a leak.
- SDP changes rejected by the peer's fingerprint/ICE checks = integrity holding.

## Impact
- Private/internal IP disclosure → de-anonymization, internal-network mapping.
- Open/leaked TURN relay → SSRF-style internal port scan, metadata reach, bandwidth
  abuse (free relay), pivot into internal services.
- SDP munging → call MITM, media-encryption downgrade, peer DoS.
- Data-channel injection / room IDOR → XSS, cross-tenant media/data access.
