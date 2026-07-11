---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
---

# Authentication / JWT / OIDC

JWT/OIDC failures often enable token forgery, token confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

## Attack Surface

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option (`"b64":false`) and critical headers (`"crit"`)

## Key Vulnerabilities

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit JWKS URL fetching to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)

### Token Confusion and OIDC

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device

## Advanced Techniques

### Microservices and Gateways

- Audience mismatch: internal services verify signature but ignore aud → accept tokens for other services
- Header trust: edge or gateway injects X-User-Id; backend trusts it over token claims
- Asynchronous consumers: workers process messages with bearer tokens but skip verification on replay

### JWS Edge Cases

- Unencoded payload (b64=false) with crit header: libraries mishandle verification paths
- Nested JWT (JWT-in-JWT) verification order errors; outer token accepted while inner claims ignored

## Special Contexts

### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible

### SSO Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens

## Chaining Attacks

- XSS → token theft → replay across services with weak audience checks
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → code capture
- IDOR in sessions/impersonation endpoints → mint tokens for other users

## Testing Methodology

1. **Inventory issuers/consumers** - Identity providers, API gateways, services, mobile/web clients
2. **Capture tokens** - Access and ID tokens for multiple roles; note header, claims, signature
3. **Map verification endpoints** - `/.well-known`, `/jwks.json`
4. **Build matrix** - Token Type × Audience × Service; attempt cross-use
5. **Mutate components** - Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), signatures
6. **Verify enforcement** - What is actually checked vs assumed

## Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, or attacker-signed JWKS)
2. Demonstrate access token vs ID token confusion at an API
3. Prove refresh token reuse without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control
5. Provide owner vs non-owner evidence with identical requests differing only in token context

## False Positives

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens

## Impact

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints

## Pro Tips

1. Pin verification to issuer and audience; log and diff claim sets across services
2. Attempt RS256→HS256 and "none" first only if algorithm pinning is unclear; otherwise focus on header key control (kid/jku/x5u/jwk)
3. Test token reuse across all services; many backends only check signature, not audience/typ
4. Exploit JWKS caching and rotation races; try retired keys and missing kid fallbacks
5. Exercise OIDC flows with PKCE/state/nonce variants and mixed clients; look for mix-up
6. Try DPoP/mTLS absence to replay tokens from different devices
7. Treat refresh as its own surface: rotation, reuse detection, and audience scoping
8. Validate every acceptance path: gateway, service, worker, WebSocket, and gRPC
9. Favor minimal PoCs that clearly show cross-context acceptance and durable access
10. When in doubt, assume verification differs per stack (mobile vs web vs gateway) and test each

## Summary

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.



## Additional Techniques — ported from WebSkills (improper-authentication-testing)

### Fast JWT triage (run before deep attacks)
- **All-tests scan:** `python3 jwt_tool.py -M at -t "<url>" -rh "Authorization: Bearer <JWT>"` then dump the flagged token with `jwt_tool.py -Q "<jwttool_id>"`.
- **Is the token required?** Remove it and resend — unchanged response means the JWT isn't the real auth mechanism (check other headers/cookies).
- **Is the signature checked?** Delete the last few signature chars. Same page = signature not verified → tamper claims directly.
- **Is the token persistent/immortal?** Replay the same token interspersed with invalid ones; if it works indefinitely, retest in ~24h and report a never-expiring token.
- **Claim processing order:** alter a benign payload field (e.g. profile image URL) with the signature untouched; if the change is reflected, the app processes claims *before/without* verifying the signature.

### Algorithm confusion with NO exposed public key (sig2n)
When the app is RS256 but you can't find `/.well-known/jwks.json`, recover the public key from two captured tokens and forge an HS256 token signed with it:
```bash
# collect two JWTs (login → copy → logout → login → copy second)
docker run --rm -it portswigger/sig2n <token1> <token2>   # github.com/silentsignal/rsa_sign2n
# for each candidate n it prints, test the forged JWT: 200 = correct key, 302→/login = wrong
```
Then in Burp JWT Editor: New Symmetric Key → replace `k` with the Base64 key, set `alg:HS256`, change `sub` to `administrator`, sign.

### Miscellaneous acceptance bugs
- **JTI short-ID replay:** if `jti` is only 4 digits (0001–9999), IDs wrap — a replayed request can collide with a valid ID after enough requests, defeating replay protection.
- **Example / foreign-token acceptance:** backends that verify signature but not audience will accept any validly-signed JWT (e.g. a vendor's example token from docs, or a token minted for another tenant/service). Test cross-service relay: sign up on another client of the same shared JWT service with the same email, then replay that token at the target.


## Additional Techniques — ported from WebSkills (writeup-techniques/jwt-auth)

These JWT/token and general auth-bypass items are not covered by the sections above (or by the sibling `jwt.md`). SAML and OTP/2FA patterns from the same source live in `saml_attacks.md` and `mfa_bypass.md`.

### JWE-wrapped PlainJWT bypass (pac4j-jwt, CVE-2026-29000)
Stacks that expect a **signed inner JWT inside an encrypted JWE** but only verify the signature *if* the decrypted payload parses as a signed token. Supply a **PlainJWT** (`alg:none`, empty sig) as the inner token so the conversion path skips signature verification. Requires: app accepts JWE bearer tokens **and** the server RSA **public** key is exposed via JWKS — with only the public key you forge an encrypted token for any user/role.
```
Inner (PlainJWT):  {"alg":"none"}.{"sub":"admin","role":"ROLE_ADMIN"}.   (empty sig)
Outer: encrypt that plaintext into a compact JWE with the exposed RSA public key → send as Bearer
```

### Crypto-implementation acceptance CVEs
- **CVE-2022-21449 "psychic signature"** — Java ECDSA (P-256 / ES256) accepts a blank `r=0, s=0` signature → forge any token against Java/Spring JWT apps.
```
{"alg":"ES256"}   signature = r=0, s=0 (all-zero / blank)
```
- **CVE-2022-39227 (python_jwt)** — polyglot token: append a **second JSON object** so the parser reads attacker claims while the signature check runs over the original → escalate to admin.
- **EdDSA (Monocypher)** implementation flaw lets you forge a signature and tamper the payload (PentesterLab EdDSA); **CBC-MAC** signing weakness (PentesterLab CBC-MAC); **"Invalid Algorithm"** — server accepts an unexpected `alg` it doesn't actually validate. Try these when the token uses a non-RSA/non-HS algorithm.

### LFI / backup / default-key → forge signed cookies (flask_unsign)
Flask/Django "session" cookies are **signed, not JWT**, but the same class — forge them with a default or leaked `SECRET_KEY`.
- **Default key**: Apache Superset CVE-2023-27524 shipped a default `SECRET_KEY` → forge `_user_id:1` and hit `/superset/welcome` as admin.
- **Leaked key chain**: arbitrary file read (LFI, `.git`, backup, build artifact) exposes the app key **and** the user table → derive the signing secret, forge any user's token (PwnDoc CVE-2022-45771 → RCE).
```
flask-unsign --unsign --cookie "<session>" --wordlist keys.txt      # recover key
flask-unsign --sign --cookie "{'_user_id':1}" --secret '<key>'      # forge admin cookie
```

### `jti` Base64-malleability revocation bypass
Distinct from the short-ID `jti` wrap already noted. When a "revoked" token is checked against a blacklist by exact `jti` string, exploit **Base64 malleability** — add padding or swap for an equivalent-decoding byte so `jti` decodes to the *same* value but the encoded string no longer matches the blacklist entry → replay a revoked token (PentesterLab API JWT Revocation).

### Signature / secret leak → forge
The signing secret or a full signature can leak in a **response body, log, or PCAP** (PentesterLab JWT Signature Leak; extract `Authorization: Bearer` from an HTTP capture). Grep proxy history / captured traffic for the third JWT segment and for `secret`/`SECRET_KEY` strings, then re-sign arbitrary claims.

### Predictable / truncatable session tokens & auth-filter path bypass
General auth-bypass patterns that appear alongside JWT in the corpus (non-JWT session tokens):
- **Truncatable/incrementable session IDs** — trailing characters can be stripped or incremented and the token still validates (CA 2E `W2E_SSNID`: stripping trailing digits still authenticates). Probe by trimming/altering the tail of the session value.
- **Auth-filter exclude-path bypass** — a servlet/filter that skips auth for a URL prefix can be tricked with traversal so a protected path matches the excluded one:
```
/setup/setup-/../../   →  Openfire AuthCheckFilter treats it as the excluded /setup/ path, reaching admin
```
