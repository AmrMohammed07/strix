---
name: tls-ssl-misconfig
description: TLS/SSL misconfiguration testing — weak ciphers, expired certificates, protocol downgrades, and HSTS bypass
---

# TLS/SSL Misconfiguration

TLS misconfigurations expose encrypted communications to interception, allow protocol downgrade attacks, and enable MITM scenarios. While modern automated tooling has improved defaults, custom configurations, legacy systems, and improper certificate management remain common sources of vulnerabilities.

## Attack Surface

**Assessment Targets**
- HTTPS endpoints (web, API, WebSocket wss://)
- Mail servers (SMTP/IMAP/POP3 with STARTTLS)
- VPN endpoints
- Database connections (MySQL/PostgreSQL TLS)
- Internal services with TLS

## Testing Tools

```bash
# testssl.sh (most comprehensive)
testssl.sh https://target.com
testssl.sh --full --html --jsonfile result.json https://target.com

# SSLyze
sslyze --regular target.com:443

# Nmap SSL scripts
nmap -sV --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p 443 target.com

# OpenSSL manual testing
openssl s_client -connect target.com:443
openssl s_client -connect target.com:443 -tls1  # Test TLS 1.0
openssl s_client -connect target.com:443 -ssl3  # Test SSLv3

# sslscan
sslscan target.com:443

# Online tools
# ssllabs.com/ssltest/
# hardenize.com
```

## Key Vulnerabilities

### Protocol Version Issues

```bash
# SSLv2 (Critical — completely broken)
openssl s_client -connect target.com:443 -ssl2

# SSLv3 (Critical — POODLE CVE-2014-3566)
openssl s_client -connect target.com:443 -ssl3

# TLS 1.0 (High — deprecated, BEAST, POODLE-TLS)
openssl s_client -connect target.com:443 -tls1

# TLS 1.1 (Medium — deprecated March 2021)
openssl s_client -connect target.com:443 -tls1_1

# Acceptable: TLS 1.2, TLS 1.3
```

### Weak Cipher Suites

```bash
# Test specific ciphers
openssl s_client -connect target.com:443 -cipher RC4-MD5
openssl s_client -connect target.com:443 -cipher DES-CBC3-SHA
openssl s_client -connect target.com:443 -cipher NULL-MD5
openssl s_client -connect target.com:443 -cipher EXPORT

# Dangerous cipher properties:
# NULL ciphers (no encryption)
# Export ciphers (40/56-bit keys — FREAK CVE-2015-0204)
# RC4 (broken stream cipher)
# DES/3DES (64-bit block — Sweet32 CVE-2016-2183)
# Anonymous DH/ECDH (no server authentication)
# CBC mode without proper MAC (BEAST, LUCKY13)
```

### Certificate Vulnerabilities

```bash
# Check certificate details
openssl s_client -connect target.com:443 | openssl x509 -text -noout

# Expired certificate
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates

# Self-signed certificate
# Common name mismatch (wrong domain)
# Weak signature algorithm (MD5, SHA1)
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -sigalg

# Certificate chain issues
# Incomplete chain (missing intermediates)
# Root CA not trusted

# Wildcard abuse
# *.target.com covers all subdomains — subdomain takeover = certificate mismatch
```

### Known Attacks

```bash
# Heartbleed (CVE-2014-0160) — OpenSSL memory leak
nmap --script ssl-heartbleed -p 443 target.com
testssl.sh --heartbleed target.com

# POODLE (CVE-2014-3566) — SSLv3 padding oracle
testssl.sh --poodle target.com

# BEAST (CVE-2011-3389) — TLS 1.0 CBC
# Mitigated by modern browsers, but server config matters

# CRIME (CVE-2012-4929) — TLS compression
testssl.sh --crime target.com
openssl s_client -connect target.com:443 | grep Compression

# BREACH (CVE-2013-3587) — HTTP compression (not TLS-level)
curl -H "Accept-Encoding: gzip" -I https://target.com

# ROBOT (CVE-2017-13099) — RSA PKCS#1 v1.5 oracle
testssl.sh --robot target.com

# LUCKY13 — Timing attack on CBC
# Mitigated in modern TLS stacks

# FREAK (CVE-2015-0204) — Export cipher downgrade
testssl.sh --freak target.com

# Logjam (CVE-2015-4000) — DHE downgrade to export
testssl.sh --logjam target.com
openssl s_client -connect target.com:443 -cipher DHE-RSA-DES-CBC-SHA
```

### HSTS Issues

```bash
# Missing HSTS
curl -I https://target.com | grep -i strict

# Short max-age
Strict-Transport-Security: max-age=300  # Easily expired

# No includeSubDomains
Strict-Transport-Security: max-age=31536000  # Subdomains still vulnerable

# Not in preload list
# https://hstspreload.org/?domain=target.com

# HTTP accessible (HSTS doesn't help on first visit without preload)
curl http://target.com  # Should redirect to HTTPS, not serve content
```

### Mixed Content

```
# Page served over HTTPS but resources loaded over HTTP:
# <script src="http://target.com/app.js">
# <img src="http://cdn.target.com/image.png">
# Active mixed content (scripts, iframes) = blocked by modern browsers
# Passive mixed content (images) = warning
# Mixed content via JavaScript: fetch('http://...')
```

### Certificate Transparency

```bash
# Check CT logs for issued certificates
curl "https://crt.sh/?q=target.com&output=json" | jq '.[].name_value'
# Reveals: subdomains, internal hostnames, historical certs
# Look for: dev., staging., internal., admin. subdomains

# Check for unexpected wildcard certs
# Check for certs issued by unknown/untrusted CAs
```

### TLS Interception (Proxy Detection)

```bash
# TLS fingerprinting — JA3 hash
# If TLS fingerprint changes between client and server, proxy/interception in path
# Use ja3.zone to compare
```

## Testing Methodology

1. **Run testssl.sh** — Comprehensive automated scan
2. **Check protocol versions** — SSLv2/3, TLS 1.0/1.1 support
3. **Audit cipher suites** — NULL, export, RC4, anonymous, EXPORT ciphers
4. **Validate certificate** — Expiry, chain, SANs, CN match, signing algorithm
5. **Known CVEs** — Heartbleed, POODLE, ROBOT, FREAK, Logjam
6. **HSTS** — Check header, max-age, includeSubDomains, preload
7. **Mixed content** — Inspect all resources loaded on HTTPS pages
8. **Certificate Transparency** — crt.sh enumeration for exposed subdomains

## Validation

1. Show testssl.sh output with specific failing tests
2. Confirm protocol/cipher handshake success with openssl command
3. For certificate issues: show expiry date or chain validation error
4. For HSTS: show header value and explain the weakness

## False Positives

- TLS 1.0 disabled at load balancer level but not backend (backend unreachable directly)
- "Expired" certificate on an internal hostname not serving real traffic
- Cipher listed as supported but not actually negotiated by server

## Impact

| Issue | Impact |
|-------|--------|
| SSLv2/3 or TLS 1.0 | Active MITM possible, session decryption |
| NULL/export ciphers | Encryption bypass |
| Heartbleed | Server memory disclosure, private key extraction |
| Expired certificate | User trust warning, potential MITM |
| Missing HSTS | SSL stripping attacks |
| Mixed content | HTTP resources interceptable |

## Pro Tips

1. testssl.sh is the industry standard — run it first on every HTTPS endpoint
2. Don't just scan port 443 — check 8443, 8080, API endpoints, WebSocket ports
3. Certificate Transparency enumeration (crt.sh) is free intel for recon
4. HSTS without preload doesn't protect first-time visitors — important context
5. In bug bounty, Heartbleed/POODLE are usually Critical if confirmed → immediate disclosure
6. Mixed content on login pages is higher severity (credentials over HTTP)
7. Short `max-age` on HSTS is a finding but usually low — explain the real-world risk
8. Check internal services too — they often have expired or self-signed certs creating MITM risk

## Summary

TLS misconfigurations range from critical (Heartbleed, POODLE) to informational (weak cipher preference). Use testssl.sh for systematic testing, focus on protocol versions and known CVEs first, then certificate validation and HSTS. Internal services often have worse TLS hygiene than externally-facing ones.
