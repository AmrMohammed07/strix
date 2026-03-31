# DNS Hijacking & Subdomain Takeover

## Overview
DNS-based attacks including subdomain takeover, dangling DNS records, and DNS rebinding.

## Subdomain Takeover

### Detection
```
# Find dangling CNAME records
dig CNAME sub.target.com
# If CNAME points to unclaimed service → takeover possible

# Common dangling targets:
# GitHub Pages: xxx.github.io
# AWS S3: xxx.s3.amazonaws.com, xxx.s3-website-*.amazonaws.com
# Heroku: xxx.herokuapp.com
# Azure: xxx.azurewebsites.net, xxx.cloudapp.net
# Shopify: xxx.myshopify.com
# Fastly: xxx.global.fastly.net
# Pantheon: xxx.pantheon.io
# Zendesk: xxx.zendesk.com
# Netlify: xxx.netlify.app

# Check if target responds with "NoSuchBucket", "Not Found", "not found on this server"
# Those are unclaimed indicators
```

### Exploitation
```
# GitHub Pages takeover:
1. CNAME points to victim.github.io
2. victim.github.io → 404 (repo deleted)
3. Register GitHub account with same username
4. Create repo with same name and enable Pages
5. Now control victim.sub.target.com

# S3 takeover:
1. CNAME points to bucket.s3.amazonaws.com
2. Bucket doesn't exist or is deleted
3. Create S3 bucket with same name
4. Upload index.html → serve malicious content

# Heroku:
1. CNAME points to app-name.herokuapp.com
2. App deleted
3. Create Heroku app with same name
```

### Impact of Subdomain Takeover
```
# XSS on subdomain that can affect parent via:
- document.domain relaxation
- Cookies scoped to .target.com
- Same-site cookie bypass

# Phishing via legitimate-looking subdomain
# CSP bypass if subdomain whitelisted
# OAuth redirect_uri bypass
# Email phishing from sub@taken-subdomain.target.com
```

## DNS Rebinding

### Concept
```
# Bypass same-origin policy using DNS TTL manipulation
# Phase 1: DNS resolves to attacker's server (serves malicious JS)
# Phase 2: DNS TTL expires, rebinds to 127.0.0.1 or internal IP
# Phase 3: JS makes requests → browser thinks same origin → goes to internal service

# Attack flow:
1. Victim browser visits attacker.com
2. DNS: attacker.com → 1.2.3.4 (attacker's server) — serves JS
3. TTL expires (set to 0 or very low)
4. Victim JS makes another request to attacker.com
5. DNS now resolves: attacker.com → 192.168.1.1 (internal target)
6. Request goes to 192.168.1.1 with attacker.com origin
7. Reads internal API responses
```

### Tools
```
# Singularity of Origin — DNS rebinding framework
# https://github.com/nccgroup/singularity

# Rebind.network — online DNS rebinding service (for authorized tests)
```

## DNS Zone Transfer
```
# Test if nameserver allows zone transfer
dig axfr target.com @ns1.target.com
host -l target.com ns1.target.com
nmap --script dns-zone-transfer -p 53 ns1.target.com

# If successful: get full list of subdomains, internal IPs
```

## DNS Cache Poisoning
```
# Inject malicious DNS records into resolver cache
# Requires specific conditions (Kaminsky attack preconditions)
# Test: check DNSSEC deployment
dig target.com +dnssec

# Missing DNSSEC → potential cache poisoning risk (report as finding)
```

## Internal DNS Enumeration
```
# Brute force internal subdomains
# From inside network or via SSRF
# Common internal names:
internal, admin, dev, staging, vpn, mail, api, db, redis, jenkins
intranet, corp, portal, ldap, ad, dc, git, wiki, jira, confluence
```

## Testing Methodology
1. Enumerate all subdomains (dnsx, subfinder, amass, alterx)
2. Check CNAME records for each: `dig CNAME sub.target.com`
3. For each CNAME, test if service is claimed
4. Test for zone transfer
5. Check DNSSEC deployment
6. Look for SPF/DMARC issues (see email_attacks.md)
7. Test DNS rebinding protections (internal services)

## Tools
- `subfinder`, `amass` — subdomain enumeration
- `nuclei -t takeovers/` — automated takeover detection
- `dnsx` — DNS resolution at scale
- `can-i-take-over-xyz` — GitHub resource for takeover fingerprints
- `Singularity` — DNS rebinding
