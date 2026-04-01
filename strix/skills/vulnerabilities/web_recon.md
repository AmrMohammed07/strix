---
name: web-recon
description: Web reconnaissance techniques for bug bounty — subdomain enumeration, JS analysis, endpoint discovery, and fingerprinting
---

# Web Reconnaissance

Recon determines attack surface before active testing. Comprehensive recon finds assets, endpoints, and technologies that manual browsing misses — and in bug bounty, more surface area = more bugs. Speed and breadth win.

## Subdomain Enumeration

### Passive (No Direct Target Interaction)

```bash
# Certificate Transparency logs
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com -o subs.txt
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value' | sort -u

# DNS brute force wordlists
puredns bruteforce /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt target.com

# Shodan/Censys/Fofa/Zoomeye
shodan search "ssl.cert.subject.CN:*.target.com" --fields hostnames,ip_str

# Google dork
site:*.target.com -www

# Archive / Wayback
gau target.com | grep "://" | cut -d "/" -f 3 | sort -u
waybackurls target.com | grep "://" | cut -d "/" -f 3 | sort -u

# GitHub/GitLab
github-subdomains -d target.com -t GITHUB_TOKEN
```

### Active (Resolving Subdomains)

```bash
# DNS resolution
massdns -r /opt/resolvers.txt -t A subs.txt -o S > resolved.txt
dnsx -l subs.txt -resp -a -aaaa -cname -o dnsx-out.txt

# Virtual host discovery
ffuf -w subs.txt -u https://IP/ -H "Host: FUZZ.target.com" -mc 200,301,302,403

# Wildcard detection
puredns -w wordlist.txt target.com --resolvers resolvers.txt
```

## Port / Service Discovery

```bash
# Fast port scan
naabu -l hosts.txt -p - -o naabu-out.txt
masscan -p1-65535 --rate 10000 IP/range -oG masscan.txt

# Service fingerprint
nmap -sV -sC -p $(cat open_ports.txt) IP

# HTTP service discovery
httpx -l hosts.txt -ports 80,443,8080,8443,8888,3000,4000,5000 -o httpx-out.txt
httpx -l hosts.txt -tech-detect -title -status-code -o httpx-full.txt
```

## Technology Fingerprinting

```bash
# Web tech stack
whatweb -a 3 https://target.com
wappalyzer --url https://target.com

# CMS detection
cmseek -u https://target.com
wpscan --url https://target.com --enumerate  # WordPress
droopescan scan drupal -u https://target.com

# Header analysis
curl -I https://target.com
# Look for: Server, X-Powered-By, X-Generator, X-Framework

# Favicon hash
# Calculate favicon hash → search in Shodan/Censys for similar infra
python3 -c "import hashlib,base64,requests; r=requests.get('https://target.com/favicon.ico'); print(hashlib.md5(base64.encodebytes(r.content)).hexdigest())"
```

## URL / Endpoint Discovery

```bash
# Crawling
katana -u https://target.com -d 5 -jc -o katana-out.txt
gospider -s https://target.com -d 3 -o spider-out

# Historical URLs
gau --threads 5 target.com | tee gau-out.txt
waybackurls target.com | tee wayback-out.txt
hakrawler -url https://target.com -depth 3

# Combine and deduplicate
cat gau-out.txt wayback-out.txt katana-out.txt | sort -u | httpx -silent -o live-endpoints.txt

# Parameter extraction
cat live-endpoints.txt | grep "?" | qsreplace "FUZZ" | sort -u > params.txt

# JS file discovery
cat live-endpoints.txt | grep "\.js$" | sort -u > jsfiles.txt
```

## JavaScript Analysis

```bash
# Extract endpoints and secrets from JS
cat jsfiles.txt | xargs -I{} curl -s {} | grep -oP '(\/api\/[^"' ]+)|(\/v[0-9]+\/[^"' ]+)'
subjs -i live-endpoints.txt -o jsfiles.txt
getjswords jsfiles.txt  # Extract potential params

# Secrets in JS
truffleHog --regex --entropy=False https://github.com/target/repo
secretfinder -i https://target.com/app.js -o cli

# LinkFinder for endpoints
python3 linkfinder.py -i https://target.com/app.js -o cli

# Manual JS analysis patterns
grep -E "(api_key|apikey|secret|token|password|passwd|auth|bearer)" *.js
grep -E "fetch\(|axios\.|XMLHttpRequest|\.ajax\(" *.js
grep -E "(\/api\/|\/v1\/|\/v2\/|\/internal\/|\/admin\/)" *.js
```

## Directory / File Fuzzing

```bash
# Directory brute force
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200,301,302,403 -o ffuf-dirs.txt

# Wordlists
# /usr/share/seclists/Discovery/Web-Content/big.txt
# /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
# /usr/share/seclists/Discovery/Web-Content/common.txt

# API endpoint fuzzing
ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Parameter fuzzing
ffuf -u https://target.com/search?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Backup file hunting
ffuf -u https://target.com/FUZZ -w backups.txt  # .bak, .old, .zip, .tar.gz, .sql
```

## Source Code & Git Exposure

```bash
# Git repo exposure
git-dumper https://target.com/.git/ /tmp/git-dump
# Check: /.git/config, /.git/HEAD, /.git/COMMIT_EDITMSG

# Common source code exposure
ffuf -u https://target.com/FUZZ -w source_exposure.txt
# Paths: /.env, /.env.local, /config.php, /config.yml, /wp-config.php.bak
# /app.config, /web.config, /appsettings.json, /.htpasswd, /phpinfo.php

# SVN
/.svn/entries → reveals source structure and file paths

# DS_Store
.DS_Store parser: python3 dsstore.py https://target.com/.DS_Store
```

## Cloud Asset Discovery

```bash
# S3 bucket enumeration
S3Scanner scan --buckets target-backup,target-dev,target-prod,target-assets
# Patterns: [company]-[env], [company]-[service], [company]-[year]
aws s3 ls s3://target-assets --no-sign-request

# Google Cloud Storage
gsutil ls gs://target-backup

# Azure Blob
az storage blob list --container-name target --account-name targetstg

# Google Dorks for cloud assets
site:s3.amazonaws.com "target.com"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
```

## Leaked Credentials & Secrets

```bash
# GitHub dork
org:targetcompany password OR secret OR api_key OR token

# Manual dorks
"target.com" API_KEY
"target.com" password filetype:env
"@target.com" password

# Shodan for exposed services
org:"Target Company" port:22,3306,5432,6379,27017,9200

# Pastebin / ghostbin
site:pastebin.com target.com

# Historical commits
truffleHog --entropy=True https://github.com/target/repo
gitleaks detect --source /path/to/repo
```

## ASN / IP Range Discovery

```bash
# Find ASN
whois -h whois.radb.net -- '-i origin AS12345' | grep route:
amass intel -org "Target Corp"

# IP range from ASN
bgpview.io API or:
whois -h whois.arin.net "n + Target Corp"

# Reverse IP lookup (find more domains on same IP)
shodan host IP
```

## Google Dorks for Bug Bounty

```
site:target.com filetype:pdf  # PDFs (may contain internal info)
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:api
site:target.com ext:env OR ext:bak OR ext:sql OR ext:log
site:target.com intext:"internal use only"
site:target.com intitle:"index of"
"target.com" inurl:"/wp-content/uploads/"
"api.target.com" OR "dev.target.com" OR "staging.target.com"
```

## Recon Automation Stack

```bash
# Full pipeline example
subfinder -d target.com | dnsx | httpx -o live.txt
cat live.txt | katana -jc | grep "\.js$" | subjs | secretfinder
cat live.txt | gau | qsreplace "FUZZ" | ffuf -u FUZZ -w payloads.txt
```

## Pro Tips

1. Run recon in stages: passive → active → deep-dive on interesting assets
2. Focus on dev/staging/internal subdomains — less hardened, more bugs
3. Check `robots.txt`, `sitemap.xml`, `.well-known/` on every discovered host
4. Wayback Machine URLs reveal old endpoints that still work
5. JS files are goldmines — new endpoints, API keys, internal comments
6. Alert on new subdomains — fresh deployments often have bugs before security review
7. Check ASN for entire IP ranges — find forgotten test servers and admin panels
8. `.git` exposure + source code = automatic high severity bug
9. CloudFront/Akamai custom error pages often leak internal domain names

## Summary

Recon multiplies bug-finding efficiency. Subdomain enumeration finds forgotten assets, JS analysis reveals undocumented APIs, and cloud bucket scanning surfaces data exposures. Build an automated pipeline and run it continuously — the best bugs are found on newly-deployed assets.
