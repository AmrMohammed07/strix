---
name: web-recon
description: Exhaustive web reconnaissance — documentation reading, JS analysis, subdomain enumeration, technology fingerprinting, endpoint mapping, attack surface construction — mandatory first phase before all vulnerability testing
---

# Web Reconnaissance — Complete Attack Surface Construction

Reconnaissance is the foundation of every successful security assessment. The quality of your recon determines the quality of your entire scan. An endpoint missed during recon is an endpoint that never gets tested. Read all documentation before touching any vulnerability test.

**CRITICAL RULE: DO NOT BEGIN VULNERABILITY TESTING UNTIL RECON IS COMPLETE.**

---

## Mandatory Recon Checklist

```
[ ] Documentation read (all API specs, Swagger, OpenAPI, GraphQL schema, help pages)
[ ] robots.txt and sitemap.xml parsed — every disallowed path is a target
[ ] All JS files downloaded and analyzed
[ ] API endpoints extracted from JS bundles
[ ] Secrets/API keys searched in JS
[ ] Subdomain enumeration completed
[ ] Port scanning completed on all live hosts
[ ] Technology stack identified
[ ] WAF/CDN/proxy detected
[ ] Authentication mechanisms identified
[ ] Endpoint checklist created at /workspace/endpoint_checklist.md
[ ] Recon report saved to /workspace/recon_report.md
```

---

## Phase 1: Documentation & API Specification Discovery

### Try All Documentation Paths
```bash
TARGET="https://target.com"

DOC_PATHS=(
    "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
    "/swagger-ui.html" "/swagger-ui/" "/swagger-ui/index.html"
    "/api-docs" "/api-docs.json" "/api/docs" "/api/documentation"
    "/openapi.json" "/openapi.yaml" "/openapi" "/api/openapi.json"
    "/v1/docs" "/v2/docs" "/v3/docs" "/api/v1/docs" "/api/v2/docs"
    "/redoc" "/redoc/" "/redoc/index.html"
    "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server"
    "/graphql" "/graphiql" "/graphql/playground" "/api/graphql"
    "/docs" "/documentation" "/developer/docs" "/api/schema" "/api/spec"
    "/api/explorer" "/api/console" "/api/health" "/api/status" "/api/version"
)

mkdir -p /workspace/docs
for path in "${DOC_PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 5 "${TARGET}${path}")
    if [[ "$status" == "200" ]]; then
        echo "[FOUND] ${TARGET}${path}"
        filename=$(echo "$path" | tr '/' '_' | tr '?' '_').json
        curl -s -L "${TARGET}${path}" -o "/workspace/docs/${filename}"
    fi
done
```

### Parse OpenAPI/Swagger Specification
```python
import json, yaml, requests

def parse_api_spec(spec_url):
    r = requests.get(spec_url, timeout=15)
    try:
        spec = yaml.safe_load(r.text)
    except:
        spec = r.json()
    
    info = spec.get("info", {})
    print(f"API: {info.get('title')} v{info.get('version')}")
    
    base_path = ""
    if "servers" in spec:
        base_path = spec["servers"][0].get("url", "").rstrip("/")
    elif "basePath" in spec:
        base_path = spec.get("basePath", "")
    
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method not in ["get","post","put","patch","delete","head","options"]:
                continue
            
            params = details.get("parameters", []) + methods.get("parameters", [])
            body = details.get("requestBody", {}).get("content", {})
            body_fields = []
            for ct, sw in body.items():
                if "properties" in sw.get("schema", {}):
                    body_fields = list(sw["schema"]["properties"].keys())
            
            ep = {
                "method": method.upper(),
                "url": f"{base_path}{path}",
                "summary": details.get("summary", ""),
                "parameters": [f"{p.get('in')}.{p.get('name')}" for p in params],
                "body_fields": body_fields,
                "auth_required": bool(details.get("security", spec.get("security", []))),
                "deprecated": details.get("deprecated", False)
            }
            endpoints.append(ep)
            print(f"  {ep['method']} {ep['url']} — {ep['summary']}")
    
    return endpoints
```

### GraphQL Introspection
```python
def graphql_introspect(graphql_url, session_cookie=None):
    introspection_query = {"query": """
    { __schema {
        queryType { name } mutationType { name } subscriptionType { name }
        types {
            name kind
            fields { name args { name } type { name kind } }
        }
    } }"""}
    
    headers = {"Content-Type": "application/json"}
    if session_cookie:
        headers["Cookie"] = f"session={session_cookie}"
    
    r = requests.post(graphql_url, json=introspection_query, headers=headers)
    if r.status_code == 200 and "data" in r.json():
        schema = r.json()["data"]["__schema"]
        with open("/workspace/graphql_schema.json", "w") as f:
            json.dump(schema, f, indent=2)
        print("GraphQL introspection ENABLED — full schema saved")
        return schema
    return None
```

### Read Application Documentation
```python
# Also navigate to and read:
# /help, /help-center, /docs, /faq, /pricing, /plans
# These pages reveal features, limits, business rules that automated scanning misses
help_paths = ["/help", "/help-center", "/faq", "/pricing", "/plans", "/features",
              "/about", "/support", "/guide", "/tutorial", "/getting-started"]

for path in help_paths:
    r = requests.get(f"https://target.com{path}", timeout=10)
    if r.status_code == 200:
        print(f"Documentation page found: {path}")
        # Save for manual review
        with open(f"/workspace/docs/page_{path.replace('/','_')}.html", "w") as f:
            f.write(r.text)
```

---

## Phase 2: JavaScript Analysis

```bash
#!/bin/bash
mkdir -p /workspace/js_files /workspace/js_deobfuscated

# Discover all JS files
katana -u https://target.com -jc -d 5 -o /workspace/katana_output.txt 2>/dev/null
grep -E "\.js($|\?)" /workspace/katana_output.txt | sort -u > /workspace/js_urls.txt

# Download all JS files
while IFS= read -r url; do
    filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
    curl -s --max-time 30 "$url" -o "/workspace/js_files/${filename}" 2>/dev/null
done < /workspace/js_urls.txt

# Deobfuscate
for f in /workspace/js_files/*.js; do
    js-beautify "$f" -o "/workspace/js_deobfuscated/$(basename $f)" 2>/dev/null
done

echo "JS files downloaded: $(ls /workspace/js_files/*.js 2>/dev/null | wc -l)"
```

```python
import re, os, json

def analyze_js_files(js_dir="/workspace/js_deobfuscated"):
    results = {"api_endpoints": set(), "secrets": [], "websocket_urls": set(),
               "internal_urls": set(), "interesting_comments": []}
    
    patterns = {
        "api_endpoints": [
            r'["\x27](/(?:api|v\d+|rest|graphql)[^"\x27\s\)]{3,100})["\x27]',
            r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\x27]([^"\x27\s]{10,150})["\x27]',
            r'(?:baseURL|apiUrl|API_URL|endpoint|BASE_URL)\s*[:=]\s*["\x27]([^"\x27]{5,100})["\x27]',
        ],
        "secrets": [
            r'(?:api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key|auth[_-]?token)\s*[:=]\s*["\x27]([A-Za-z0-9+/=_\-]{16,100})["\x27]',
            r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\x27]([A-Za-z0-9+/=]{16,})["\x27]',
            r'(?:STRIPE_|TWILIO_|SENDGRID_|FIREBASE_)[A-Z_]+\s*[:=]\s*["\x27]([^"\x27]{16,})["\x27]',
        ],
        "websocket_urls": [
            r'(?:ws|wss)://[^\s"\']{5,100}',
            r'new WebSocket\(["\x27]([^"\x27]{5,100})["\x27]\)',
        ],
        "internal_urls": [
            r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\']{0,100}',
        ]
    }
    
    for filename in os.listdir(js_dir):
        if not filename.endswith(".js"):
            continue
        
        with open(os.path.join(js_dir, filename), 'r', errors='ignore') as f:
            content = f.read()
        
        for cat, pats in patterns.items():
            for pat in pats:
                matches = re.findall(pat, content, re.IGNORECASE)
                for m in matches:
                    val = m if isinstance(m, str) else m[0]
                    if cat == "api_endpoints":
                        results["api_endpoints"].add(val)
                    elif cat == "secrets":
                        results["secrets"].append({"value": val[:50], "file": filename})
                    elif cat == "websocket_urls":
                        results["websocket_urls"].add(val)
                    elif cat == "internal_urls":
                        results["internal_urls"].add(val)
    
    print(f"\nJS Analysis: {len(results['api_endpoints'])} endpoints, "
          f"{len(results['secrets'])} potential secrets, "
          f"{len(results['websocket_urls'])} WebSocket URLs")
    
    if results["secrets"]:
        print("[!] POTENTIAL SECRETS FOUND — review /workspace/js_analysis_results.json")
    
    with open("/workspace/js_analysis_results.json", "w") as f:
        json.dump({k: list(v) if isinstance(v, set) else v for k, v in results.items()}, f, indent=2)
    
    return results
```

---

## Phase 3: Subdomain Enumeration

```bash
DOMAIN="target.com"

# Passive enumeration
subfinder -d $DOMAIN -all -recursive -o /workspace/subdomains_passive.txt 2>/dev/null

# Active brute force (download wordlist if needed)
[ ! -f /home/pentester/tools/wordlists/subdomains.txt ] && \
    curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
    -o /home/pentester/tools/wordlists/subdomains.txt

ffuf -u "https://FUZZ.$DOMAIN" \
    -w /home/pentester/tools/wordlists/subdomains.txt \
    -mc 200,204,301,302,307,403 -ac \
    -o /workspace/subdomains_active.json -of json 2>/dev/null

# Combine and resolve
cat /workspace/subdomains_passive.txt 2>/dev/null \
    <(cat /workspace/subdomains_active.json 2>/dev/null | python3 -c "import sys,json; [print(r['input']['FUZZ']+'.'"$DOMAIN"') for r in json.load(sys.stdin).get('results',[])]") \
    | sort -u > /workspace/all_subdomains.txt

# Probe for live hosts
httpx -l /workspace/all_subdomains.txt \
    -title -tech-detect -status-code -follow-redirects \
    -o /workspace/live_subdomains.txt 2>/dev/null

echo "Live subdomains: $(wc -l < /workspace/live_subdomains.txt)"
```

---

## Phase 4: Port Scanning

```bash
# Fast port scan on all live hosts
awk '{print $1}' /workspace/live_subdomains.txt 2>/dev/null | \
    sort -u > /workspace/live_ips.txt

naabu -iL /workspace/live_ips.txt \
    -top-ports 1000 \
    -o /workspace/open_ports.txt 2>/dev/null

# Service detection on interesting ports
nmap -sV --open -iL /workspace/live_ips.txt \
    -p 21,22,23,25,80,443,3000,3306,5000,5432,6379,8080,8443,8888,9000,9200,27017 \
    -oN /workspace/nmap_services.txt 2>/dev/null

echo "Non-standard open ports:"
grep "open" /workspace/nmap_services.txt | grep -v "http\|https\|ssh"
```

---

## Phase 5: Technology Fingerprinting

```bash
# WAF detection
wafw00f https://target.com -a 2>/dev/null

# Technology stack
httpx -u https://target.com -tech-detect -title -server -status-code

# Vulnerable JS libraries
retire --js --jspath /workspace/js_files/ \
    --outputformat json --outputpath /workspace/vulnerable_libraries.json 2>/dev/null

# Common sensitive files
SENSITIVE_PATHS=(
    "/.git/config" "/.git/HEAD" "/.env" "/.env.local" "/.env.production"
    "/config.json" "/settings.json" "/appsettings.json" "/web.config"
    "/phpinfo.php" "/server-status" "/server-info" "/actuator/env"
    "/backup.zip" "/db.sql" "/database.sql" "/.DS_Store"
    "/robots.txt" "/crossdomain.xml" "/security.txt" "/.well-known/security.txt"
)

echo "Checking sensitive paths..."
for path in "${SENSITIVE_PATHS[@]}"; do
    status=$(curl -s -o /tmp/resp -w "%{http_code}" -L --max-time 5 "https://target.com${path}")
    if [[ "$status" == "200" ]]; then
        size=$(wc -c < /tmp/resp)
        echo "[FOUND $size bytes] https://target.com${path}"
    elif [[ "$status" == "403" ]]; then
        echo "[403 Forbidden] https://target.com${path} (exists but blocked)"
    fi
done
```

---

## Phase 6: robots.txt and Sitemap Parsing

```python
def parse_robots_and_sitemap(base_url):
    discovered = []
    
    # robots.txt
    r = requests.get(f"{base_url}/robots.txt")
    if r.status_code == 200:
        print("robots.txt:")
        for line in r.text.split('\n'):
            print(f"  {line}")
            # Disallowed paths are HIGH PRIORITY targets
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    discovered.append(f"[robots-disallowed] {base_url}{path}")
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                # Parse sitemap recursively
                discovered.extend(parse_sitemap(sitemap_url))
    
    # Sitemap
    for sitemap_url in [f"{base_url}/sitemap.xml", f"{base_url}/sitemap_index.xml"]:
        r = requests.get(sitemap_url)
        if r.status_code == 200:
            discovered.extend(parse_sitemap(sitemap_url))
    
    return discovered

def parse_sitemap(sitemap_url, depth=0):
    if depth > 3:
        return []
    
    urls = []
    r = requests.get(sitemap_url, timeout=10)
    if r.status_code != 200:
        return []
    
    # Extract all URLs
    import re
    urls_in_sitemap = re.findall(r'<loc>([^<]+)</loc>', r.text)
    
    for url in urls_in_sitemap:
        if ".xml" in url.lower():
            # Nested sitemap
            urls.extend(parse_sitemap(url, depth+1))
        else:
            urls.append(url)
    
    return urls
```

---

## Phase 7: Build the Endpoint Checklist

```python
def build_endpoint_checklist():
    """Compile ALL discovered endpoints into the tracking checklist"""
    
    all_endpoints = []
    
    # From API spec parsing
    if os.path.exists("/workspace/api_endpoints.json"):
        with open("/workspace/api_endpoints.json") as f:
            spec_endpoints = json.load(f)
            for ep in spec_endpoints:
                all_endpoints.append(f"- [ ] {ep['method']} {ep['url']} — {ep.get('summary','')}")
    
    # From JS analysis
    if os.path.exists("/workspace/js_analysis_results.json"):
        with open("/workspace/js_analysis_results.json") as f:
            js_results = json.load(f)
            for endpoint in js_results.get("api_endpoints", []):
                all_endpoints.append(f"- [ ] GET https://target.com{endpoint} [from JS]")
    
    # From crawling
    if os.path.exists("/workspace/katana_output.txt"):
        with open("/workspace/katana_output.txt") as f:
            for line in f:
                url = line.strip()
                if url:
                    all_endpoints.append(f"- [ ] GET {url} [from crawl]")
    
    # Deduplicate
    all_endpoints = list(dict.fromkeys(all_endpoints))
    
    with open("/workspace/endpoint_checklist.md", "w") as f:
        f.write("# Endpoint Coverage Checklist\n")
        f.write("# Status: [ ] pending | [~] in-progress | [x] tested | [!] vuln-found | [s] skipped\n\n")
        
        categories = {
            "## Authentication Endpoints": [e for e in all_endpoints if any(k in e for k in ["/login","/register","/auth","/oauth","/reset","/verify"])],
            "## Admin Endpoints": [e for e in all_endpoints if any(k in e for k in ["/admin","/manage","/internal","/staff","/superadmin"])],
            "## API Endpoints": [e for e in all_endpoints if "/api/" in e],
            "## Public Pages": [e for e in all_endpoints if "/api/" not in e and not any(k in e for k in ["/login","/admin"])],
        }
        
        written = set()
        for cat_name, cat_endpoints in categories.items():
            unique = [e for e in cat_endpoints if e not in written]
            if unique:
                f.write(f"{cat_name}\n\n")
                for ep in sorted(unique):
                    f.write(f"{ep}\n")
                    written.add(ep)
                f.write("\n")
        
        # Remaining
        remaining = [e for e in all_endpoints if e not in written]
        if remaining:
            f.write("## Other Endpoints\n\n")
            for ep in sorted(remaining):
                f.write(f"{ep}\n")
    
    print(f"Endpoint checklist created: /workspace/endpoint_checklist.md")
    print(f"Total endpoints: {len(all_endpoints)}")
```

---

## Recon Report Template

Save to `/workspace/recon_report.md`:

```markdown
# Recon Report — TARGET — TIMESTAMP

## Technology Stack
- Frontend: [React/Vue/Angular/etc.]
- Backend: [Node.js/Python/PHP/Java/etc.]
- Framework: [Express/Django/Laravel/etc.]
- Database: [inferred]
- Infrastructure: [AWS/GCP/Azure/etc.]
- CDN/WAF: [Cloudflare/AWS WAF/etc.]
- Auth mechanism: [JWT/session/OAuth]

## Documentation Found
- API spec: [URLs and endpoint count]
- GraphQL: [introspection enabled/disabled]
- Help pages: [list]

## Key JS Analysis Findings
- API endpoints from JS: [N]
- Potential secrets: [describe — do NOT include actual secret values in report]
- WebSocket URLs: [list]
- Internal URLs: [list]

## Subdomain Inventory
[List all live subdomains with status/tech]

## Attack Surface Priorities
1. [Most interesting — explain why]
2. [Second priority]
3. [Third priority]

## Endpoint Checklist
Created: /workspace/endpoint_checklist.md
Total endpoints: [N]
```


## Additional Techniques — ported from WebSkills (web2-recon)

Recon exists to decide **what to test first** and **whether the target is worth time at all**. After the endpoint checklist is built, run this prioritization layer.

### Target Scoring — Go / No-Go (score before spending time)

| Criterion | Points |
|---|---|
| Large user base (>100K) or handles money/PII | +2 |
| Complex features: API, OAuth, file upload, GraphQL, multi-tenancy | +1 |
| Recent code/feature changes (new endpoints in JS diff, changelog) | +1 |
| Tech stack with a known-CVE footgun (see `framework_1day_rce.md`) | +1 |
| Source code / API docs available | +1 |
| Admin / internal / debug surface reachable | +1 |

**Pre-dive hard kill signals** (skip the host, 5-minute rule):
1. Scope is only a static marketing page — no forms, no auth, no user data.
2. All subdomains return 403 / static pages; no API endpoints in URLs or JS.
3. No JavaScript bundles with interesting endpoint paths.
4. Automated template scan returns 0 medium/high; no anomalies in headers/timing.

### Stack → Primary Bug-Class Routing

Once fingerprinting identifies the stack, hunt these first (highest hit-rate per stack):

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (`mark_safe`) |
| Flask | SSTI (`render_template_string`) | SSRF (requests lib) |
| Laravel | Mass assignment (`$fillable`) | IDOR (Eloquent, no ownership) |
| Express / Node | Prototype pollution | Path traversal + `/_debug` surface |
| Spring Boot | Actuator endpoints (`/actuator/*`) → `framework_1day_rce.md` | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (`ReturnUrl`) |
| Next.js | SSRF via Server Actions + `/_next/data/` leak | Open redirect via `redirect()` |
| GraphQL | Introspection → auth bypass on mutations | IDOR via `node(id:)` |
| WordPress | Plugin SQLi | REST API auth bypass (`/wp-json/`) |
| SPA (React/Vue/Angular) | DOM XSS via state/router sinks | Client-side route auth bypass (role check only in JS) |

### URL Triage — Classify the Crawl/Archive Output

```bash
# Params worth testing
grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" urls.txt
# API / upload / admin / auth surfaces
grep -E "/api/|/v[0-9]/|/graphql|/rest/" urls.txt
grep -E "upload|file|attachment|avatar|import" urls.txt
grep -E "/admin|/internal|/debug|/staging|/console" urls.txt
grep -E "/oauth|/login|/sso|/saml|/callback|/token" urls.txt

# gf pattern classification (tomnomnom/gf)
cat urls.txt | gf ssrf     # then route to ssrf.md
cat urls.txt | gf idor     # then route to idor.md
cat urls.txt | gf redirect # then route to open_redirect.md
cat urls.txt | gf sqli | gf xss | gf lfi | gf rce
```

### Post-Triage Priority Order
1. API endpoints with ID params → IDOR/BOLA.
2. File-upload features → XSS/RCE.
3. OAuth/SSO flows → auth-bypass / redirect_uri abuse.
4. Search/filter/sort with user input → SQLi/SSRF/SSTI.
5. Admin/debug endpoints → auth bypass + error-disclosure chains.
