---
name: api-key-exposure
description: API key and secret exposure detection — finding leaked credentials in JS, repos, responses, and cloud metadata
---

# API Key / Secret Exposure

API keys, tokens, and secrets found in client-side code, public repositories, error messages, or misconfigured cloud services represent immediate, high-severity findings in bug bounty. The impact depends on what the key controls — AWS keys can mean full account compromise.

## Where Secrets Hide

### JavaScript Files

```javascript
// Hardcoded in source:
const API_KEY = "sk-ant-api03-xxxxx";
var config = { apiKey: "AIzaSyXXXXXXXXXXX" };
window._env = { STRIPE_KEY: "pk_live_XXXXX" };
axios.defaults.headers['Authorization'] = 'Bearer eyJXXXX';

// In minified JS: search for patterns
// In source maps (.js.map): original source with comments
```

### Git Repositories

```bash
# In current code
grep -r "api_key\|apikey\|secret\|password\|token\|bearer" --include="*.js,*.py,*.env,*.json"

# In git history (deleted files still in history)
git log --all --full-history -- "*.env"
git show COMMIT_HASH:path/to/file
truffleHog --regex --entropy=True /path/to/repo
gitleaks detect --source . --verbose
```

### Configuration Files Exposed on Web

```
# Common paths to check:
/.env
/.env.local
/.env.production
/.env.backup
/config.php
/config.yml
/config.json
/appsettings.json
/web.config
/application.properties
/application.yml
/docker-compose.yml
/Dockerfile
/.aws/credentials
/.ssh/id_rsa
/wp-config.php
/wp-config.php.bak
/settings.py
/local_settings.py
/database.yml
/secrets.yml
```

### HTTP Responses

```
# Error responses leaking env vars or config:
HTTP 500: {"error": "...", "env": {"DATABASE_URL": "postgres://user:pass@host/db"}}

# Debug mode enabled:
Django debug=True → full settings in error page
Laravel APP_DEBUG=true → stack trace with env vars

# API responses:
{"user": {"stripe_secret_key": "sk_live_XXXX"}}  # Accidental field inclusion
X-Debug-Token response header → Symfony profiler

# OAuth token in response body when should be code-only
# JWT payload containing internal config
```

### Cloud Metadata Services

```bash
# AWS IMDS (from SSRF or compromised server)
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
→ AccessKeyId, SecretAccessKey, Token

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
→ Bearer token for GCP APIs

# Azure
http://169.254.169.254/metadata/identity/oauth2/token
→ MSI token

# Kubernetes secrets
/var/run/secrets/kubernetes.io/serviceaccount/token
```

### Browser Storage

```javascript
// Check in DevTools console:
localStorage.getItem('token')
sessionStorage.getItem('apiKey')
document.cookie  // Auth cookies
indexedDB // May contain cached credentials
```

## High-Value Key Types

| Key Pattern | Service | Impact |
|-------------|---------|--------|
| `AKIA[A-Z0-9]{16}` | AWS Access Key | Full AWS account access |
| `sk-ant-api03-` | Anthropic | LLM API access, billing |
| `sk-[a-zA-Z0-9]{48}` | OpenAI | AI API, billing |
| `AIzaSy[0-9A-Za-z-_]{33}` | Google API | Maps, GCP, Firebase |
| `gh[pousr]_[A-Za-z0-9_]{36,}` | GitHub | Repository access, org |
| `glpat-[0-9a-zA-Z-]{20}` | GitLab | Code, CI/CD |
| `sk_live_[0-9a-zA-Z]{24}` | Stripe | Payment processing |
| `rk_live_[0-9a-zA-Z]{24}` | Stripe Restricted | Limited payment access |
| `SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}` | SendGrid | Email sending |
| `xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}` | Slack Bot | Slack workspace access |
| `[0-9]{15,16}:[a-zA-Z0-9_-]{35}` | Telegram Bot | Bot control |
| `EAACEdEose0cBA[0-9A-Za-z]+` | Facebook | FB/Instagram access |
| `[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}` | Various UUIDs | Context-dependent |

## Verification (Without Causing Harm)

```bash
# AWS key - check identity only (read-only, no damage)
aws sts get-caller-identity --access-key-id AKIAXXXX --secret-access-key XXXX
# Shows: Account, UserId, ARN → proves validity

# GitHub token
curl -H "Authorization: token ghp_XXXX" https://api.github.com/user
# Shows: username, email, org memberships

# Stripe key (test mode only)
curl https://api.stripe.com/v1/balance -u sk_test_XXXX:
# Shows: available balance → proves validity

# Google API key
curl "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=TOKEN"

# Slack token
curl -H "Authorization: Bearer xoxb-XXXX" https://slack.com/api/auth.test
```

**IMPORTANT**: Verify existence and scope only — do NOT:
- Make purchases, send emails, or take actions
- Access production data beyond what proves the key works
- Use keys to access systems beyond demonstrating the finding

## OSINT / Automated Secret Scanning

```bash
# TruffleHog (supports many sources)
trufflehog git https://github.com/target/repo
trufflehog github --org targetorg --token GITHUB_TOKEN
trufflehog s3 --bucket target-bucket

# Gitleaks
gitleaks detect --source /path/to/repo -v
gitleaks detect --source /path/to/repo --report-path leaks.json

# Git-secrets
git secrets --scan

# GitHub Advanced Search (manual)
# site:github.com "target.com" "api_key"
# site:github.com "target.com" "password"
# Push protection alerts in target's public repos

# Google Dorks
site:github.com "target.com" password
site:gitlab.com "target.com" secret_key
site:pastebin.com "target.com" api
```

## Testing Methodology

1. **Spider all JS files** — katana/gospider → grep for key patterns
2. **Check common config paths** — ffuf with config-file wordlist
3. **Analyze git history** — Clone public repos, run truffleHog
4. **Test error responses** — Trigger 500 errors, check for env leakage
5. **Check localStorage/cookies** — DevTools inspection
6. **SSRF to metadata** — If SSRF exists, fetch cloud metadata
7. **Source maps** — Check for `.js.map` files with original commented source
8. **Third-party integrations** — Check requests to analytics, CDN, payment with exposed keys

## Validation

1. Identify the exact location where the key was found (URL, file, commit hash)
2. Verify the key is valid using a read-only API call (as above)
3. Determine the scope/permissions of the key
4. Document the potential impact (what the attacker could do with it)
5. Report and recommend immediate rotation

## False Positives

- Test/sandbox keys (not production) — verify environment
- Already-rotated keys (verify they're invalid before reporting)
- Public keys (asymmetric crypto) — not secret by design
- API keys for public/free-tier services with no sensitive access

## Impact

- AWS keys: full account compromise, data theft, cryptomining, denial of service
- Payment keys: financial fraud, customer data theft
- OAuth tokens: impersonation, account access across integrated services
- CI/CD tokens: supply chain compromise, code modification

## Pro Tips

1. AWS key finding = automatic critical if it has any IAM permissions — test with `sts:GetCallerIdentity` first
2. Source maps (`.js.map`) are the best-kept secret for exposed source code — always check
3. GitHub secret scanning for public repos is automated — focus on private repos and git history
4. `Authorization: Bearer` tokens in XHR requests during normal browsing are often JWTs — decode them
5. Check all third-party script domains in network tab — keys passed as URL params to analytics
6. `.env` exposure + RCE = double report or combine for critical severity
7. Commit history is permanent until force-pushed — old deleted secrets may still be there
8. Many companies have bug bounty bonuses for CI/CD or cloud key findings

## Summary

Secret exposure is often the highest-impact finding relative to effort. Scan JS files, check common config paths, mine git history, and verify before reporting. Rotate immediately on confirmation — the window between discovery and exploitation can be minutes.
