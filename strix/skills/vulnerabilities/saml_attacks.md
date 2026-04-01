---
name: saml-attacks
description: SAML authentication attack techniques including signature wrapping, XML injection, and SSO bypass
---

# SAML Attacks

SAML (Security Assertion Markup Language) is widely used for enterprise SSO. Its XML-based structure, complex signature validation, and multiple processing paths create a rich attack surface. Signature wrapping, parser differentials, and broken XML canonicalization have led to critical authentication bypass vulnerabilities in major platforms.

## Attack Surface

**SAML Flow Components**
- SP-initiated SSO: SP redirects to IdP, IdP returns signed assertion
- IdP-initiated SSO: IdP pushes assertion directly to SP
- Assertion Consumer Service (ACS) endpoint at SP
- Attribute statements, NameID, session index
- XML Digital Signatures (XMLDSig) and Encryption (XMLEnc)

**Protocols**
- SAML 2.0 (HTTP-POST, HTTP-Redirect, Artifact bindings)
- WS-Federation (used by Azure AD, ADFS)

**Input Vectors**
- `SAMLResponse` POST parameter (base64-encoded XML)
- `RelayState` parameter
- `SAMLRequest` parameter
- HTTP-Redirect binding with deflate+base64 encoding

## Key Vulnerabilities

### XML Signature Wrapping (XSW)

The IdP signs a specific XML element, but the SP processes a different element. The attacker injects an unsigned copy of the assertion with modified attributes (e.g., different username/role) and moves the signed element to an irrelevant location that still validates.

**XSW Variants**
```xml
<!-- XSW1: Insert malicious assertion before signed one -->
<samlp:Response>
  <saml:Assertion>MALICIOUS_ADMIN_ASSERTION</saml:Assertion>
  <saml:Assertion ID="signed_id">LEGITIMATE_ASSERTION<ds:Signature.../></saml:Assertion>
</samlp:Response>

<!-- XSW2: Clone signed assertion, inject modified unsigned copy -->
<!-- XSW3-8: Various placements exploiting XPath reference resolution -->
```

**Tool**: `SAMLReQuest`, `esaml`, `saml-raider` (Burp plugin)

### Comment Injection (CVE-2018-0489 / Duo / OneLogin)

XML comments can split attribute values in some parsers:
```xml
<saml:NameID>admin<!--comment-->@evil.com</saml:NameID>
<!-- Some SPs read: admin, others read: admin@evil.com -->

<saml:NameID>victim@corp.com<!---->@attacker.com</saml:NameID>
```

### XML External Entity (SAML XXE)

Many SAML parsers process XML with external entities enabled:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>
  <saml:Issuer>&xxe;</saml:Issuer>
  ...
</samlp:Response>
```

### Signature Exclusion / No Validation

- Remove the `<ds:Signature>` element entirely — some SPs accept unsigned assertions
- Modify the assertion, re-encode, submit without signature
- Test with `schemaValidation=false` headers or params

### Algorithm Confusion

- Downgrade signing algorithm: replace `SHA256` with `SHA1` or `MD5`
- Change `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256">` to weaker variant
- Some SPs accept attacker-specified algorithms

### XML Canonicalization Attacks

- Exploit differences between what is canonicalized/signed and what is processed
- Insert namespace declarations that change canonical form
- Test with `xml:space` and `xml:lang` attribute injection

### SAML Replay

- Capture a valid SAMLResponse, replay it
- Test if `NotOnOrAfter` and `InResponseTo` conditions are validated
- Some SPs accept expired or reused assertions

### Redirect Binding Bypass

- SAML HTTP-Redirect uses URL-encoded deflated XML
- Decode: `zlib.decompress(base64.decode(param), -8)`
- Modify and re-encode: often unsigned in redirect binding (only signed in POST)
- RelayState not always validated — test for open redirect

### NameID Manipulation

```xml
<!-- Try admin values -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
  admin
</saml:NameID>

<!-- Format confusion -->
<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
  admin@corp.com
</saml:NameID>
```

### Attribute Statement Manipulation

```xml
<!-- Inject admin role/group -->
<saml:AttributeStatement>
  <saml:Attribute Name="Role">
    <saml:AttributeValue>administrator</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

## Bypass Techniques

**Base64 / Encoding Tricks**
- URL encode the `SAMLResponse` value
- Double base64 encode
- Add padding (`=`) or remove it
- Try URL-safe base64 variants

**XML Encoding**
- `&amp;`, `&lt;`, `&gt;` — test if SP unescapes before signature check
- Unicode normalization in attribute values
- Null bytes in NameID

**HTTP Parameter Pollution**
```
SAMLResponse=ORIGINAL&SAMLResponse=MODIFIED
```
Some parsers use first, some use last.

**Whitespace in Assertions**
- Add/remove whitespace around XML elements after signature (changes hash but some SPs don't re-validate)

## Testing Methodology

1. **Capture SAMLResponse** — Use Burp or browser devtools to intercept the POST
2. **Decode** — `echo SAML_BASE64 | base64 -d | xmllint --format -`
3. **Identify signed elements** — Check `ds:Signature` and `Reference URI` attribute
4. **Test signature removal** — Delete `<ds:Signature>` block, re-encode, submit
5. **Test XSW** — Use saml-raider Burp plugin to auto-generate XSW variants
6. **Test comment injection** — Insert `<!---->` in NameID/email values
7. **Test XXE** — Add DOCTYPE declaration with external entity
8. **Test replay** — Resubmit captured response after delay
9. **Test attribute injection** — Modify role/group attributes if signed at response level not assertion
10. **Test redirect binding** — Decode-modify-encode unsigned redirect SAMLRequest/Response

## Validation

1. Demonstrate successful authentication as a different user (e.g., `admin`) without valid credentials
2. Show which XML manipulation technique bypassed signature validation
3. Provide before/after XML diff showing the modification
4. Confirm via session/cookie/response that the target account was accessed

## False Positives

- SP correctly validates signature over the exact element that is processed
- Strict schema validation rejecting injected DOCTYPE/comments
- Properly implemented InResponseTo tracking preventing replay
- NameID bound to IdP-issued immutable identifier

## Impact

- Complete authentication bypass and account takeover
- Privilege escalation to administrator roles
- Access to all data in SAML-protected applications
- Enterprise-wide compromise if IdP/SP trust is broad

## Pro Tips

1. saml-raider Burp extension automates XSW variants — try all 8 attack profiles
2. Always test both SP-initiated and IdP-initiated flows — different code paths
3. Check if RelayState is validated — open redirect chains are common
4. Python `python3-saml` and OneLogin libraries have had repeated comment injection bugs
5. Decode redirect binding: `import zlib,base64; zlib.decompress(base64.b64decode(s), -8)`
6. Compare what `Reference URI` points to vs. what the application uses after processing
7. WS-Federation tokens (used by Azure/ADFS) have similar issues — test `wresult` parameter
8. SAML endpoints are often at `/saml/acs`, `/saml2/idp/SSO`, `/Shibboleth.sso/SAML2/POST`

## Summary

SAML's XML complexity is its weakness. Signature wrapping exploits the gap between what is signed and what is processed. Always test signature removal, XSW variants, comment injection, and replay — production deployments frequently skip one of these checks.
