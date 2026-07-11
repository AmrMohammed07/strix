---
name: messaging-feature
description: Messaging / chat / DM / comment / notification feature testing — blind XSS & HTML injection in the two render sinks (web UI + email), email-header injection, message/thread/attachment IDOR, send-as-another-user, session-after-logout, notification data leakage, file-upload abuse, CSRF auto-send, and rate-limit / email-bombing
---

# Messaging Feature Abuse

User-supplied message content is stored then rendered in two different sinks — the recipient/staff **web UI** and the **email notification** — often with different or missing encoding in each. Add multi-party state (sender/recipient/thread/staff) and attachments and you get a dense cluster of stored-XSS, IDOR, access-control, and data-leakage bugs. Messaging is the canonical **blind-XSS** sink: the payload fires later in a staff/admin panel or an email client, not in your own session — use an out-of-band callback host.

## Injection

Test in message body, subject/title, reply field, and confirm execution in **both** the web UI and email notifications:
```
tester'"/><<h1>h1>ester0x88<</h1>/h1>
0x88"><<img/src=https://your-collab>img/src=...>
Your Account has been suspended change your password From Here <a/href=https://evil.com>change password</a
```
- HTML injection in email rendering; XSS in the email section.
- **Email header injection** — inject `\n` / `%0a` into fields that feed mail headers (CC/BCC/spoof).
- **Markup / invisible-pixel injection** — an auto-loaded remote/invisible image (iplogger) leaks the viewer's IP, UA, and read-receipt timing even without script execution.

## IDOR

- Change message ID → read others' messages.
- Change conversation/thread ID → view other conversations.
- Modify user/client ID; send message **as another user**; modify recipient ID.

## Access control

- **Session after logout** — access messages / reuse the old token post-logout.
- **Privilege escalation** — reply to a thread you shouldn't reach; access deleted/archived messages via direct endpoint; client↔staff cross-access.
- **BAC** — replay/duplicate send; edit message content after sending; send when messaging is disabled; send when blocked; bypass client/staff restrictions.

## Data leakage

- Inspect API responses for hidden fields, leaked emails / internal IDs, cross-account data, metadata; trigger errors for stack traces.
- Email notifications leaking full message content, emails, internal IDs, or "secure messaging" content.

## File upload (attachments)

- Upload `.html` / `.svg` / `.js` / PDF-with-embedded-JS; double extensions (`file.jpg.html`); bypass Content-Type validation; payload in filename.
- Access uploaded files via direct URL; modify sender ID; access other users' attachments (IDOR). Prove the file is served with a dangerous content-type / executes, or is reachable cross-account.

## Abuse / DoS

- Rate-limit checks; spam via multiple notifications; race conditions; high-volume message flood; **email bombing** via notifications; very long messages (10k+ chars) → DoS potential. Get authorization before stress testing.

## Other

- Unauthenticated access to messaging APIs.
- **CSRF** — build an auto-send PoC on a state-changing send.
- **Input validation** — unicode/RTL, emojis, null byte `%00`, broken JSON / missing parameters.

## Validation & evidence

- Blind XSS / HTML injection: confirm actual execution/rendering in the recipient or staff context (callback fired, or markup rendered as HTML), in both sinks — UI and email.
- Pixel injection: show the collaborator/iplogger hit (IP + UA) when the victim opens the message.
- IDOR: prove cross-account access with two accounts, capturing request + the other user's data.
- File upload: prove dangerous serving/execution or cross-account direct-URL reach.
- Email leakage: show the notification body/headers containing data the recipient shouldn't get.
- Session-after-logout: replay the post-logout token and show it still returns messages.

## References
- Markup injection (invisible image steals data): medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba1012
