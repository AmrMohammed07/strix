---
name: invite-feature
description: Invitation / team-membership feature testing — invite-token leakage & non-expiry, role escalation on invite, invite-email IDOR & ghost membership, cross-role BAC, invite/accept race conditions, and U+3164 Hangul-filler duplicate-invite & account-lockout
---

# Invite Feature Abuse

Invitation flows sit on top of identity + roles + multi-account state and cross several trust boundaries: inviter→invitee, pending→member, role-at-invite→role-at-accept. Classic gaps: the invite token is a bearer credential (leak/non-expiry/replay); role is chosen at invite time but not re-enforced at accept time (escalation & races); the bound email is attacker-influenceable (IDOR / ghost membership / lockout); per-action authz is assumed from "you were invited" and never re-checked (BAC). Prove cross-account / role-mismatch / lockout before reporting.

## Tokens

- **Token leaked in `Resend-Token` response** — the invite token/link is returned in the resend endpoint's body.
- **Failure to invalidate / non-expiry** — generate an invite, accept it on a secondary account, remove that user from the team, then rejoin with the same link.

## Auth / 2FA

- **Second admin disables first admin's 2FA without password** — admin needs a password to disable their own 2FA, but a second admin (invited by the first) can disable it without one.

## Email binding

- **IDOR on the email parameter at invite signup** — admin invites a specific email; invitee intercepts the registration submit and changes the `email` parameter → email changed successfully.
- **Signup without accepting the invite (ghost membership)** — send invite to `test@example.com`; instead of accepting, sign up directly; the account becomes a real org member while the dashboard still shows the invite as "pending" (anonymous member).

## Privilege escalation

- **API misconfiguration role flip** — the login (or invite) request carries `role:"user"`; match & replace to `role:"admin"`. UI may log out, but full data is visible via API in Burp.
- **Logic-error project takeover via bad-char display name** — attacker (invited as member) sets a name containing HTML tags / `%00` / non-Latin chars; the victim's "remove member" request then errors out and never completes → attacker cannot be removed.

## Injection

- XSS in the first-name field delivered through the invitation link.

## BAC across roles (Auth Analyzer workflow)

Pass the low-privilege user's JWT + cookie to Burp Auth-Analyzer; it replays all admin requests as the lower-privilege user. Confirm the action actually succeeds (not just a rendered button):
- Member invites admin / member / edits org settings / removes members / edits permissions.
- Viewer edits content.

## Race conditions

- Race in invite-send and in accept-invitation.
- **Race → role escalation (Viewer→Admin):** as admin, capture `POST /api/.../invite/`; duplicate into two Repeater tabs — A `role:viewer`, B `role:admin`; send as a single-packet parallel group; confirm two separate invite links arrive; accept the Viewer invite (locked as Viewer), then open the Admin invite link → account becomes Admin despite role immutability.
- **Ghost Admin variant:** generate both links, accept **Admin first**, then Viewer; UI shows Viewer but an admin-only API call succeeds (UI=Viewer, backend=Admin). Document the mismatch.

## U+3164 Hangul filler

Why it works: `U+3164` (HANGUL FILLER) is width-bearing but visually blank; it stays a distinct string at the uniqueness/storage layer yet renders identically in the UI.

- **Duplicate-invite bypass:** invite `victim@target.com` normally, then intercept a second invite and append `U+3164` in the `email` field → `victim@target.comㅤ`; response is `201 Created` instead of "already invited", and two invite emails arrive.
- **Permanent account lockout (DoS):** send the poisoned invite, have the victim complete registration from it; the account looks normal, but login with the clean `victim@target.com` fails because the backend stored the poisoned form (or login normalizes it away). The admin dashboard shows an identical-looking email; victim cannot self-recover.
- **Injecting the char in Burp:** switch to Hex view, find the end of the email value, insert bytes `E3 85 A4` (UTF-8 for U+3164), or paste `ㅤ` directly.

## Validation & evidence

- BAC/privesc: prove the admin-only API returns success as the lower role; for Ghost Admin document the UI-vs-backend mismatch.
- Race: capture both parallel requests + responses and confirm two invite links plus the escalated final role.
- U+3164: show the hex bytes and the `201`; for the DoS show clean-email login failing after registration.
- Non-expiry: show the same link rejoining after removal (timestamps help).
- Ghost membership: dashboard says "pending" while the account has real access.

## References
- Race condition on invitation sending: medium.com/@amralaa66652/the-power-of-a-race-condition-d8f9be8ba71a
