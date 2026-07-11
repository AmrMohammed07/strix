---
name: suspended-banned-user-access
description: Testing what a banned/suspended account can still do and what others can do to it — stale sessions, un-revoked tokens, password-reset re-activation, and PII leakage after ban
---

# Banned / Suspended User Access

When an account is banned or suspended, the UI usually blocks the obvious paths — but the ban often isn't enforced across sessions, tokens, integrations, or unauthenticated flows. Test both directions: what the banned user can still do, and what active users can do to/with the banned user.

## Inbound (Active User → Banned User)
- Collaboration: can an active user invite/assign/add the banned user's email or ID to a private project/team/workspace? (ref: HackerOne #1959219 — banned user invited as collaborator, could reset password)
- Asset transfer: can an active user transfer ownership of a repo/billing account/funds to the banned user?
- Mention/ping: does @mention or DM to the banned user still get processed and email them?

## Outbound (Banned User → App)
- Stale session: ban an account holding an active session in another browser — does that session die immediately, or can it still browse / hit the API with the old cookie?
- API token: are PATs / API keys revoked on ban? Try an old token to read or modify data.
- OAuth/SSO: with "Login with Google" / corporate SSO, can the banned user still authenticate into peripheral services/subdomains?

## Unauthenticated Feature Access
- Password reset: can the banned user request a reset, receive the email, and change the password?
- Email verification: does clicking an old "confirm email" link restore account state?
- Support portal: can the banned email still open Zendesk/helpdesk tickets?

## Data Privacy / Leakage
- Profile IDOR: UI 404s the banned profile, but does `/api/v1/users/{banned_id}` still leak PII?
- Webhook/integration: are previously-configured webhooks/Slack/Discord integrations still firing company data to the banned user's servers?
