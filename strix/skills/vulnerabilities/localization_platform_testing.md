---
name: localization-platform-testing
description: Industry checklist for localization/translation SaaS (Crowdin/Lokalise/Transifex-style) — workspace/role access control, translation UUID IDORs, domain-verification & email/OAuth bypass, Pro-only paywall bypass, and stored XSS in custom AI prompts/editors
---

# Localization / Translation Platform Testing

These platforms are **workspaces + projects + members with granular roles** over translation assets. Bugs cluster around (a) joining/verifying into orgs you shouldn't, (b) role/project scoping the **API doesn't re-check**, and (c) UUID IDORs + excessive data exposure on translations/keys/reports/PII. **Analyze the JS** for role names and hidden API endpoints, and always test direct API calls — the UI hides scoping the API forgets to enforce.

## Auth & Account Verification

- Bypass email verification by verifying a victim's email with the attacker's verification code.
- Test OAuth misconfig on Facebook/Microsoft/GitLab logins (→ oauth_sso.md).
- **Domain-verification abuse:** these apps suggest a workspace to anyone signing up with a matching email domain. Attempt domain verification for domains you don't own (or `@gmail.com`) — success is a bug.
- Test paywall bypass around 2FA enforcement (e.g., enforcing 2FA on the free plan).

## Roles, Permissions & Access Control

Common roles: **Owner, Manager, Proofreader, Translator, Language Coordinator** (+ hidden/paid custom roles). From the JS, craft invite requests assigning these roles, or attach roles during invitation acceptance.

- **Workspace-vs-project scoping:** a manager removed from one project may still access that project's data via the API.
- **Language Coordinator over-reach:** direct API calls fetch words/translations/files for languages you aren't assigned to.
- Expose project user-groups to a translator-role member.
- Translator access to `api.target.cloud/v1/owners/[UID]/workflows/live` → workflow-detail leakage.
- Unauthorized access to all screenshots (incl. unassigned), project processes, contributor PII.
- Removed developers/managers reading/deleting archived reports.

## API IDORs & Data Exposure (usually UUIDs)

- `app.target.com/translation/{translation_id}/history` → history for unassigned-language translations.
- `api.target.com/api2/projects/{project_id}/translations` → team members' real emails (excessive data exposure).
- `api.target.com/project/[PROJECT_ID]/keys/[KEY_ID]` IDOR; translation-comment IDORs.
- Translator access to owner-generated reports; contributor PII/private-email exposure. (Generic technique → idor.md / bac.)

## Stored XSS & Input Validation

- **Custom AI prompt features** are frequently stored-XSS-vulnerable (these apps implement AI poorly).
- Editor and translation-value input fields → XSS/HTML injection (→ xss.md).

## Business Logic & Paywall

- Project **move/copy to another workspace** → bypasses external project ownership and free-tier limits.
- Make a project public, pull URLs from web archive, self-join as the lowest role → privilege escalation to any public project's tasks.
- Project **branching** → paywall bypass / privesc.
- Pro-only workflows via `api.target.cloud/v1/groups/{group_id}/workflows/{workflow_id}/actions/activate` → bypass Pro restriction.

## Notifications, Integrations, Race

- Notification-system misconfig leaking translation info for unassigned languages (email + in-app).
- Privilege escalation + CSRF in org integration management (→ csrf.md).
- Race conditions exceeding free-plan invite/feature limits (→ race_conditions.md).

## Validation

Prove **cross-account/cross-language** access with two accounts (assigned vs unassigned) — not just that an endpoint returns data for your own assignment.
