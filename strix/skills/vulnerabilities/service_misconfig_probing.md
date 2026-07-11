---
name: service-misconfig-probing
description: Stack-fingerprint-then-probe catalog of default debug/admin/config endpoints per framework and datastore, plus SaaS misconfiguration checks (Salesforce Aura, Postman, Google hd=, Jenkins script console, GitLab snippets)
---

# Service Misconfiguration Probing

Fingerprint the stack first (headers, cookies, errors, favicon, JS), then probe that stack's default debug/admin/config endpoints. The signal is a `200`/`401`/`403` with **real content** that differs from the app's generic 404. Automate with misconfig-mapper (bugology.intigriti.io/misconfig-mapper-docs). Only test in-scope targets and confirm impact before reporting.

## Framework Debug/Admin/Config Endpoints

**Symfony:** `/app_dev.php`, `/_profiler`, `/_profiler/latest`, `/_profiler/phpinfo`, `/_wdt/{token}`, `/config.php`, `/_configurator/steps`
**Laravel:** `/.env`, `/_debugbar/open`, `/telescope/requests`, `/telescope/exceptions`, `/ignition/execute-solution`, `/horizon`, `/pulse`
**Django:** `/.env`, `/admin/login`, `/__debug__`, `/static/debug_toolbar/`, `/djdt/`
**Rails:** `/rails/info/properties`, `/rails/console`, `/rails/db`, `/config/database.yml`, `/.env`
**Express/Node:** `/.env`, `/debug`, `/trace`, `/env`, `/config`, `/status`
**Flask:** `/.env`, `/console`, `/debug`, `/_debug`
**Next.js:** `/.env.local`, `/.env.production`, `/_next/static/development`, `/api/debug`, `/.next/`
**Strapi:** `/admin`, `/dashboard`, `/.env`, `/plugins/users-permissions`
**Spring Boot:** `/actuator/env`, `/actuator/beans`, `/actuator/mappings`, `/actuator/heapdump` (memory dump → secrets/sessions), `/actuator/threaddump`, `/jolokia/exec` (JMX → potential RCE), `/hawtio`
**ASP.NET:** `/trace.axd`, `/elmah.axd`, `/Web.config`, `/web.config.bak`, `/App_config/connectionStrings.config` (IIS/ViewState deep-dive → technologies/iis.md)
**PHP:** `/phpinfo.php`, `/info.php`, `/php.ini~`, `/server-status`, `/server-info`
**WordPress:** `/wp-config.php~`, `/wp-config.php.bak`, `/wp-json/wp/v2/users`, `/xmlrpc.php`
**GraphQL:** `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/altair`, `/playground` (exploitation → graphql_attacks.md)

## Datastores & Infra UIs

**Apache:** `/server-status`, `/server-info`, `/.htaccess`, `/.htpasswd`
**Nginx:** `/nginx_status`, `/stub_status`
**Tomcat:** `/manager/html`, `/host-manager/html`, `/examples`
**Kibana:** `/app/kibana`, `/app/console`, `/api/console`
**Elasticsearch:** `/_cat/indices`, `/_cat/nodes`, `/_cluster/health`, `/*/_search`
**MongoDB:** `/dbadmin`, `/mongo`, `/admin/mongo`
**Redis:** `/redis`, `/phpredisadmin`
**Docker:** `/_ping`, `/v1.41/info`, `/v1.41/containers/json`, `/v2/_catalog` (registry)

## General Exposure Checks

- **Env/config:** `/.env`, `/.env.local`, `/.env.production`, `/config.php`, `/configuration.php`, `/settings.php`
- **Backups/source:** `/*.bak`, `/*.old`, `/*~`, `/*.sql`, `/*.zip`, `/*.tar.gz`, `/backup`
- **Directory listing:** `/uploads/`, `/files/`, `/assets/`, `/media/`, `/user_uploads/`
- **VCS exposure:** `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.hg/`

## SaaS Misconfigurations

- **Postman:** `postman.com/{company}/?tab=workspaces` — public workspaces leak secrets.
- **Salesforce Aura:** `POST /aura` / `/sfsites/aura` / `/s/sfsites/aura` on `*.force.com`, `*.lightning.force.com` — Aura components enabled → object enumeration.
- **Trello:** `site:trello.com "company"`, `trello.com/b/{BOARD_ID}` — public boards.
- **Figma:** `figma.com/file/{DesignID}/{name}` — view-access misconfig.
- **Freshservice:** `https://<company>.freshservice.com/support/signup` — open registration.
- **Slack:** invite a new member without admin approval → misconfig.
- **Bitbucket:** `bitbucket.org/{WORKSPACE_ID}`, `site:bitbucket.org inurl:/workspace/projects` — public private repos.
- **Confluence:** anonymous `POST /rpc/xmlrpc` (`confluence2.getPage`), `/rpc/soap-axis/confluenceservice-v2`; disabled XSRF; email visibility; `<company>.atlassian.net/wiki/spaces`.
- **Jira:** `/secure/Signup!default.jspa` (open registration), `/servicedesk/customer/user/login`, anonymous email visibility.
- **AWS S3:** `aws s3 ls s3://{BUCKET} --no-sign-request`.
- **Cloudflare R2:** `site:.r2.dev "company"`.
- **Google:** Groups `site:groups.google.com "{company}"`; Docs `docs.google.com/document/d/{id}/edit`; GCS `storage.googleapis.com/{company}`; **OAuth `hd=` bypass** — change `hd=company.com` to another domain (full method → oauth_sso.md / oidc_attacks.md).
- **Jenkins:** `/signup` (open signup); **Groovy script console** `/script` / `/scriptText` (`curl -s 'https://jenkins.{HOST}/script' -X POST --data 'script={SCRIPT}'`) → RCE.
- **GitLab:** `/explore/snippets` — private snippets exposed.
- **Drupal:** `/node/{ID}` brute force.

## Validation

A generic `200` may be a catch-all SPA route — confirm the response is the *actual* debug/admin/config content and differs from the app's normal 404 before reporting.
