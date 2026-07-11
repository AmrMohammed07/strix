# PROJECT_EXPLAINED.md

A complete, plain-language walkthrough of this project for someone who was **not**
part of building it. Every specific claim below is traceable to real code via
`file.py:line` references. The most important thing this document does is separate
**REAL CODE** (mechanically enforced — the model cannot talk its way around it) from
**PROMPT TEXT** (instructions the AI model is *asked* to follow, but which nothing
enforces).

---

## 1. What this project is

This is a fork of **[usestrix/strix](https://github.com/usestrix/strix)** — an
**autonomous AI penetration-testing agent**. You give it a target (a URL, a repo, an
IP); a "root" AI agent runs reconnaissance, spawns specialized sub-agents to test each
vulnerability class, those sub-agents validate findings against strict evidence rules,
and the system produces a report. Under the hood it drives a real browser, an
intercepting proxy, and a shell inside a sandboxed Docker container, and it talks to an
LLM (via LiteLLM) to decide what to do next.

**This fork adds, on top of upstream:** (a) two **code-level enforcement gates**
(coverage + raw-HTTP evidence), (b) a **keyword→skill auto-augment router**, (c) a
**UI-coverage ledger** (`ui_surface.md`) and SPA-route discovery, (d) two custom tools —
**`hackerone_intel`** (a local HackerOne intelligence KB) and **`test_inbox`** (reads
mail.tm test mailboxes for reset/verification flows), and (e) a large expansion of the
**skill library** (~114 selectable skills).

**Provenance (brief):** upstream `usestrix/strix` → a friend's already-modified
"VANGUARD-9" fork (which, among other things, converted a rigid forced-phase workflow
into an *advisory* one) → this fork, which builds on that VANGUARD-9 baseline.

---

## 2. The core building blocks, one by one

For each: what it is, where it lives, and **REAL CODE vs PROMPT TEXT**.

### The Root Agent — **PROMPT TEXT**
`strix/skills/coordination/root_agent.md`. This is a markdown file injected into the
root agent's system prompt. It tells the AI *how to orchestrate* — do recon first, spawn
one sub-agent per vulnerability-class × component, audit coverage before finishing. It
also contains a human-readable "KEYWORD → SKILL ROUTING" table. **Nothing here is
enforced by code** — it's guidance the model follows by choice. (The *mechanical* version
of that routing table lives in code; see the router below.)

### Scan modes (quick / standard / deep) — **PROMPT TEXT**
`strix/skills/scan_modes/{quick,standard,deep}.md`. Each is a markdown skill that is
**always appended** to whatever agent's prompt (see §3.2). They describe an 8-phase
workflow and quality rules. **Post-VANGUARD-9 change:** the phase *sequence* is now
explicitly **advisory** ("advisory workflow, not a rigid gate: skip, reorder, or revisit
phases as the target warrants"), not a hard-coded state machine. What stayed strict are
the *evidence/anti-false-positive rules* (raw HTTP required, XSS only if it executes in a
browser, IDOR only with real cross-user data, missing headers = Info). Default mode is
**deep** (`main.py` argparse). These rules are still just prose — the *only* two of them
that became actual code are the coverage and raw-HTTP gates below.

### The skill library — **PROMPT TEXT**
`strix/skills/<category>/*.md`. **114 selectable skills** (verified via
`get_all_skill_names()`): `vulnerabilities` 90, `technologies` 11, `frameworks` 3,
`cloud` 2, `protocols` 2, `reporting` 2, `web3` 2, `mobile` 1, `reconnaissance` 1 — plus
the `scan_modes` (3) and `coordination` (2) categories which are loadable by name but
excluded from the "selectable" list. Each skill is a markdown file with YAML frontmatter
(`--- name: … / description: … ---`) followed by the methodology body. **Discovery:**
`strix/skills/__init__.py` → `get_available_skills()` scans category folders (excluding
`scan_modes` and `coordination`), keys each skill by its **filename stem**. **Loading:**
`load_skills()` strips the frontmatter and returns just the body text. It's all prompt
text — a skill only affects a run if it gets injected into some agent's prompt.

### Sub-agents (`create_agent`) — **REAL CODE**
`strix/tools/agents_graph/agents_graph_actions.py:277` (`def create_agent`). When the
root agent calls this tool, real code runs: it parses the `skills="…"` string, validates
names against the registry, runs the keyword router (below), builds an
`LLMConfig(skills=skill_list, scan_mode=…)` (`:346`), instantiates a `StrixAgent`, and
**spawns it on a background thread** (`_run_agent_in_thread`). The agent graph
(`_agent_graph`) tracks parent/child relationships. So "spawning a sub-agent" is a
genuine function call + thread, not the model imagining a helper.

### Enforcement gate #1 — `_coverage_gate` — **REAL CODE**
`strix/tools/finish/finish_actions.py:114`. When the root agent tries to end the scan via
`finish_scan` (`:239`), this gate **reads the real ledger file** `endpoint_checklist.md`
(`_CHECKLIST_PATH`, `:66`) out of the sandbox (through the tool-server), parses it with
`_untested_checklist_entries()` (`:98` — counts lines containing `[ ]`, `pending`, or
`in-progress`), and if **any** entry is still untested it returns
`{"success": false, "coverage_incomplete": true, …}` (`:148`) — i.e. it **blocks
completion**. It is re-run on *every* `finish_scan` attempt (the loop at `:277`), so the
model cannot self-attest its way past it. If the checklist can't be read at all, it
degrades open (lets the scan finish) rather than deadlocking.

### Enforcement gate #2 — `_validate_raw_http_evidence` — **REAL CODE**
`strix/tools/reporting/reporting_actions.py:159`. When a sub-agent files a finding via
`create_vulnerability_report` (`:229`), this runs synchronously inside that call. It checks
the `technical_analysis` text against two regexes: `_HTTP_REQUEST_RE` (a method verb —
`GET|POST|PUT|…`, `:155`) **and** `_HTTP_RESPONSE_RE` (`HTTP/x` or a 3-digit status line,
`:156`). If either signal is missing, the report is **rejected** with a validation error.
It is deliberately **skipped for code-review findings** — the check only runs
`if not code_locations` (`:258`), so a static/source finding (which has no HTTP traffic)
isn't forced to fake one.

### Keyword→skill auto-augment router — `_route_skills` — **REAL CODE (with an honest ceiling)**
`strix/tools/agents_graph/agents_graph_actions.py:248`, driven by the `_SKILL_ROUTES`
regex map (`:201`) and `_MAX_SKILLS = 5` (`:245`). Inside `create_agent`, it scans the
new sub-agent's `"{name} {task}"` text against the map and **force-adds** the matching
skills to `skill_list` (`:319`), honoring the 5-skill cap. The map covers ~11
parameter-shaped signals (e.g. `url|redirect|…` → `ssrf`+`path_traversal_lfi_rfi`+`open_redirect`;
`cmd|exec` → `command_injection`+`rce`; `id|user_id` → `idor`) plus 2 feature-name rows
(reset/recovery → `reset_password`; sign-up/verify → `registration_email_verification`).
**What it guarantees:** the mapped skill's *text is present* in the spawned agent's prompt,
regardless of whether the model remembered to list it. **What it does NOT guarantee:** that
the agent actually *acts on* that skill or *calls* a related tool — that remains model
judgment. So it's real code up to "the methodology is loaded," and prompt-text from there.

### Custom tool #1 — `hackerone_intel` — **REAL CODE, root-only**
`strix/tools/hackerone_intel/tool.py:198` (`@register_tool(sandbox_execution=False)` →
runs host-side). It **shells out** to a local KB engine
(`~/.claude/skills/hackerone-kb/bin/h1_query.py` over a SQLite store of ~12,340 disclosed
HackerOne reports) with an argv list (no shell injection). Modes: `plan/playbook/profile/
feature/chains/search/class/show/…`, read-only. **Root-only:** it rejects sub-agents via
`if agent_state.parent_id is not None` (`:212`) — because it's a *consult-first planning*
step for the orchestrator, not something every sub-agent should re-query.

### Custom tool #2 — `test_inbox` — **REAL CODE, broadly available**
`strix/tools/test_inbox/tool.py:456` (`@register_tool(sandbox_execution=False)`). Reads
durable mail.tm test mailboxes (e.g. `member07@dollicons.com`) so an agent can complete
reset-password / email-verification / ATO flows and extract the emailed token. Modes:
`list_accounts / list_messages / get_message / search_messages / latest_message /
wait_for_message`. **No `parent_id` guard** (verified — none exists) → any agent can call
it, because it's an *execution* tool the sub-agent running the flow needs directly. Its
safety comes from a **credential boundary**, not access restriction: it runs host-side
with `httpx trust_env=False` so its traffic bypasses the scan proxy, and it **never
returns or logs** the account password or JWT (errors name the alias only). It talks to
the public mail.tm API (`POST /token` for a JWT, `GET /messages` to list, `GET
/messages/{id}` for the body). Configured via `MAILTM_ACCOUNTS` + `MAILTM_ACCT_<alias>_…`
env vars.

### The ledger / workspace system — **runtime files (mixed)**
Created inside the **sandbox container's `/workspace`** during a run. Two kinds:
- **Agent-written prose the model maintains (PROMPT-driven):** `recon_report.md`,
  `auth_tokens.md`, `authenticated_endpoints.md`, `user_a_resources.md`, `js_endpoints.*`,
  and **`ui_surface.md`** (the seen-but-unvisited UI/route ledger). The model writes and
  updates these because the skills tell it to. Nothing parses `ui_surface.md` in code.
- **`endpoint_checklist.md` — the one that is BOTH written by the model AND code-parsed
  by a gate.** The model maintains it (`[ ] pending | [~] in-progress | [x] tested | …`),
  but `_coverage_gate` (real code) reads and parses it to decide whether `finish_scan`
  may complete. This is the single ledger with mechanical teeth.

Durable outputs (the final report + run data) are written to the **host** at
`./strix_runs/<run-name-or-id>/` (`strix/telemetry/tracer.py:298`). The container's
`/workspace` is **not** bind-mounted, so those ledger files are ephemeral (gone when the
container is cleaned up) unless captured before the run ends.

---

## 3. The full sequence — how a scan runs, step by step

Command: `poetry run strix --target http://localhost:3000 -m quick`.

**3.1 — CLI entry → config → sandbox.**
Entry point is `strix.interface.main:main` (`pyproject.toml:45`). `main.py` parses args
(`--target`, `-m/--scan-mode`, `--run-name`, `--resume`, …), resolves the LLM config
(`strix/config/config.py` → `resolve_llm_config()`, reads `STRIX_LLM` + `LLM_API_KEY`),
and the Docker runtime (`strix/runtime/docker_runtime.py:180` `_create_container`) starts
a container from the sandbox image and waits for its in-container tool-server.

**3.2 — Root agent initialization.**
A root `StrixAgent` starts. Its system prompt = the base template
(`strix/agents/StrixAgent/system_prompt.jinja`) rendered with the loaded skills. The skill
list is assembled in `strix/llm/llm.py` `_load_system_prompt()`:
`skills_to_load = [*config.skills, f"scan_modes/{scan_mode}"]` (`:96-97`) → `load_skills()`
(`:99`) → injected into the template under `loaded_skill_names` (`:104`). For the root,
`config.skills` includes `root_agent`. So at this point the prompt = base methodology +
`root_agent.md` + `scan_modes/quick.md`.

**3.3 — Phase 0 recon.**
Following its (prompt-text) instructions, the root agent crawls, analyzes JS, probes docs,
and writes `/workspace/recon_report.md` and the initial `/workspace/endpoint_checklist.md`
(marking discovered endpoints `[ ] pending`). No testing happens until this map exists —
that ordering is prose guidance, not a code gate (the only code gate on finishing is the
coverage gate at the *end*).

**3.4 — Spawning a sub-agent (concrete trace).**
Say recon finds a login form. The root agent calls the `create_agent` tool with, e.g.,
`name="Auth Agent — /api/login", task="test the forgot-password and login flow", skills="idor"`.
Real code (`create_agent`, `agents_graph_actions.py:277`) runs: `_route_skills` scans
`"Auth Agent — /api/login test the forgot-password and login flow"`, the reset/recovery
row matches "forgot-password" → **`reset_password` is force-added** to `skill_list`
(`:319`) even though the model only listed `idor`. `LLMConfig(skills=[…"idor","reset_password"…])`
is built (`:346`), a `StrixAgent` is created and launched on a thread. That sub-agent's
system prompt now **contains `reset_password.md`'s methodology** — guaranteed by code. (If
the model had named an authentication task, `authentication_jwt.md` etc. would be there
because the model listed them — that part is prompt-driven.)

**3.5 — A sub-agent doing actual testing.**
The sub-agent calls real tools: `browser_action` (`strix/tools/browser/browser_actions.py:184`,
a *sandbox*-executed tool → runs inside the container, drives Chromium), the proxy tools
(`strix/tools/proxy/…`, capture/replay HTTP), and — for a reset flow — `test_inbox`
(host-side) to fetch the emailed token. It captures raw request/response pairs as evidence
because the skills tell it that's required.

**3.6 — Filing a report.**
When the sub-agent has proof, it calls `create_vulnerability_report`
(`reporting_actions.py:229`). **At that instant**, `_validate_raw_http_evidence` runs
inside the call: unless `technical_analysis` contains both a request verb and a response
status line (and unless it's a `code_locations` finding), the report is **rejected**. A
CVSS is computed and a dedupe check runs; a valid report is stored via the tracer.

**3.7 — Root audits completion.**
When the root agent calls `finish_scan` (`finish_actions.py:239`), guards run in order:
(1) `_validate_root_agent` (only the root may finish), (2) `_check_active_agents` (blocks
while sub-agents are still running), (3) non-empty summary/methodology/analysis/
recommendations, then (4) the gate loop `for _gate in (_coverage_checkpoint,
_coverage_gate)` (`:277`). If `_coverage_gate` finds any `endpoint_checklist.md` entry
still untested, `finish_scan` returns "coverage incomplete" and the scan continues.

**3.8 — Outputs.**
Final report + run data land on the host in `./strix_runs/<run>/`
(`tracer.py:298` — `Path.cwd()/strix_runs`). The container (and its `/workspace`) are torn
down afterward.

---

## 4. Component communication map

Each arrow marked **[code]** (a real function/thread/HTTP call) or **[prompt]** (the model
reads text and *chooses* to act):

- **CLI → runtime:** `main.py` **[code]→** `docker_runtime.create_sandbox` **[code]→**
  Docker container + tool-server.
- **Root agent → sub-agent:** Root agent **[prompt: decides to spawn]→** `create_agent`
  tool **[code]→** `_route_skills` **[code, force-adds skills]→** `LLMConfig` **[code]→**
  new `StrixAgent` on a thread **[code]**.
- **Any agent → the target:** agent **[prompt: decides to act]→** `browser_action` /
  proxy tools **[code]→** tool-server inside the sandbox **[code, HTTP]→** target.
- **Sub-agent → evidence gate:** sub-agent **[prompt: decides to report]→**
  `create_vulnerability_report` **[code]→** `_validate_raw_http_evidence` runs
  **synchronously inside that call [code]→** accepted or rejected.
- **Root agent → coverage gate:** root **[prompt: decides it's done]→** `finish_scan`
  **[code]→** `_coverage_gate` reads `endpoint_checklist.md` **[code]→** allowed or blocked.
- **Root agent → intelligence:** root **[prompt]→** `hackerone_intel` tool **[code]→**
  shells out to `h1_query.py` + SQLite **[code]**. (Sub-agents are rejected by code.)
- **Auth sub-agent → inbox:** sub-agent **[prompt: skill tells it to]→** `test_inbox`
  **[code]→** mail.tm API over TLS **[code]**.

The pattern: **deciding *whether* to act is almost always prompt-driven; the act itself,
once chosen, is a real code call — and the two gates + the router are the points where code
overrides or constrains the model regardless of what it "wants."**

---

## 5. Code vs. prompt-text — master list

| REAL CODE (mechanically enforced) | PROMPT TEXT (model-followed, not enforced) |
|---|---|
| `_coverage_gate` — blocks `finish_scan` while `endpoint_checklist.md` has untested entries (`finish_actions.py:114`) | Scan modes `quick/standard/deep` methodology + rules (`skills/scan_modes/*.md`) |
| `_validate_raw_http_evidence` — rejects reports lacking raw HTTP req+resp (`reporting_actions.py:159`) | The whole skill library (`skills/**/*.md`, 114 skills) |
| `_route_skills` auto-augment — force-loads mapped skills (`agents_graph_actions.py:248`) *(guarantees skill **loads**, not that it's **used**)* | `root_agent.md` coordination guidance (incl. its human-readable routing table) |
| `create_agent` — thread spawn + `LLMConfig` + skill injection (`agents_graph_actions.py:277`) | The base `system_prompt.jinja` methodology sections (payload lists, per-phase guidance) |
| `create_vulnerability_report` — CVSS calc, dedupe, storage (`reporting_actions.py:229`) | "Do recon before testing", "validate with 2 signals", severity rules — all prose |
| `finish_scan` guards — root-only, active-agents, non-empty fields (`finish_actions.py:239`) | `ui_surface.md` "not complete until all `[x]`" rule (no code reads it) |
| `hackerone_intel` (root-only, `parent_id` guard) + `test_inbox` (broad, credential boundary) tools | Whether the model *chooses* to call any tool at all |
| Agent-graph / threading (`_agent_graph`, `_run_agent_in_thread`) | The endpoint_checklist's *content quality* (the model writes it; code only counts markers) |
| Checkpoint/resume (`telemetry/checkpoint.py`, `interface/checkpoint_restore.py`) | |

**Honest boundary cases:** the router is code that *loads* a skill, but *acting* on that
skill is prompt-text. `endpoint_checklist.md` is model-written prose, but its `[ ]`/pending
markers are *code-parsed* by the coverage gate. `test_inbox` is code, but whether an agent
calls it depends on the (prompt-text) skill step telling it to.

---

## 6. Known limitations / deliberately deferred items

- **System-prompt duplication (not de-duplicated).** ~400–470 lines of per-vulnerability
  methodology are duplicated across `system_prompt.jinja`, `root_agent.md`, and the skill
  files. A refactor was scoped but deferred (prerequisites: wider guaranteed routing + a
  benchmark to catch regressions).
- **Router coverage is partial.** `_SKILL_ROUTES` covers ~11 parameter classes + 2
  feature classes — **not** all ~30 vulnerability classes. XSS, CORS, CSRF, auth/JWT,
  business-logic, GraphQL, WebSocket, rate-limit, session, NoSQL, etc. are still
  model-judgment (no code-guaranteed skill load). Deferred widening.
- **Auto-augment ceiling.** Guarantees a skill's text is *present* when the spawn task/name
  carries the signal; it can't force the model to *use* it, and a signal-less task or the
  5-skill cap can drop matches.
- **CTF/lightweight mode: intentionally not built.** `quick` mode keeps full evidence
  standards and recon; there is no recon-skipping mode.
- **`test_inbox` "configured" ≠ "authenticated".** `list_accounts` reporting a mailbox as
  `ok` means it's *structurally configured* (alias + password + address resolvable), not
  that the password actually authenticates against mail.tm — that's only proven by a live
  mode call.
- **Proxy-side routing complement: deferred.** A ground-truth-parameter detector at the
  proxy layer was designed but not built; current routing keys off the model-authored
  task/name text.

---

## 7. How to run it

Accurate to the current CLI (`main.py` argparse) — flags may drift over time.

**Environment (host, before launching):**
```bash
# LLM (required): a LiteLLM provider/model string + key.
export STRIX_LLM="gemini/gemini-3-pro-preview"   # or "openai/gpt-5", "anthropic/…", "strix/gpt-5"
export LLM_API_KEY="…your provider key…"           # for gemini/, an AI Studio AIzaSy… key
# Optional integrations:
#   PERPLEXITY_API_KEY=…      -> enables the web_search tool
#   MAILTM_ACCOUNTS / MAILTM_ACCT_<alias>_PASSWORD (+ MAILTM_DOMAIN) -> enables test_inbox
```
Docker must be running (the sandbox is a Docker container). `hackerone_intel` additionally
needs the local KB at `~/.claude/skills/hackerone-kb/` (optional; degrades gracefully if
absent).

**Run a scan** (from the repo root, via Poetry). Start with **quick mode against a target
you own/are authorized to test** (e.g. a local OWASP Juice Shop), never a live bug-bounty
program until you've watched a full run:
```bash
poetry run strix --target http://localhost:3000 -m quick --run-name juiceshop-baseline-01
```
Flags: `--target` (repeatable, required) · `-m/--scan-mode {quick,standard,deep}` (default
**deep**) · `-n/--non-interactive` (no TUI) · `--instruction "…"` / `--instruction-file …`
· `--run-name …` · `--resume` · `--new`/`--force-new` · `--config …`.

**Outputs:** `./strix_runs/<run-name>/` on the host (final report + run data). The
`/workspace` ledgers live inside the container during the run only.

**Resume** a stopped run (deterministic when you gave it a `--run-name`):
```bash
poetry run strix --target http://localhost:3000 --run-name juiceshop-baseline-01 --resume
```
`--resume` loads the checkpoint (`strix_runs/<run>/checkpoint.json`) for that run-name +
target and continues; `--new` deletes any checkpoint and starts fresh.

---

*Every `file.py:line` reference in this document was checked against the current source at
the time of writing. If code moves, the line numbers may drift — the function/file names
are the stable anchors.*
