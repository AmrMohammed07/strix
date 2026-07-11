"""``hackerone_intel`` — consult the local HackerOne intelligence engine (root agent only).

Wraps the already-built KB at ``$H1_KB_HOME`` (default ``~/.claude/skills/hackerone-kb``):
a SQLite store of 12,340 disclosed HackerOne reports plus distilled playbooks, per-tech
and per-feature intel, bug-chain intelligence, and a ranked hunt planner — all exposed
through ``bin/h1_query.py``.

Design note — shell out, not direct sqlite3
--------------------------------------------
This tool shells out to ``h1_query.py`` rather than querying ``h1_kb.sqlite`` directly.
Direct SQL could only reproduce the handful of DB-backed modes (search/class/show/tech/
assets/classes/programs). It could NOT reproduce:

  * ``plan`` — the ranked, evidence-backed hunt planner, which ``h1_query.py`` delegates
    to ``h1_plan.py`` (ranking logic well beyond a simple query) and is the primary
    "consult-first" use case; and
  * ``playbook`` / ``profile`` / ``feature`` / ``chains`` / ``recon`` / ``analysis`` —
    which read curated markdown off the KB tree, not the DB.

Shelling out reuses the whole engine as-is and avoids forking logic that would then rot.
The subprocess is always invoked with an argv **list** (never ``shell=True``): there is
no shell-injection surface. The 104 MB DB is never copied into this repo — it is read in
place via ``H1_KB_HOME`` (which must point at the KB *home directory*, because
``h1_query.py`` locates its own ``db/``, ``playbooks/``, and ``intel/`` relative to
itself).

Read-only: the ``outcome`` subcommand (the KB's write/learning path) is deliberately not
exposed. Root-agent only: like ``finish_scan``, this rejects sub-agents at call time — it
is a consult-first orchestration step for the root agent, not a per-subagent tool.

Graceful degradation: if the KB path / DB file does not exist on this host, the tool
returns ``{"success": False, "error": ...}`` rather than raising.

Known limitation (underlying script, out of scope to patch — it lives outside this repo):
a ``query`` that is *exactly* one of ``h1_query.py``'s recognised flag strings —
``--class``, ``--program``, ``--severity``, ``--limit``, ``--bounty``, ``--kind`` — is
misread by its positional arg reader (which indexes ``sys.argv`` for the flag), yielding
wrong or empty matches rather than a clean error. Ordinary leading-dash text such as
``-test`` is fine. Avoid passing a bare flag string as ``query``.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

_DEFAULT_H1_KB_HOME = "~/.claude/skills/hackerone-kb"
_SUBPROCESS_TIMEOUT_S = 60
_DEFAULT_MAX_CHARS = 16_000

# Modes the agent may invoke, mapped to h1_query.py subcommands. ``outcome`` is
# intentionally absent — it writes to the KB's learning store, and this tool is read-only.
_ALLOWED_MODES: frozenset[str] = frozenset(
    {
        "plan",
        "playbook",
        "profile",
        "feature",
        "chains",
        "recon",
        "search",
        "class",
        "show",
        "tech",
        "assets",
        "analysis",
        "classes",
        "programs",
    }
)

# Modes whose primary input (a slug or free-text term) arrives in ``query`` and must be
# non-empty.
_REQUIRES_QUERY: frozenset[str] = frozenset(
    {"playbook", "profile", "feature", "search", "class", "tech", "assets"}
)


def _kb_home() -> Path:
    return Path(os.environ.get("H1_KB_HOME", _DEFAULT_H1_KB_HOME)).expanduser()


def _plan_args(tech: str, feature: str, target: str, limit: int) -> list[str]:
    if not tech.strip() and not feature.strip():
        raise ValueError("mode 'plan' requires at least one of 'tech' or 'feature'")
    args = ["plan"]
    if tech.strip():
        args += ["--tech", tech]
    if feature.strip():
        args += ["--feature", feature]
    if target.strip():
        args += ["--target", target]
    args += ["--top", str(limit)]
    return args


def _build_args(
    mode: str,
    *,
    query: str,
    report_id: int | None,
    tech: str,
    feature: str,
    target: str,
    limit: int,
) -> list[str]:
    """Map the tool's named params to h1_query.py's positional/flag args.

    Raises ``ValueError`` (with an agent-readable message) for an unknown mode or a mode
    missing its required input, before any subprocess is spawned.
    """
    if mode not in _ALLOWED_MODES:
        raise ValueError(
            f"unknown mode {mode!r}. Valid modes: {', '.join(sorted(_ALLOWED_MODES))}"
        )
    if mode in _REQUIRES_QUERY and not query.strip():
        raise ValueError(f"mode {mode!r} requires a non-empty 'query'")

    if mode == "plan":
        return _plan_args(tech, feature, target, limit)
    if mode == "show":
        if report_id is None:
            raise ValueError("mode 'show' requires 'report_id'")
        return ["show", str(report_id)]

    # Remaining modes map to fixed argv shapes. ``analysis`` takes an optional name
    # (h1_query.py defaults to the README synthesis); chains/recon/classes take no args.
    per_mode: dict[str, list[str]] = {
        "search": [mode, query, "--limit", str(limit)],
        "class": [mode, query, "--limit", str(limit)],
        "programs": ["programs", "--limit", str(limit)],
        "playbook": [mode, query],
        "profile": [mode, query],
        "feature": [mode, query],
        "tech": [mode, query],
        "assets": [mode, query],
        "analysis": ["analysis", query] if query.strip() else ["analysis"],
        "chains": ["chains"],
        "recon": ["recon"],
        "classes": ["classes"],
    }
    return per_mode[mode]


def _run_query(script: Path, args: list[str], mode: str, max_chars: int) -> dict[str, Any]:
    """Run h1_query.py with the given argv and turn its output into a result dict.

    Handles timeout, launch failure, and non-zero exit cleanly, and caps large output at
    ``max_chars`` with a ``truncated`` marker so it cannot blow out an agent's context.
    """
    try:
        # argv list, never shell=True → there is no shell-injection surface here.
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(script), *args],
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("hackerone_intel: mode %s timed out", mode)
        return {"success": False, "error": f"HackerOne KB query timed out (mode={mode})"}
    except OSError:
        logger.exception("hackerone_intel: failed to launch query script")
        return {"success": False, "error": "Could not run the HackerOne KB query script"}

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"exit {proc.returncode}"
        return {
            "success": False,
            "error": (
                f"HackerOne KB query failed (mode={mode}): {tail}. If 'query' is exactly "
                "a flag string, see the known-limitation note in the tool docstring."
            ),
        }

    output = proc.stdout or ""
    cap = max_chars if max_chars > 0 else _DEFAULT_MAX_CHARS
    result: dict[str, Any] = {"success": True, "mode": mode}
    if len(output) > cap:
        result["output"] = output[:cap]
        result["truncated"] = True
    else:
        result["output"] = output
    return result


@register_tool(sandbox_execution=False)
def hackerone_intel(
    mode: str,
    query: str = "",
    report_id: int | None = None,
    tech: str = "",
    feature: str = "",
    target: str = "",
    limit: int = 20,
    max_chars: int = _DEFAULT_MAX_CHARS,
    agent_state: Any = None,
) -> dict[str, Any]:
    # Root-agent only — same enforcement pattern as finish_scan. Sub-agents get a clean
    # rejection instead of re-running the consult-first planner.
    if agent_state is not None and getattr(agent_state, "parent_id", None) is not None:
        return {
            "success": False,
            "error": (
                "hackerone_intel is root-agent only. Sub-agents should act on the root "
                "agent's hunt plan rather than re-querying the KB."
            ),
        }

    home = _kb_home()
    db_path = home / "db" / "h1_kb.sqlite"
    script = home / "bin" / "h1_query.py"
    if not db_path.is_file() or not script.is_file():
        logger.warning(
            "hackerone_intel: KB not configured under %s (db_present=%s, script_present=%s)",
            home,
            db_path.is_file(),
            script.is_file(),
        )
        return {"success": False, "error": f"HackerOne KB not configured at H1_KB_HOME ({home})"}

    try:
        built_args = _build_args(
            mode,
            query=query,
            report_id=report_id,
            tech=tech,
            feature=feature,
            target=target,
            limit=limit,
        )
    except ValueError as exc:
        return {"success": False, "error": str(exc)}

    return _run_query(script, built_args, mode, max_chars)
