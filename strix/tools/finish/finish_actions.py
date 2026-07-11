from typing import Any

from strix.tools.registry import register_tool


# ---------------------------------------------------------------------------
# Coverage checkpoint injected when finish_scan is called before any real
# reconnaissance/mapping has happened.  This fires at most once and only guards
# against premature termination — it does NOT force a fixed number of testing
# rounds.  Once the surface is mapped, the agent decides when it is exhausted.
# ---------------------------------------------------------------------------

# Below this many iterations, a finish_scan attempt is treated as premature and
# the coverage checkpoint fires once before the scan is allowed to complete.
MIN_RECON_ITERATIONS = 15

_RECON_CHECKPOINT = """
Before finishing: confirm reconnaissance and attack-surface mapping are actually complete.

- Have you enumerated the endpoints/routes the app exposes (crawl, JS analysis, known paths)?
- Have you walked the UI and noted every section/page/role you can reach?
- Have you identified the auth surface (login, session, tokens), even if not yet fully tested?

If recon and mapping are genuinely done, call finish_scan again and it will complete. This check
fires only once — it exists to avoid finishing before any real surface discovery, NOT to force a
fixed number of testing rounds. Once the surface is mapped, you decide when it has been exhausted.
"""


def _coverage_checkpoint(agent_state: Any) -> dict[str, Any] | None:
    """Fire the one-shot coverage checkpoint if finish_scan is called before any
    real recon/mapping has happened. Returns a gate response to send back to the
    agent, or None to allow the scan to complete. Fires at most once per scan.
    """
    if agent_state is None or getattr(agent_state, "coverage_checkpoint_done", False):
        return None
    agent_state.coverage_checkpoint_done = True
    # Reset the warning flag so the agent doesn't panic-finish next turn.
    if hasattr(agent_state, "max_iterations_warning_sent"):
        agent_state.max_iterations_warning_sent = False
    if getattr(agent_state, "iteration", 0) < MIN_RECON_ITERATIONS:
        return {
            "success": False,
            "coverage_checkpoint": True,
            "message": (
                "Coverage checkpoint: confirm reconnaissance and surface mapping are "
                "complete before finishing. This check fires only once."
            ),
            "objectives": _RECON_CHECKPOINT.strip(),
        }
    return None


# ---------------------------------------------------------------------------
# Mechanical coverage gate.  Unlike the one-shot recon checkpoint above, this
# reads the actual /workspace/endpoint_checklist.md through the EXISTING
# authenticated sandbox tool-server channel and blocks finish_scan while any
# entry is still untested/pending.  It re-checks on EVERY finish_scan call and
# is never latched off, so the model cannot self-attest its way past it.  If the
# checklist cannot be read (no sandbox, file absent, tool-server error) the gate
# degrades gracefully and lets the scan proceed rather than hard-blocking a scan
# that never created a checklist (e.g. quick mode).
# ---------------------------------------------------------------------------

# endpoint_checklist.md path, relative to /workspace (the read tool prepends it).
_CHECKLIST_PATH = "endpoint_checklist.md"
# Cap the number of pending entries echoed back so the response stays small.
_MAX_PENDING_LISTED = 10


def _run_coro_sync(coro: Any) -> Any:
    """Run an async coroutine to completion from sync code, even when an event
    loop is already running in the current thread, using a dedicated thread with
    its own loop. Returns the result; re-raises the coroutine's exception.
    """
    import asyncio
    import threading

    box: dict[str, Any] = {}

    def _runner() -> None:
        loop = asyncio.new_event_loop()
        try:
            box["result"] = loop.run_until_complete(coro)
        except BaseException as exc:  # noqa: BLE001 - carried to the caller thread and re-raised
            box["error"] = exc
        finally:
            loop.close()

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _untested_checklist_entries(checklist_text: str) -> list[str]:
    """Return the untested/pending checklist lines, using the SAME markers the
    deep-mode Pass 4 audit uses: an unchecked box ``[ ]`` or a ``pending`` /
    ``in-progress`` status. Checked ``[x]`` / tested / skipped entries are done.
    """
    untested: list[str] = []
    for raw in checklist_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if "[ ]" in line or "pending" in lowered or "in-progress" in lowered:
            untested.append(line)
    return untested


def _coverage_gate(agent_state: Any) -> dict[str, Any] | None:
    """Block finish_scan while endpoint_checklist.md still has untested entries.

    Reads the checklist through the existing authenticated tool-server channel
    (``execute_tool`` -> sandbox ``str_replace_editor`` view). Returns a blocking
    response if any entry is untested/pending, or ``None`` to allow completion.
    Any failure to read (no sandbox, missing file, tool-server error) returns
    ``None`` so scans that never had a checklist are not hard-blocked.
    """
    try:
        from strix.tools.executor import execute_tool

        result = _run_coro_sync(
            execute_tool(
                "str_replace_editor",
                agent_state,
                command="view",
                path=_CHECKLIST_PATH,
            )
        )
    except Exception:  # noqa: BLE001 - cannot verify coverage => degrade, do not block
        return None

    if not isinstance(result, dict) or result.get("error") or "content" not in result:
        # Checklist missing or unreadable => nothing to enforce => fall through.
        return None

    untested = _untested_checklist_entries(str(result["content"]))
    if not untested:
        return None

    plural = "y" if len(untested) == 1 else "ies"
    return {
        "success": False,
        "coverage_incomplete": True,
        "message": (
            f"Coverage gate: /workspace/endpoint_checklist.md still has {len(untested)} "
            f"untested/pending entr{plural}. Test — or explicitly mark skipped — every entry "
            "before finishing. This gate re-checks on every finish_scan call."
        ),
        "pending": untested[:_MAX_PENDING_LISTED],
    }


def _validate_root_agent(agent_state: Any) -> dict[str, Any] | None:
    if agent_state and hasattr(agent_state, "parent_id") and agent_state.parent_id is not None:
        return {
            "success": False,
            "error": "finish_scan_wrong_agent",
            "message": "This tool can only be used by the root/main agent",
            "suggestion": "If you are a subagent, use agent_finish from agents_graph tool instead",
        }
    return None


def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_graph

        if agent_state and agent_state.agent_id:
            current_agent_id = agent_state.agent_id
        else:
            return None

        active_agents = []
        stopping_agents = []

        for agent_id, node in _agent_graph["nodes"].items():
            if agent_id == current_agent_id:
                continue

            status = node.get("status", "unknown")
            if status == "running":
                active_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )
            elif status == "stopping":
                stopping_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )

        if active_agents or stopping_agents:
            response: dict[str, Any] = {
                "success": False,
                "error": "agents_still_active",
                "message": "Cannot finish scan: agents are still active",
            }

            if active_agents:
                response["active_agents"] = active_agents

            if stopping_agents:
                response["stopping_agents"] = stopping_agents

            response["suggestions"] = [
                "Use wait_for_message to wait for all agents to complete",
                "Use send_message_to_agent if you need agents to complete immediately",
                "Check agent_status to see current agent states",
            ]

            response["total_active"] = len(active_agents) + len(stopping_agents)

            return response

    except ImportError:
        pass
    except Exception:
        import logging

        logging.exception("Error checking active agents")

    return None


@register_tool(sandbox_execution=False)
def finish_scan(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_state: Any = None,
) -> dict[str, Any]:
    validation_error = _validate_root_agent(agent_state)
    if validation_error:
        return validation_error

    active_agents_error = _check_active_agents(agent_state)
    if active_agents_error:
        return active_agents_error

    validation_errors = []

    if not executive_summary or not executive_summary.strip():
        validation_errors.append("Executive summary cannot be empty")
    if not methodology or not methodology.strip():
        validation_errors.append("Methodology cannot be empty")
    if not technical_analysis or not technical_analysis.strip():
        validation_errors.append("Technical analysis cannot be empty")
    if not recommendations or not recommendations.strip():
        validation_errors.append("Recommendations cannot be empty")

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    # Coverage checkpoint — fires at most ONCE, and only if finish_scan is called
    # before any real recon/mapping (iteration below MIN_RECON_ITERATIONS). This
    # preserves the guard against premature termination WITHOUT forcing a fixed
    # number of rounds: the scan completes as soon as the surface is exhausted.
    # Pre-finish gates, in order: the one-shot recon checkpoint (unchanged), then
    # the mechanical coverage gate that reads endpoint_checklist.md through the
    # sandbox tool-server and blocks while any entry is untested/pending. The
    # coverage gate re-checks every call (not one-shot) and degrades gracefully if
    # the checklist can't be read.
    for _gate in (_coverage_checkpoint, _coverage_gate):
        gate_response = _gate(agent_state)
        if gate_response is not None:
            return gate_response

    # ------------------------------------------------------------------
    # Complete the scan for real.
    # ------------------------------------------------------------------
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.update_scan_final_fields(
                executive_summary=executive_summary.strip(),
                methodology=methodology.strip(),
                technical_analysis=technical_analysis.strip(),
                recommendations=recommendations.strip(),
            )

            vulnerability_count = len(tracer.vulnerability_reports)

            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
            }

        import logging

        logging.warning("Current tracer not available - scan results not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
    else:
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed (not persisted)",
            "warning": "Results could not be persisted - tracer unavailable",
        }
