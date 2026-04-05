from typing import Any

from strix.tools.registry import register_tool


# ---------------------------------------------------------------------------
# Deep-dive phase prompts injected when finish_scan is called too early.
# Phase 0 completes normally (no gate).  Phases 1-3 are progressively harder.
# ---------------------------------------------------------------------------

_PHASE_PROMPTS = {
    1: """
╔══════════════════════════════════════════════════════════════════════╗
║           PHASE 1 COMPLETE — ADVANCING TO PHASE 2 (DEEP DIVE)       ║
╚══════════════════════════════════════════════════════════════════════╝

You attempted to finish, but the scan is NOT complete. Phase 1 covered broad
discovery. Phase 2 requires deep exploitation of everything you found.

MANDATORY PHASE 2 OBJECTIVES — execute ALL of these before calling finish_scan again:

1. ENDPOINT EXHAUSTION
   - List every URL/endpoint you discovered in Phase 1.
   - Test each one for IDOR, BAC, injection, and auth bypass independently.
   - Do not skip any endpoint because it "seems safe" — test it anyway.

2. PARAMETER FUZZING
   - For every POST/PUT endpoint: fuzz all parameters individually with boundary
     values, operator objects, SQL metacharacters, and null/empty values.
   - For every GET endpoint: fuzz all query parameters with the same payloads.

3. SECOND-ORDER ATTACKS
   - If Phase 1 found stored data anywhere: access that data from a DIFFERENT
     user/role to check if stored XSS or IDOR applies.
   - Test every "view your own profile/order/message" endpoint with another
     user's IDs substituted.

4. UI SECTION EXPANSION
   - Open the app in the browser. Click EVERY button, link, dropdown, and tab
     you have not yet clicked.
   - Fill out and submit every form you have not yet submitted.
   - Navigate to every page section: dashboard, profile, settings, admin,
     billing, notifications, API keys, integrations.

5. AUTHENTICATION RE-TEST
   - Try accessing every authenticated endpoint WITHOUT a session token.
   - Try accessing every admin endpoint with a standard user token.
   - Test password reset flow end-to-end if you haven't already.

DO NOT call finish_scan until all 5 objectives above are fully completed.
""",

    2: """
╔══════════════════════════════════════════════════════════════════════╗
║        PHASE 2 COMPLETE — ADVANCING TO PHASE 3 (EXPERT MODE)        ║
╚══════════════════════════════════════════════════════════════════════╝

Phase 2 is complete. Phase 3 requires expert-level techniques that go beyond
standard testing. You must now assume the application has hidden vulnerabilities
that basic testing cannot reveal.

MANDATORY PHASE 3 OBJECTIVES — ALL must be executed:

1. CHAINED ATTACK PATHS
   - Combine every finding from Phases 1 and 2. Example: Use a low-severity
     info-disclosure to get a user ID, then use that ID in an IDOR attack.
   - Identify every privilege escalation path: low-priv → admin, anonymous → user.
   - Map the kill chain: what is the maximum damage achievable by chaining
     all discovered vulnerabilities?

2. BUSINESS LOGIC ATTACKS
   - Test every numeric field for negative values, overflow, and race conditions.
   - Test every workflow for step-skipping: can you reach step 5 without step 3?
   - Test every price/quantity field: can you purchase at $0? Can you submit
     negative quantities to get credits?
   - Test coupon codes, referral codes, and discount logic for reuse/bypass.

3. ADVANCED INJECTION
   - For every JSON body endpoint: send MongoDB operator objects
     {"$ne": null}, {"$gt": ""}, {"$regex": ".*"} — check for boolean differential.
   - For every search field: test SSTI with {{7*7}}, ${7*7}, #{7*7}.
   - For every file upload: test path traversal in filename, polyglot files,
     SVG with XSS, and content-type bypass.

4. HTTP-LEVEL ATTACKS
   - Test Host header injection on all endpoints.
   - Test X-Forwarded-For, X-Real-IP, X-Original-URL header injection.
   - Test HTTP method override: X-HTTP-Method-Override: DELETE on POST endpoints.
   - Try HTTP/1.1 request smuggling (CL.TE or TE.CL) on any reverse-proxied endpoint.

5. JWT & SESSION ATTACKS (if auth uses tokens)
   - Decode every JWT and check algorithm. Try alg:none bypass.
   - Test algorithm confusion: RS256 → HS256 with public key as secret.
   - Test token reuse after logout.
   - Test predictable session IDs by collecting 5+ tokens and checking entropy.

6. SSRF ESCALATION
   - If Phase 1/2 found any SSRF: escalate it. Try accessing internal metadata
     endpoints (169.254.169.254, fd00:ec2::254), internal services on 127.0.0.1:*,
     and cloud IMDS endpoints.
   - Try SSRF via file://, gopher://, dict:// protocols.

DO NOT call finish_scan until all 6 objectives above are fully documented with evidence.
""",

    3: """
╔══════════════════════════════════════════════════════════════════════╗
║     PHASE 3 COMPLETE — ADVANCING TO PHASE 4 (FINAL VALIDATION)      ║
╚══════════════════════════════════════════════════════════════════════╝

Phases 1-3 are complete. Phase 4 is the FINAL VALIDATION sweep. Your job now
is to prove everything, consolidate everything, and maximize impact.

MANDATORY PHASE 4 OBJECTIVES — this is your last pass before reporting:

1. VALIDATE EVERY FINDING
   - Reproduce EVERY vulnerability found in Phases 1-3. Confirm it still works.
   - For each finding: capture the EXACT request/response pair as evidence.
   - Assign correct severity: does it require auth? Does it require user interaction?
     Is impact limited or full application compromise?
   - PURGE any finding where you cannot reproduce it or where the response
     is indistinguishable from normal application behavior.

2. FALSE POSITIVE AUDIT — DISCARD findings that match ANY of these:
   - XSS reported only because payload appeared in a JSON API response
     (not rendered in HTML — JSON never executes JavaScript).
   - NoSQL injection reported only because HTTP 500 occurred on operator object
     (type mismatch, not injection — must prove boolean differential or auth bypass).
   - SSRF reported only because DNS resolution occurred with no internal access.
   - CORS reported on a public endpoint that intentionally serves all origins.
   - Missing security headers reported as High/Critical severity.
   - Rate limiting absence on non-sensitive endpoints.

3. ATTACK CHAIN MAXIMIZATION
   - Build the highest-impact attack chain from all findings combined.
   - Describe the exact sequence: step 1 (exploit A) → step 2 (use result to
     exploit B) → step 3 (achieve full account takeover / data exfiltration / RCE).
   - This chain MUST appear in your final report as a "Critical Attack Path."

4. COVERAGE CONFIRMATION
   - List every endpoint discovered during the scan.
   - Confirm each one was tested.
   - List every UI section/page visited.
   - List every form submitted.
   - If any endpoint was NOT tested, test it now before finishing.

5. FINAL REPORT REQUIREMENTS
   Your finish_scan call MUST include:
   - executive_summary: overall risk rating, top 3 findings, business impact
   - methodology: all 4 phases, tools used, coverage percentage, what was tested
   - technical_analysis: every finding with title, severity, proof-of-concept
     request/response, CWE ID, and reproduction steps
   - recommendations: specific remediation for each finding, ordered by priority

NOW call finish_scan with a complete, validated, evidence-backed report.
""",
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

    # ------------------------------------------------------------------
    # DEEP PHASES GATE — intercept finish_scan until the final phase.
    # Each interception resets the max-iterations warning so the agent
    # doesn't get panicked into finishing early in the next phase.
    # ------------------------------------------------------------------
    if agent_state and hasattr(agent_state, "current_phase"):
        current_phase = agent_state.current_phase
        max_phases = getattr(agent_state, "max_phases", 4)

        if current_phase < max_phases - 1:
            next_phase = current_phase + 1
            agent_state.current_phase = next_phase
            agent_state.phase_iteration_start = agent_state.iteration
            # Reset warning flag so the agent doesn't panic-finish in Phase N+1
            agent_state.max_iterations_warning_sent = False

            phase_prompt = _PHASE_PROMPTS.get(next_phase, _PHASE_PROMPTS[1])
            return {
                "success": False,
                "phase_gate": True,
                "current_phase": current_phase,
                "next_phase": next_phase,
                "total_phases": max_phases,
                "message": (
                    f"Phase {current_phase + 1}/{max_phases} summary accepted. "
                    f"Advancing to Phase {next_phase + 1}/{max_phases}. "
                    f"You must complete the objectives below before calling finish_scan again."
                ),
                "phase_objectives": phase_prompt.strip(),
            }

    # ------------------------------------------------------------------
    # Final phase (or phases disabled) — complete the scan for real.
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
