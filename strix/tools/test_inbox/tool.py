"""``test_inbox`` — read a mail.tm test inbox for auth-flow testing (host-side).

Reads durable test-domain mailboxes (e.g. ``member07@dollicons.com``) through the
public mail.tm API so an agent can complete reset-password / email-verification /
account-takeover flows across multiple configured accounts — extracting the token
or link from the email the target just sent.

Security-critical design (each guarantee is load-bearing, not incidental):

* HOST-SIDE ONLY (``sandbox_execution=False``) + ``httpx`` ``trust_env=False`` — the
  mail.tm traffic never traverses the Caido scan proxy, so the account password
  (in the ``POST /token`` body) and the JWT (in the ``Authorization`` header) never
  land in proxy history that another agent could read via ``list_requests``.
* Credentials/tokens NEVER cross the tool boundary: no account address, password,
  or JWT is ever returned, logged, or placed in an error message. Errors reference
  the alias only (e.g. "authentication failed for member07").
* Message bodies are returned as inert, untrusted data — never rendered, never
  auto-fetching URLs/images in the body, never auto-downloading attachments
  (metadata only). The envelope is marked ``"untrusted_content": true`` and body
  text is capped at ``max_chars``.
* Per-account graceful degradation: one misconfigured/failing alias never blocks
  the others. Missing/empty configuration degrades cleanly; the tool never crashes.
* mail.tm calls are self-throttled to <= 8 QPS and honor ``429`` / ``Retry-After``.

Configuration (set at runtime — never committed):
    MAILTM_ACCOUNTS="member07,member08"          # roster of aliases only (no secrets)
    MAILTM_ACCT_member07_ADDRESS="member07@dollicons.com"  # optional if MAILTM_DOMAIN set
    MAILTM_ACCT_member07_PASSWORD="..."
    MAILTM_DOMAIN="dollicons.com"                # optional: default addr to <alias>@<domain>
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import httpx

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

_BASE_URL = "https://api.mail.tm"
_HTTP_TIMEOUT_S = 20.0
_MIN_INTERVAL_S = 1.0 / 8.0  # <= 8 QPS per the documented mail.tm limit
_WAIT_CAP_S = 60  # hard cap on wait_for_message (stagnation-detector safe; see design)
_POLL_INTERVAL_S = 4.0
_DEFAULT_MAX_CHARS = 16_000
_PAGE_SIZE = 30  # mail.tm returns 30 messages per page
_FORMATS = ("text", "html", "both")

_ALLOWED_MODES = frozenset(
    {
        "list_accounts",
        "list_messages",
        "get_message",
        "search_messages",
        "latest_message",
        "wait_for_message",
    }
)

# In-memory, per-process JWT cache keyed by alias. Never persisted, never returned.
_TOKEN_CACHE: dict[str, str] = {}
_throttle_lock = threading.Lock()
_last_call = [0.0]  # module-level mutable holder (avoids the `global` statement)


# ---------------------------------------------------------------------------
# Configuration (env) — reads only, resolves aliases -> credentials internally.
# ---------------------------------------------------------------------------
def _resolve_accounts() -> dict[str, dict[str, str]]:
    """Return {alias: {"address","password","status"}} from the environment.

    ``status`` is "ok" only when both an address (explicit or derived from
    MAILTM_DOMAIN) and a password are present, else "misconfigured". The password
    lives only inside this internal dict and is never surfaced.
    """
    roster = os.environ.get("MAILTM_ACCOUNTS", "")
    aliases = [a.strip() for a in roster.split(",") if a.strip()]
    domain = os.environ.get("MAILTM_DOMAIN", "").strip()

    accounts: dict[str, dict[str, str]] = {}
    for alias in aliases:
        address = os.environ.get(f"MAILTM_ACCT_{alias}_ADDRESS", "").strip()
        if not address and domain:
            address = f"{alias}@{domain}"
        password = os.environ.get(f"MAILTM_ACCT_{alias}_PASSWORD", "")
        status = "ok" if (address and password) else "misconfigured"
        accounts[alias] = {"address": address, "password": password, "status": status}
    return accounts


def _account_creds(account: str | None) -> tuple[str, str] | None:
    """Resolve (address, password) for a configured+ok alias, else None."""
    if not account:
        return None
    entry = _resolve_accounts().get(account)
    if not entry or entry["status"] != "ok":
        return None
    return entry["address"], entry["password"]


# ---------------------------------------------------------------------------
# HTTP plumbing — direct TLS to api.mail.tm, no proxy env, no credential logging.
# ---------------------------------------------------------------------------
def _throttle() -> None:
    with _throttle_lock:
        wait = _MIN_INTERVAL_S - (time.monotonic() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.monotonic()


def _authenticate(address: str, password: str) -> str | None:
    """POST /token -> JWT string, or None on failure. Never logs body/credentials."""
    _throttle()
    try:
        with httpx.Client(trust_env=False, timeout=_HTTP_TIMEOUT_S) as client:
            resp = client.post(
                f"{_BASE_URL}/token",
                json={"address": address, "password": password},
            )
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        token = resp.json().get("token")
    except ValueError:
        return None
    return token if isinstance(token, str) and token else None


def _api_get(
    alias: str,
    address: str,
    password: str,
    path: str,
    params: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Authenticated GET with one 401 re-auth and one 429 backoff.

    Returns (status_code, json_or_None); status_code -1 = network/transport error.
    Never logs the Authorization header or request/response bodies.
    """
    token = _TOKEN_CACHE.get(alias)
    if not token:
        token = _authenticate(address, password)
        if not token:
            return 401, None
        _TOKEN_CACHE[alias] = token

    for attempt in range(2):
        _throttle()
        try:
            with httpx.Client(trust_env=False, timeout=_HTTP_TIMEOUT_S) as client:
                resp = client.get(
                    f"{_BASE_URL}{path}",
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.HTTPError:
            return -1, None

        if resp.status_code == 401 and attempt == 0:
            _TOKEN_CACHE.pop(alias, None)
            token = _authenticate(address, password)
            if not token:
                return 401, None
            _TOKEN_CACHE[alias] = token
            continue
        if resp.status_code == 429 and attempt == 0:
            retry_after = resp.headers.get("Retry-After", "")
            delay = min(float(retry_after), 5.0) if retry_after.isdigit() else 2.0
            time.sleep(delay)
            continue
        try:
            data = resp.json()
        except ValueError:
            data = None
        return resp.status_code, data

    return 429, None


# ---------------------------------------------------------------------------
# Shaping helpers — strip anything sensitive; mark bodies untrusted.
# ---------------------------------------------------------------------------
def _summary(msg: dict[str, Any]) -> dict[str, Any]:
    """Header-level summary. Deliberately omits the account's own 'to' address."""
    frm = msg.get("from") or {}
    return {
        "id": msg.get("id"),
        "from": {"address": frm.get("address"), "name": frm.get("name")},
        "subject": msg.get("subject"),
        "intro": msg.get("intro"),
        "createdAt": msg.get("createdAt"),
        "seen": msg.get("seen"),
        "hasAttachments": msg.get("hasAttachments"),
    }


def _cap(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


def _full_message(msg: dict[str, Any], fmt: str, max_chars: int) -> dict[str, Any]:
    """Full message as INERT untrusted data: body text/html capped, attachments
    metadata only (no downloadUrl), never rendered or auto-fetched.
    """
    out = _summary(msg)
    truncated = False
    if fmt in ("text", "both"):
        body, cut = _cap(str(msg.get("text") or ""), max_chars)
        out["text"] = body
        truncated = truncated or cut
    if fmt in ("html", "both"):
        html_val = msg.get("html")
        html_str = "\n".join(html_val) if isinstance(html_val, list) else str(html_val or "")
        body, cut = _cap(html_str, max_chars)
        out["html"] = body
        truncated = truncated or cut
    out["attachments"] = [
        {
            "filename": a.get("filename"),
            "contentType": a.get("contentType"),
            "size": a.get("size"),
        }
        for a in (msg.get("attachments") or [])
    ]
    out["untrusted_content"] = True
    if truncated:
        out["truncated"] = True
    return out


def _matches(msg: dict[str, Any], from_match: str | None, subject_query: str | None) -> bool:
    if from_match:
        frm = msg.get("from") or {}
        hay = f"{frm.get('address', '')} {frm.get('name', '')}".lower()
        if from_match.lower() not in hay:
            return False
    return not (
        subject_query and subject_query.lower() not in (msg.get("subject") or "").lower()
    )


def _err(message: str) -> dict[str, Any]:
    return {"success": False, "error": message}


def _fetch_messages(
    alias: str, address: str, password: str, limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Fetch up to `limit` message summaries (paginating as needed).

    Returns (messages, error_dict); error_dict is None on success.
    """
    collected: list[dict[str, Any]] = []
    pages = max(1, (limit + _PAGE_SIZE - 1) // _PAGE_SIZE)
    for page in range(1, pages + 1):
        status, data = _api_get(alias, address, password, "/messages", {"page": page})
        if status == 401:
            return [], _err(f"authentication failed for {alias}")
        if status != 200 or not isinstance(data, dict):
            return [], _err(f"mail.tm API error for {alias} (status {status})")
        members = data.get("hydra:member") or data.get("member") or []
        collected.extend(members)
        if len(members) < _PAGE_SIZE:
            break
    return collected[:limit], None


# ---------------------------------------------------------------------------
# Modes.
# ---------------------------------------------------------------------------
def _mode_list_accounts() -> dict[str, Any]:
    accounts = _resolve_accounts()
    return {
        "success": True,
        "mode": "list_accounts",
        "accounts": [{"alias": a, "status": v["status"]} for a, v in accounts.items()],
    }


def _mode_list_messages(account: str | None, limit: int) -> dict[str, Any]:
    creds = _account_creds(account)
    if not creds or account is None:
        return _err(f"account '{account}' is not configured or is misconfigured")
    messages, error = _fetch_messages(account, creds[0], creds[1], limit)
    if error:
        return error
    return {
        "success": True,
        "mode": "list_messages",
        "account": account,
        "count": len(messages),
        "messages": [_summary(m) for m in messages],
    }


def _mode_get_message(
    account: str | None, message_id: str | None, fmt: str, max_chars: int
) -> dict[str, Any]:
    creds = _account_creds(account)
    if not creds or account is None:
        return _err(f"account '{account}' is not configured or is misconfigured")
    if not message_id:
        return _err("get_message requires 'message_id'")
    status, data = _api_get(account, creds[0], creds[1], f"/messages/{message_id}")
    if status == 401:
        return _err(f"authentication failed for {account}")
    if status == 404:
        return _err(f"message not found for {account}")
    if status != 200 or not isinstance(data, dict):
        return _err(f"mail.tm API error for {account} (status {status})")
    return {
        "success": True,
        "mode": "get_message",
        "account": account,
        "message": _full_message(data, fmt, max_chars),
    }


def _mode_search_messages(
    account: str | None,
    query: str | None,
    from_match: str | None,
    limit: int,
    deep: bool,
) -> dict[str, Any]:
    creds = _account_creds(account)
    if not creds or account is None:
        return _err(f"account '{account}' is not configured or is misconfigured")
    messages, error = _fetch_messages(account, creds[0], creds[1], limit)
    if error:
        return error

    header_hits = [m for m in messages if _matches(m, from_match, query)]
    if query:
        for m in messages:
            if m not in header_hits and query.lower() in (m.get("intro") or "").lower():
                header_hits.append(m)

    result: dict[str, Any] = {
        "success": True,
        "mode": "search_messages",
        "account": account,
        "matched": [_summary(m) for m in header_hits],
    }

    if deep and query:
        deep_hits: list[dict[str, Any]] = []
        scanned = 0
        for m in messages:
            if m in header_hits:
                continue
            status, data = _api_get(account, creds[0], creds[1], f"/messages/{m.get('id')}")
            scanned += 1
            body = str(data.get("text") or "") if isinstance(data, dict) else ""
            if status == 200 and query.lower() in body.lower():
                deep_hits.append(_summary(m))
        result["deep_matched"] = deep_hits
        result["deep_note"] = (
            f"deep body scan fetched {scanned} extra messages (rate-limited to <=8 QPS)"
        )

    return result


def _mode_latest_message(
    account: str | None,
    from_match: str | None,
    query: str | None,
    fmt: str,
    max_chars: int,
) -> dict[str, Any]:
    creds = _account_creds(account)
    if not creds or account is None:
        return _err(f"account '{account}' is not configured or is misconfigured")
    messages, error = _fetch_messages(account, creds[0], creds[1], _PAGE_SIZE)
    if error:
        return error
    match = next((m for m in messages if _matches(m, from_match, query)), None)
    if not match:
        return {"success": True, "mode": "latest_message", "account": account, "found": False}
    got = _mode_get_message(account, match.get("id"), fmt, max_chars)
    return got | {"mode": "latest_message", "found": True}


def _mode_wait_for_message(
    account: str | None,
    from_match: str | None,
    query: str | None,
    timeout_s: int,
    fmt: str,
    max_chars: int,
) -> dict[str, Any]:
    creds = _account_creds(account)
    if not creds or account is None:
        return _err(f"account '{account}' is not configured or is misconfigured")

    # Hard cap at 60s (stagnation-detector compatibility). timeout_s<=0 -> 30s default.
    effective = 30 if timeout_s <= 0 else min(timeout_s, _WAIT_CAP_S)
    deadline = time.monotonic() + effective
    while True:
        messages, error = _fetch_messages(account, creds[0], creds[1], _PAGE_SIZE)
        if error:
            return error
        match = next((m for m in messages if _matches(m, from_match, query)), None)
        if match:
            got = _mode_get_message(account, match.get("id"), fmt, max_chars)
            return got | {"mode": "wait_for_message", "found": True}
        if time.monotonic() >= deadline:
            return {
                "success": True,
                "mode": "wait_for_message",
                "account": account,
                "found": False,
                "waited_s": round(effective),
            }
        time.sleep(min(_POLL_INTERVAL_S, max(0.0, deadline - time.monotonic())))


def _dispatch_message_mode(
    mode: str,
    account: str | None,
    message_id: str | None,
    query: str | None,
    from_match: str | None,
    limit: int,
    fmt: str,
    cap: int,
    timeout_s: int,
    deep: bool,
) -> dict[str, Any]:
    if mode == "list_messages":
        return _mode_list_messages(account, limit)
    if mode == "get_message":
        return _mode_get_message(account, message_id, fmt, cap)
    if mode == "search_messages":
        return _mode_search_messages(account, query, from_match, limit, deep)
    if mode == "latest_message":
        return _mode_latest_message(account, from_match, query, fmt, cap)
    return _mode_wait_for_message(account, from_match, query, timeout_s, fmt, cap)


@register_tool(sandbox_execution=False)
def test_inbox(
    mode: str,
    account: str | None = None,
    message_id: str | None = None,
    query: str | None = None,
    from_match: str | None = None,
    limit: int = 20,
    fmt: str = "text",
    timeout_s: int = 0,
    max_chars: int = _DEFAULT_MAX_CHARS,
    deep: bool = False,
) -> dict[str, Any]:
    if mode not in _ALLOWED_MODES:
        return _err(f"unknown mode {mode!r}. Valid modes: {', '.join(sorted(_ALLOWED_MODES))}")

    fmt = fmt if fmt in _FORMATS else "text"
    cap = max_chars if max_chars > 0 else _DEFAULT_MAX_CHARS

    if mode == "list_accounts":
        return _mode_list_accounts()

    # Every other mode needs at least one configured+ok account.
    if not any(v["status"] == "ok" for v in _resolve_accounts().values()):
        return _err("test inbox not configured (set MAILTM_ACCOUNTS + per-alias ADDRESS/PASSWORD)")

    try:
        return _dispatch_message_mode(
            mode, account, message_id, query, from_match, limit, fmt, cap, timeout_s, deep
        )
    except Exception:  # noqa: BLE001 - never crash the scan; never leak internals
        logger.warning("test_inbox mode %s failed for account %s", mode, account)
        return _err(f"test_inbox failed for account '{account}' (mode {mode})")
