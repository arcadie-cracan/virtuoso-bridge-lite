"""Daemon identity guards: cross-user and cross-project Virtuoso sessions.

The remote daemon port is a host-wide, first-come-first-served resource: any
user's Virtuoso on the same machine can end up listening on the port our SSH
tunnel forwards to.  Whoever owns the listener receives every SKILL expression
we send, so before using a reachable daemon we verify it belongs to the SSH
login user.

Verification layers (first non-empty answer wins):

1. ``getShellEnvVar("USER")`` in the daemon's Virtuoso process.
2. ``getShellEnvVar("LOGNAME")`` — Virtuoso launched from a stripped
   environment often has neither, so an empty answer means *indeterminate*,
   never *match*.
3. ``getpid()`` in Virtuoso, then ``stat -c %U /proc/<pid>`` (fallback
   ``ps -o user=``) over SSH — the process owner is authoritative and does
   not depend on the process environment at all.

The expected user comes from ``VB_REMOTE_USER[_<profile>]`` and, when unset,
from SSH ``whoami`` on the tunnel — so ssh-config-only setups are checked too.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from virtuoso_bridge.models import ExecutionStatus

logger = logging.getLogger(__name__)

_TRUTHY = {"1", "true", "yes", "on"}
OVERRIDE_ENV = "VB_ALLOW_CROSS_USER_DAEMON"

# execute_skill error fragments that mean "no daemon is behind the tunnel"
# (refused connect, or the SSH -L local end accepted and the remote connect
# failed -> empty response / RST).  Anything else while the TCP endpoint
# answers (e.g. a timeout) means *something* is listening but would not
# identify itself — treated as indeterminate and refused.
_DAEMON_NOT_LOADED_MARKERS = (
    "Connection refused",
    "Empty response from daemon",
    "Connection reset",
    "Broken pipe",
    "10054",  # WSAECONNRESET
    "10061",  # WSAECONNREFUSED
)


@dataclass(frozen=True)
class DaemonUserCheck:
    ok: bool
    expected_user: str = ""
    daemon_user: str = ""
    error: str = ""
    # True when the check did not run because no daemon answered (fresh
    # setup, CIW load pending).  Callers may proceed; re-verified later.
    skipped: bool = False


@dataclass(frozen=True)
class DaemonHostCheck:
    ok: bool
    configured_host: str = ""
    endpoint_hostname: str = ""
    daemon_hostname: str = ""
    error: str = ""


def cross_user_override_enabled() -> bool:
    return os.getenv(OVERRIDE_ENV, "").strip().lower() in _TRUTHY


def expected_remote_user(profile: str | None, runner: Any = None) -> str:
    """Unix user the tunnel is expected to reach.

    ``VB_REMOTE_USER[_<profile>]`` first; without it, SSH ``whoami`` through
    the tunnel's runner (ssh-config-only setups).  Returns "" only when even
    the SSH login name is unavailable (typically local mode).
    """
    suffix = f"_{profile}" if profile else ""
    configured = os.getenv(f"VB_REMOTE_USER{suffix}", "").strip()
    if configured:
        return configured
    if runner is not None:
        try:
            result = runner.run_command("whoami")
            if result.returncode == 0:
                who = (result.stdout or "").strip()
                if who:
                    return who
        except Exception:
            logger.debug("whoami fallback for expected daemon user failed", exc_info=True)
    return ""


def clean_skill_output(value: str | None) -> str:
    text = (value or "").strip()
    if text.lower() == "nil":
        return ""
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text.replace("\\n", "\n").replace('\\"', '"')


def _normalized_hostnames(host: str) -> set[str]:
    value = (host or "").strip().rstrip(".").lower()
    if not value:
        return set()
    return {value, value.split(".", 1)[0]}


def check_daemon_host(
    *,
    daemon_hostname: str,
    endpoint_hostname: str,
    configured_host: str,
) -> DaemonHostCheck:
    """Compare the banner host with the OS host reached by the tunnel endpoint."""
    daemon_names = _normalized_hostnames(daemon_hostname)
    # SSH aliases are not necessarily related to the target's OS hostname.
    # Only diagnose a mismatch after probing the endpoint hostname itself.
    endpoint_names = _normalized_hostnames(endpoint_hostname)
    ok = not daemon_names or not endpoint_names or bool(daemon_names & endpoint_names)
    error = ""
    if not ok:
        error = (
            f"daemon banner reports host {daemon_hostname!r}, but the configured "
            f"tunnel endpoint {configured_host!r} resolves over SSH to "
            f"{endpoint_hostname or '(unknown)'!r}"
        )
    return DaemonHostCheck(
        ok=ok,
        configured_host=configured_host,
        endpoint_hostname=endpoint_hostname,
        daemon_hostname=daemon_hostname,
        error=error,
    )


def classify_daemon_query_failure(error_text: str) -> str:
    """Classify a failed identity query.

    Returns ``"not_loaded"`` when the failure pattern means no daemon is
    listening behind the tunnel (normal pre-``load()`` state), or
    ``"indeterminate"`` when the TCP endpoint answered but the daemon could
    not identify itself — e.g. a busy foreign daemon — which callers should
    treat as a hard failure, not a pass.
    """
    text = error_text or ""
    for marker in _DAEMON_NOT_LOADED_MARKERS:
        if marker in text:
            return "not_loaded"
    return "indeterminate"


def _run_skill(client: Any, expr: str, timeout: int) -> str:
    result = client.execute_skill(expr, timeout=timeout)
    if result.status != ExecutionStatus.SUCCESS:
        raise RuntimeError("; ".join(result.errors) or f"daemon query failed: {expr}")
    return clean_skill_output(result.output)


def _daemon_user_from_process(client: Any, runner: Any, timeout: int) -> str:
    """Resolve the Virtuoso process owner over SSH via ``getpid()``.

    Does not depend on the Virtuoso process environment at all, so it also
    identifies daemons whose ``USER``/``LOGNAME`` are unset.
    """
    if runner is None:
        return ""
    try:
        pid = _run_skill(client, "getpid()", timeout)
    except Exception:
        return ""
    pid = pid.strip()
    if not pid.isdigit():
        return ""
    # Best-effort: retain the PID on the client so other consumers (status,
    # process-owner cross-checks) reuse it instead of asking again.  Duck
    # typed — guard callers may be plain test doubles.
    try:
        client._remote_virtuoso_pid = int(pid)
    except Exception:
        pass
    for cmd in (f"stat -c %U /proc/{pid} 2>/dev/null", f"ps -o user= -p {pid} 2>/dev/null"):
        try:
            result = runner.run_command(cmd)
        except Exception:
            continue
        if result.returncode == 0:
            owner = (result.stdout or "").strip().splitlines()
            owner = owner[-1].strip() if owner else ""
            if owner:
                return owner
    return ""


def query_daemon_user(client: Any, *, timeout: int = 5, runner: Any = None) -> str:
    """Best-effort Unix user of the daemon's Virtuoso process.

    Raises when the daemon does not answer; returns "" when it answers but
    its user cannot be determined (callers must not treat "" as a match).
    """
    if runner is None:
        runner = getattr(client, "ssh_runner", None)
    for expr in ('getShellEnvVar("USER")', 'getShellEnvVar("LOGNAME")'):
        user = _run_skill(client, expr, timeout)
        if user:
            return user
    return _daemon_user_from_process(client, runner, timeout)


def check_daemon_user(
    client: Any,
    *,
    profile: str | None,
    timeout: int = 5,
    runner: Any = None,
) -> DaemonUserCheck:
    """Verify the reachable daemon belongs to the expected Unix user.

    Never raises: unreachable/unloaded daemons produce ``ok=True,
    skipped=True``; an answering daemon that cannot be identified, or whose
    user differs from the expected one, produces ``ok=False`` with ``error``.
    """
    if runner is None:
        runner = getattr(client, "ssh_runner", None)
    expected = expected_remote_user(profile, runner=runner)

    if cross_user_override_enabled():
        try:
            daemon_user = query_daemon_user(client, timeout=timeout, runner=runner)
        except Exception:
            daemon_user = ""
        return DaemonUserCheck(ok=True, expected_user=expected, daemon_user=daemon_user)

    try:
        daemon_user = query_daemon_user(client, timeout=timeout, runner=runner)
    except Exception as exc:
        if classify_daemon_query_failure(str(exc)) == "not_loaded":
            return DaemonUserCheck(ok=True, expected_user=expected, skipped=True)
        return DaemonUserCheck(
            ok=False,
            expected_user=expected,
            error=(
                f"could not determine the Unix user of the daemon behind the "
                f"tunnel ({exc}); refusing a possibly foreign Virtuoso session"
            ),
        )

    if not expected:
        # Nothing to compare against (no VB_REMOTE_USER and no SSH login
        # name) — typically local mode; keep the historical permissive path.
        return DaemonUserCheck(ok=True, expected_user="", daemon_user=daemon_user)

    if not daemon_user:
        return DaemonUserCheck(
            ok=False,
            expected_user=expected,
            error=(
                f"daemon did not report its Unix user; refusing a possibly "
                f"foreign Virtuoso session (expected {expected!r})"
            ),
        )

    if daemon_user != expected:
        return DaemonUserCheck(
            ok=False,
            expected_user=expected,
            daemon_user=daemon_user,
            error=(
                f"daemon Unix user {daemon_user!r} does not match configured "
                f"or tunnel user {expected!r}"
            ),
        )
    return DaemonUserCheck(ok=True, expected_user=expected, daemon_user=daemon_user)


# ---------------------------------------------------------------------------
# Project guard: the same user's sessions in different projects
# ---------------------------------------------------------------------------
#
# On the ETTI flow every project module exports CURRENT_PROJECT, each project
# gets its own bridge port, and the project menu starts the daemon with
# RB_PROJECT.  The daemon reports that project in its signed handshake (older
# daemons: ``getShellEnvVar("CURRENT_PROJECT")`` in Virtuoso).  A workspace
# declares the project it is for with ``VB_PROJECT[_<profile>]``; a reachable
# daemon of another project is refused before any SKILL runs.  It is the same
# user, so the token and the user check cannot tell the sessions apart.

PROJECT_ENV = "VB_PROJECT"
PROJECT_MISMATCH_PREFIX = "daemon project mismatch"


class DaemonProjectError(RuntimeError):
    """The reachable daemon belongs to another project's Virtuoso session."""


@dataclass(frozen=True)
class DaemonProjectCheck:
    ok: bool
    expected_project: str = ""
    daemon_project: str = ""
    error: str = ""
    # True when no daemon answered (nothing to compare; re-verified later).
    skipped: bool = False


def expected_project(profile: str | None) -> str:
    """Project this workspace is for: ``VB_PROJECT[_<profile>]``.

    Empty means unchecked (setups without projects, or a workspace that is
    not bound to one).
    """
    suffix = f"_{profile}" if profile else ""
    value = os.getenv(f"{PROJECT_ENV}{suffix}", "").strip()
    if not value and suffix:
        value = os.getenv(PROJECT_ENV, "").strip()
    return value


def compare_daemon_project(expected: str, reported: str | None) -> DaemonProjectCheck:
    """Decide whether a daemon reporting *reported* may serve *expected*."""
    expected = (expected or "").strip()
    reported = (reported or "").strip()
    if not expected:
        return DaemonProjectCheck(ok=True, daemon_project=reported)
    if not reported:
        return DaemonProjectCheck(
            ok=False,
            expected_project=expected,
            error=(
                f"{PROJECT_MISMATCH_PREFIX}: the daemon did not report a project, "
                f"but this workspace is for {expected!r}. The Virtuoso session was "
                f"not started from a project module (or its bridge predates "
                f"project identity); refusing a session that cannot be confirmed"
            ),
        )
    if reported != expected:
        return DaemonProjectCheck(
            ok=False,
            expected_project=expected,
            daemon_project=reported,
            error=(
                f"{PROJECT_MISMATCH_PREFIX}: the daemon belongs to your {reported!r} "
                f"Virtuoso session, but this workspace is for {expected!r}. Start "
                f"the Agent Bridge in the {expected} session ({expected} menu -> "
                f"Agent Bridge... -> Start) and make sure VB_REMOTE_PORT/VB_LOCAL_PORT "
                f"are that project's port ({expected} menu -> Agent Client Setup...)"
            ),
        )
    return DaemonProjectCheck(ok=True, expected_project=expected, daemon_project=reported)


def query_daemon_project(client: Any, *, timeout: int = 5) -> str:
    """Project of the daemon's Virtuoso session ("" when it reports none).

    From the signed handshake when the daemon reports it, else from
    ``getShellEnvVar("CURRENT_PROJECT")`` in Virtuoso.  Raises when the
    daemon does not answer.
    """
    fetch = getattr(client, "daemon_project", None)
    if callable(fetch):
        return (fetch(timeout=timeout) or "").strip()
    return _run_skill(client, 'getShellEnvVar("CURRENT_PROJECT")', timeout)


def check_daemon_project(
    client: Any,
    *,
    profile: str | None,
    timeout: int = 5,
) -> DaemonProjectCheck:
    """Verify the reachable daemon belongs to this workspace's project.

    Never raises: an unreachable daemon produces ``ok=True, skipped=True``;
    a daemon that answers but reports no project, another project, or that
    cannot be queried produces ``ok=False`` with ``error``.
    """
    expected = expected_project(profile)
    if not expected:
        return DaemonProjectCheck(ok=True)
    try:
        reported = query_daemon_project(client, timeout=timeout)
    except Exception as exc:
        if classify_daemon_query_failure(str(exc)) == "not_loaded":
            return DaemonProjectCheck(ok=True, expected_project=expected, skipped=True)
        return DaemonProjectCheck(
            ok=False,
            expected_project=expected,
            error=(
                f"{PROJECT_MISMATCH_PREFIX}: could not determine the project of the "
                f"daemon ({exc}); refusing a session that cannot be confirmed"
            ),
        )
    return compare_daemon_project(expected, reported)
