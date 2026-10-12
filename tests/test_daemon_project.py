"""Project identity guard: one user's Virtuoso sessions in different projects.

Daemon side: ``ramic_bridge.il`` and the daemons report ``RB_PROJECT`` (else
``CURRENT_PROJECT``) in the banner, the signed handshake and the identity
file, and the loader removes its own identity record when the daemon exits.

Client side: ``VB_PROJECT`` binds a workspace to a project; a reachable daemon
that reports another project (the same user, same token, same host) is
refused before any SKILL runs, and ``start`` / ``status`` say so.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import threading
from importlib import resources

import pytest

from virtuoso_bridge import cli
from virtuoso_bridge.daemon_guard import (
    PROJECT_MISMATCH_PREFIX,
    check_daemon_project,
    compare_daemon_project,
    expected_project,
)
from virtuoso_bridge.models import ExecutionStatus
from virtuoso_bridge.transport.tunnel import SSHClient
from virtuoso_bridge.virtuoso.basic.bridge import VirtuosoClient, _default_remote_port

STX = "\x02"
_RESOURCES = "virtuoso_bridge.virtuoso.basic.resources"


class ProjectDaemon:
    """Auth-off fake daemon.

    *project* is what the handshake reports (``None``: a daemon that predates
    project identity, no ``project`` key); *env_project* is what
    ``getShellEnvVar("CURRENT_PROJECT")`` answers in its Virtuoso.
    """

    def __init__(self, project: str | None = None, env_project: str = ""):
        self.project = project
        self.env_project = env_project
        self.executed: list[str] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            req = json.loads(b"".join(chunks).decode("utf-8"))
            if req.get("op") == "hello":
                caps = {"proto": 1, "auth": "off", "daemon": "fake-project", "virtuoso_pid": 4242}
                if self.project is not None:
                    caps["project"] = self.project
                conn.sendall(f"{STX}{json.dumps(caps)}".encode("utf-8"))
                return
            skill = req["skill"]
            self.executed.append(skill)
            if 'getShellEnvVar("CURRENT_PROJECT")' in skill:
                body = f'"{self.env_project}"' if self.env_project else "nil"
            elif skill.strip() == "1+1":
                body = "2"
            else:
                body = "nil"
            conn.sendall(f"{STX}{body}".encode("utf-8"))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self._sock.close()


@pytest.fixture(autouse=True)
def _unauthenticated_doubles(monkeypatch):
    # The doubles model an auth-off daemon; the real setup never sets this.
    monkeypatch.setenv("VB_ALLOW_UNAUTHENTICATED_DAEMON", "1")
    monkeypatch.delenv("VB_PROJECT", raising=False)


def _client(port: int, project: str) -> VirtuosoClient:
    return VirtuosoClient(port=port, timeout=5, log_to_ciw=False, expected_project=project)


# ---------------------------------------------------------------------------
# Workspace binding and the decision
# ---------------------------------------------------------------------------


def test_expected_project_profile_suffix(monkeypatch) -> None:
    monkeypatch.setenv("VB_PROJECT", "EULER")
    monkeypatch.setenv("VB_PROJECT_lab", "WSSI")
    assert expected_project(None) == "EULER"
    assert expected_project("lab") == "WSSI"
    assert expected_project("other") == "EULER"
    monkeypatch.delenv("VB_PROJECT")
    monkeypatch.delenv("VB_PROJECT_lab")
    assert expected_project(None) == ""
    assert expected_project("lab") == ""


def test_compare_daemon_project() -> None:
    assert compare_daemon_project("", "EULER").ok  # unbound workspace: unchecked
    assert compare_daemon_project("WSSI", "WSSI").ok
    other = compare_daemon_project("WSSI", "EULER")
    assert not other.ok
    assert other.error.startswith(PROJECT_MISMATCH_PREFIX)
    assert "'EULER'" in other.error and "'WSSI'" in other.error
    assert "Agent Bridge... -> Start" in other.error
    none = compare_daemon_project("WSSI", "")
    assert not none.ok and "did not report a project" in none.error


# ---------------------------------------------------------------------------
# Default port: per user and project
# ---------------------------------------------------------------------------


def test_default_port_per_user_and_project(monkeypatch) -> None:
    monkeypatch.delenv("VB_REMOTE_USER", raising=False)
    # Without a project the historical per-user port is unchanged.
    assert _default_remote_port("acracan", "") == 65423
    assert _default_remote_port("acracan") == 65423
    euler = _default_remote_port("acracan", "EULER")
    wssi = _default_remote_port("acracan", "WSSI")
    assert euler != wssi
    for port in (euler, wssi):
        assert 61000 <= port <= 64999
    digest = hashlib.sha1(b"acracan/EULER").hexdigest()
    assert euler == 61000 + int(digest[:8], 16) % 4000
    # Another user in the same project gets another port.
    assert _default_remote_port("student", "EULER") != euler
    # VB_PROJECT supplies the project when the caller passes none.
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    assert _default_remote_port("acracan") == wssi


def test_tunnel_from_env_derives_the_project_port(monkeypatch) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    for key in ("VB_REMOTE_PORT", "VB_LOCAL_PORT", "VB_REMOTE_USER", "VB_PROJECT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("VB_REMOTE_HOST", "canopus")
    monkeypatch.setenv("VB_REMOTE_USER", "acracan")
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    ssh = SSHClient.from_env(keep_remote_files=True)
    assert ssh.remote_port == _default_remote_port("acracan", "WSSI")
    monkeypatch.setenv("VB_REMOTE_PORT", "61234")
    assert SSHClient.from_env(keep_remote_files=True).remote_port == 61234


# ---------------------------------------------------------------------------
# The client refuses another project's daemon before any SKILL runs
# ---------------------------------------------------------------------------


def test_client_refuses_other_project_daemon() -> None:
    daemon = ProjectDaemon(project="EULER")
    try:
        result = _client(daemon.port, "WSSI").execute_skill("1+1", timeout=5)
        assert result.status == ExecutionStatus.ERROR
        assert result.errors and result.errors[0].startswith(PROJECT_MISMATCH_PREFIX)
        assert daemon.executed == []  # nothing ran in the wrong session
    finally:
        daemon.close()


def test_client_accepts_matching_project() -> None:
    daemon = ProjectDaemon(project="WSSI")
    try:
        client = _client(daemon.port, "WSSI")
        result = client.execute_skill("1+1", timeout=5)
        assert result.status == ExecutionStatus.SUCCESS and result.output == "2"
        assert client.daemon_project() == "WSSI"
        assert daemon.executed == ["1+1"]
    finally:
        daemon.close()


def test_client_asks_pre_project_daemon_for_current_project() -> None:
    daemon = ProjectDaemon(project=None, env_project="EULER")
    try:
        result = _client(daemon.port, "WSSI").execute_skill("1+1", timeout=5)
        assert result.status == ExecutionStatus.ERROR
        assert result.errors[0].startswith(PROJECT_MISMATCH_PREFIX)
        # Only the identity query reached Virtuoso, never the command.
        assert daemon.executed == ['getShellEnvVar("CURRENT_PROJECT")']
    finally:
        daemon.close()
    daemon = ProjectDaemon(project=None, env_project="WSSI")
    try:
        result = _client(daemon.port, "WSSI").execute_skill("1+1", timeout=5)
        assert result.status == ExecutionStatus.SUCCESS
        assert daemon.executed == ['getShellEnvVar("CURRENT_PROJECT")', "1+1"]
    finally:
        daemon.close()


def test_client_refuses_daemon_without_project_when_bound() -> None:
    daemon = ProjectDaemon(project="")
    try:
        result = _client(daemon.port, "WSSI").execute_skill("1+1", timeout=5)
        assert result.status == ExecutionStatus.ERROR
        assert "did not report a project" in result.errors[0]
        assert daemon.executed == []
    finally:
        daemon.close()


def test_unbound_workspace_is_not_checked() -> None:
    daemon = ProjectDaemon(project="EULER")
    try:
        client = _client(daemon.port, "")
        assert client.execute_skill("1+1", timeout=5).status == ExecutionStatus.SUCCESS
        assert client.daemon_project() == "EULER"
    finally:
        daemon.close()


def test_check_daemon_project_classifies(monkeypatch) -> None:
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    daemon = ProjectDaemon(project="EULER")
    try:
        check = check_daemon_project(_client(daemon.port, "WSSI"), profile=None, timeout=5)
        assert not check.ok and check.daemon_project == "EULER"
    finally:
        daemon.close()
    # Nothing listening (refused connect): skipped, never a pass or a failure.
    class _Unloaded:
        def daemon_project(self, timeout=5):
            raise ConnectionRefusedError("[Errno 111] Connection refused")

    check = check_daemon_project(_Unloaded(), profile=None, timeout=2)
    assert check.ok and check.skipped

    # A daemon that answers but cannot be queried is refused, not passed.
    class _Mute:
        def daemon_project(self, timeout=5):
            raise RuntimeError("daemon query failed: busy")

    check = check_daemon_project(_Mute(), profile=None, timeout=2)
    assert not check.ok and "could not determine" in check.error
    monkeypatch.delenv("VB_PROJECT")
    assert check_daemon_project(_Mute(), profile=None).ok


# ---------------------------------------------------------------------------
# CLI: start (local mode) and status report the mismatch
# ---------------------------------------------------------------------------


def test_cli_local_start_reports_project_mismatch(monkeypatch, capsys) -> None:
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    monkeypatch.setattr(cli, "_state_or_local_daemon_token", lambda state, profile: None)
    daemon = ProjectDaemon(project="EULER")
    try:
        rc = cli._check_local_daemon_project(None, {"port": daemon.port})
    finally:
        daemon.close()
    out = capsys.readouterr().out
    assert rc == 1
    assert "PROJECT MISMATCH" in out and "workspace project: WSSI" in out
    daemon = ProjectDaemon(project="WSSI")
    try:
        rc = cli._check_local_daemon_project(None, {"port": daemon.port})
    finally:
        daemon.close()
    assert rc == 0
    assert "[daemon] OK - project WSSI" in capsys.readouterr().out


def test_local_state_belongs_to_the_workspace_port(tmp_path, monkeypatch) -> None:
    """state.json is per user: another workspace's port means 'not set up here'."""
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    monkeypatch.setenv("VB_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("VB_REMOTE_PORT", raising=False)
    (tmp_path / "state.json").write_text(json.dumps({"mode": "local", "port": 61000}), encoding="utf-8")
    assert SSHClient.is_running(None)  # nothing configured: trust the saved setup
    monkeypatch.setenv("VB_REMOTE_PORT", "61000")
    assert SSHClient.is_running(None)  # this workspace's port
    monkeypatch.setenv("VB_REMOTE_PORT", "62000")
    assert not SSHClient.is_running(None)  # another project's workspace: redo setup


def test_from_env_refuses_other_project_daemon(tmp_path, monkeypatch) -> None:
    """The Python entry point refuses too, with the project message."""
    from virtuoso_bridge.daemon_guard import DaemonProjectError

    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.load_vb_env", lambda *a, **k: None)
    monkeypatch.setenv("VB_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VB_REMOTE_HOST", "localhost")
    monkeypatch.setenv("VB_REMOTE_USER", "")
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    daemon = ProjectDaemon(project="EULER")
    try:
        monkeypatch.setenv("VB_REMOTE_PORT", str(daemon.port))
        (tmp_path / "state.json").write_text(
            json.dumps({"mode": "local", "port": daemon.port}), encoding="utf-8")
        with pytest.raises(DaemonProjectError, match=PROJECT_MISMATCH_PREFIX):
            VirtuosoClient.from_env(timeout=5, log_to_ciw=False)
        assert daemon.executed == []
    finally:
        daemon.close()


def test_cli_eval_refusal_is_an_error_line(tmp_path, monkeypatch, capsys) -> None:
    """`virtuoso-bridge eval` against another project's daemon: exit 1, no traceback."""
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.load_vb_env", lambda *a, **k: None)
    monkeypatch.setattr("virtuoso_bridge.cli._load_cli_env", lambda: None)
    monkeypatch.setenv("VB_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VB_REMOTE_HOST", "localhost")
    monkeypatch.setenv("VB_REMOTE_USER", "")
    monkeypatch.setenv("VB_PROJECT", "WSSI")
    daemon = ProjectDaemon(project="EULER")
    try:
        monkeypatch.setenv("VB_REMOTE_PORT", str(daemon.port))
        (tmp_path / "state.json").write_text(
            json.dumps({"mode": "local", "port": daemon.port}), encoding="utf-8")
        rc = cli.main(["eval", "getWorkingDir()"])
        assert daemon.executed == []
    finally:
        daemon.close()
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.startswith("ERROR: daemon project mismatch")
    assert "Traceback" not in captured.err


def test_from_env_local_mode_carries_the_token_before_start(tmp_path, monkeypatch) -> None:
    """Local mode, saved setup of another workspace: the client is still authenticated."""
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    monkeypatch.setattr("virtuoso_bridge.virtuoso.basic.bridge.load_vb_env", lambda *a, **k: None)
    monkeypatch.setenv("VB_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VB_BRIDGE_TOKEN", str(tmp_path / "token"))
    monkeypatch.setenv("VB_REMOTE_HOST", "localhost")
    monkeypatch.setenv("VB_REMOTE_USER", "")
    monkeypatch.setenv("VB_REMOTE_PORT", "61001")
    monkeypatch.delenv("VB_PROJECT", raising=False)
    (tmp_path / "state.json").write_text(
        json.dumps({"mode": "local", "port": 62002}), encoding="utf-8")  # another workspace
    client = VirtuosoClient.from_env(timeout=5, log_to_ciw=False)
    assert client.port == 61001
    assert client.daemon_token and len(client.daemon_token) == 64
    assert (tmp_path / "token").read_text().strip() == client.daemon_token


def test_cli_status_helpers_detect_mismatch() -> None:
    assert cli._is_project_mismatch([f"{PROJECT_MISMATCH_PREFIX}: x"])
    assert not cli._is_project_mismatch(["Connection refused"])
    assert not cli._is_project_mismatch(None)


# ---------------------------------------------------------------------------
# Identity file: project recorded, stale records flagged
# ---------------------------------------------------------------------------


def test_identity_file_reports_project_and_staleness(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("virtuoso_bridge.transport.tunnel.load_vb_env", lambda *a, **k: None)
    identity = tmp_path / "daemon_identity.txt"
    identity.write_text(
        "host=canopus\nip=10.0.0.1\npid=99999999\nbind=127.0.0.1:61234\n"
        "project=EULER\nvirtuoso_pid=99999998\nworkdir=/work/projects/EULER/analog/users/u\n"
        "started=Oct 12 2026\n",
        encoding="utf-8",
    )
    client = SSHClient(remote_host="localhost", remote_user="", port=61234)
    client._remote_identity_path = str(identity)
    record = client.read_daemon_identity()
    assert record["project"] == "EULER"
    assert record["workdir"].endswith("/users/u")
    assert record["virtuoso_pid"] == "99999998"
    assert "stale" in record and "99999999" in record["stale"]


# ---------------------------------------------------------------------------
# Shipped CIW resources
# ---------------------------------------------------------------------------


def _resource(name: str) -> str:
    return resources.files(_RESOURCES).joinpath(name).read_text()


def test_loader_records_and_removes_its_identity() -> None:
    il = _resource("ramic_bridge.il")
    assert re.search(r'^RBProject = or\(getShellEnvVar\("RB_PROJECT"\) getShellEnvVar\("CURRENT_PROJECT"\) ""\)$',
                     il, re.MULTILINE)
    write = il[il.index("procedure(RBWriteIdentity()"):il.index("procedure(RBIdentityOwnedp()")]
    for key in ("project=%s", "virtuoso_pid=%L", "workdir=%s", "started=%s"):
        assert key in write
    finish = il[il.index("procedure(RBIpcFinishHandler("):il.index("procedure(RBQuoteShellArg(")]
    assert "RBRemoveIdentity()" in finish
    # the banner's project token is parsed into RBLastProject
    assert 'equal(substring(tok 1 8) "project=")' in il
    assert 'equal(substring(tok 1 13) "virtuoso_pid=")' in il
    assert "getpid()" not in il  # SKILL has no getpid(): the banner carries it
    # and a fresh start forgets the previous daemon's project
    assert il.count('RBLastProject = ""') >= 3


@pytest.mark.parametrize("name", ["ramic_bridge_daemon_3.py", "ramic_bridge_daemon_27.py"])
def test_daemons_report_the_session_project(name: str) -> None:
    text = _resource(name)
    assert 'PROJECT_ENV = "RB_PROJECT"' in text
    assert 'PROJECT_FALLBACK_ENV = "CURRENT_PROJECT"' in text
    assert '"project": SESSION_PROJECT' in text
    assert re.search(r'\[RB-banner\] pid=.* auth=.* project=.* virtuoso_pid=', text)
