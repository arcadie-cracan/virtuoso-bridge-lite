"""RB_LOCAL selects the daemon bind address before the auto-start.

``ramic_bridge.il`` ends with ``RBStart()``, so ``RBLocal`` must come from the
Virtuoso process environment (like ``RB_PORT``); assigning it after ``load()``
is too late for the first bind.

The live case is opt-in, in an isolated local Virtuoso session:
  VB_RUN_IPC_LOG_TESTS=1 VB_TEST_VIRTUOSO=/path/to/virtuoso \
    pytest tests/test_rb_local_bind.py
"""
from __future__ import annotations

from importlib import resources
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time

import pytest

from virtuoso_bridge import VirtuosoClient

_RESOURCES = "virtuoso_bridge.virtuoso.basic.resources"


def _bridge_il() -> str:
    return resources.files(_RESOURCES).joinpath("ramic_bridge.il").read_text()


def test_rblocal_is_read_from_environment_before_autostart():
    text = _bridge_il()
    assignment = re.search(r'^RBLocal = getShellEnvVar\("RB_LOCAL"\) == "1"$',
                           text, re.MULTILINE)
    assert assignment, "RBLocal must be initialised from RB_LOCAL"
    autostart = text.rindex("\nRBStart()")
    assert assignment.start() < autostart
    # No later top-level reset may undo the environment value.
    assert not re.search(r"^RBLocal = (nil|t)\b", text, re.MULTILINE)


def _wait(predicate, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("timed out waiting for Virtuoso test condition")


@pytest.mark.skipif(
    os.getenv("VB_RUN_IPC_LOG_TESTS") != "1",
    reason="set VB_RUN_IPC_LOG_TESTS=1 and VB_TEST_VIRTUOSO for isolated live tests",
)
@pytest.mark.parametrize("value,local", [(None, False), ("0", False), ("1", True)])
def test_rb_local_controls_first_bind(tmp_path, value, local):
    executable = os.environ["VB_TEST_VIRTUOSO"]
    work = tmp_path / "work"
    work.mkdir()
    resource = resources.files(_RESOURCES)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    token = secrets.token_hex(32)
    token_path = work / "token"
    token_path.write_text(token)
    token_path.chmod(0o600)
    identity = work / "identity.txt"
    environment = os.environ.copy()
    environment.pop("RB_LOCAL", None)
    if value is not None:
        environment["RB_LOCAL"] = value
    environment.update(
        RB_PORT=str(port), RB_TOKEN_PATH=str(token_path),
        RB_DAEMON_PATH=str(resource.joinpath("ramic_bridge_daemon_3.py")),
        RB_PYTHON_PATH=sys.executable, RB_IDENTITY_PATH=str(identity),
    )
    startup = work / "startup.il"
    startup.write_text(f'load({json.dumps(str(resource.joinpath("ramic_bridge.il")))})\n')
    client = VirtuosoClient(port=port, timeout=5, daemon_token=token, log_to_ciw=False)

    with (work / "stdout.log").open("w") as output:
        process = subprocess.Popen(
            [executable, "-nograph", "-nocdsinit", "-restore", str(startup),
             "-log", str(work / "CDS.log")],
            cwd=work, env=environment, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            _wait(lambda: identity.exists() and "pid=" in identity.read_text())
            result = client.execute_skill("list(RBLocal RBLastBind)", timeout=5)
            assert not result.errors, result
            expected_host = "127.0.0.1" if local else "0.0.0.0"
            assert result.output == f'({"t" if local else "nil"} "{expected_host}:{port}")'
        finally:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
