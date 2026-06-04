"""Run the Node-based frontend security harness as part of `pytest tests/`.

The actual assertions live in tests/frontend/run_frontend_tests.mjs (it executes
the real escHtml/safeLog/_normHost/_sameTarget source extracted from
templates/index.html). This wrapper just shells out to node so the whole suite
runs with one command; it skips cleanly when node is not installed.
"""
import os
import shutil
import subprocess

import pytest

_HERE = os.path.dirname(__file__)
_HARNESS = os.path.join(_HERE, "frontend", "run_frontend_tests.mjs")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_frontend_security_helpers():
    result = subprocess.run(
        ["node", _HARNESS],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Surface the harness output so failures are readable in pytest.
    print(result.stdout)
    if result.returncode != 0:
        pytest.fail(
            "Frontend security harness failed:\n"
            + result.stdout
            + ("\n" + result.stderr if result.stderr else "")
        )
