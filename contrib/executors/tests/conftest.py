"""Fixtures for the contrib executor tests.

Mirrors `tests/conftest.py` in the repository root: these tests run in their own pytest
invocation, so the core conftest is not loaded here.
"""

import gc
import re
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

# pytest's own tmp_path keeps only this many sanitized characters of the node
# id. The raw id is not a path: quotes, colons and braces are illegal on
# Windows (WinError 123) and a 128-character value blows past MAX_PATH
# (WinError 267) once it is used as a subprocess cwd.
_NODE_DIR_MAX = 30


def _safe_node_dirname(node_name: str) -> str:
    cleaned = re.sub(r"[\W]", "_", node_name)[:_NODE_DIR_MAX]
    return cleaned or "test"


@pytest.fixture
def tmp_path(request):
    """Per-test directory without pytest's Windows-only 0o700 ACL.

    The name follows pytest's tmp_path rule (word characters, 30-character
    cap) instead of the raw node id. Tests should keep writing through this
    fixture; a parameter value is never a directory name.
    """
    root = Path.cwd() / "scratch" / "pytest-managed"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{_safe_node_dirname(request.node.name)}-{uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        gc.collect()
        shutil.rmtree(path, ignore_errors=True)
        try:
            root.rmdir()
            root.parent.rmdir()
        except OSError:
            # Parallel or still-open test resources may keep the shared root alive.
            pass
