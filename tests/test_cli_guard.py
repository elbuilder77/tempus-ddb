"""`tempus guard` is a thin door to the Tempus Guard CLI; without it, it says how to get it."""

import importlib.util

import pytest

from tests.test_cli import run_cli


def test_guard_is_listed_in_help():
    code, out, _ = run_cli(["--help"])
    assert code == 0
    assert "guard" in out


def test_guard_without_the_client_explains_how_to_install_it(tmp_path):
    # A stub package that fails to import stands in for "tempus-guard-cli is not installed".
    stub = tmp_path / "tempus_guard"
    stub.mkdir()
    (stub / "__init__.py").write_text("raise ImportError('not installed')\n")
    code, out, err = run_cli(["guard", "intent", "--help"], env={"PYTHONPATH": str(tmp_path)})
    assert code == 2
    assert "pip install tempus-guard-cli" in err
    assert out == ""


@pytest.mark.skipif(
    importlib.util.find_spec("tempus_guard") is None, reason="tempus-guard-cli not installed"
)
def test_guard_delegates_to_the_client_when_installed(tmp_path):
    # Options meant for tempus-guard itself go after `--`; subcommands pass through as they are.
    code, out, _ = run_cli(["guard", "--", "--version"])
    assert code == 0
    assert out.startswith("tempus-guard ")
    code, out, _ = run_cli(["guard", "intent", "--help"])
    assert code == 0
    assert "--agent-keyfile" in out and "--tenant-id" in out
    # tmp_path lives inside this repository, so a missing directory is the sure outsider.
    code, _, err = run_cli(["guard", "hook", "--repo", str(tmp_path / "missing"), "status"])
    assert code == 2
    assert "is not a directory" in err
