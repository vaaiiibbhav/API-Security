"""Tests for SAGA CLI execution."""

import subprocess
import sys

from typer.testing import CliRunner

from saga.cli import app

runner = CliRunner()


def test_cli_runner_help():
    """Test CLI help output via CliRunner."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "SAGA: Security Analysis & Graph-based Audit Tool" in result.output


def test_cli_runner_info():
    """Test CLI info command output via CliRunner."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "SAGA Framework" in result.output
    assert "Target Base URL" in result.output


def test_cli_runner_version():
    """Test CLI --version output via CliRunner."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "SAGA version" in result.output


def test_module_cli_execution():
    """Test python -m saga.cli --help execution via subprocess."""
    result = subprocess.run(
        [sys.executable, "-m", "saga.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    expected_help = "SAGA: Security Analysis & Graph-based Audit Tool"
    assert expected_help in result.stdout or "Usage:" in result.stdout
