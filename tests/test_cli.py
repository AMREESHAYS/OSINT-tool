from typer.testing import CliRunner

from osint.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.stdout


def test_modules_lists_registry():
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    assert "dns" in result.stdout and "username" in result.stdout


def test_scan_unknown_target_errors():
    result = runner.invoke(app, ["scan", "has spaces here"])
    assert result.exit_code != 0
