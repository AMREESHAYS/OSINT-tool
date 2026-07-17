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


# Using --only with a non-existent module name selects zero modules, so the scan
# completes instantly with no network — lets us test CLI plumbing offline.
def test_scan_prints_auth_notice_by_default():
    result = runner.invoke(app, ["scan", "example.com", "--only", "none"])
    assert result.exit_code == 0
    assert "authorized to test" in result.stdout


def test_scan_quiet_suppresses_panel_and_notice():
    result = runner.invoke(app, ["scan", "example.com", "--only", "none", "-q"])
    assert result.exit_code == 0
    assert "authorized to test" not in result.stdout


def test_scan_prints_summary():
    result = runner.invoke(app, ["scan", "example.com", "--only", "none"])
    assert result.exit_code == 0
    assert "risk" in result.stdout.lower()
