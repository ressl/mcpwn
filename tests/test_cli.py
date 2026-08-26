import json
import sys

from click.testing import CliRunner
from conftest import VULNERABLE_SERVER

from mcpwn.cli import main


def report_with_findings(findings: list[dict]) -> str:
    return json.dumps({"scanner": "mcpwn", "version": "0.2.0", "findings": findings})


def test_scan_no_target_exits_1():
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code == 1
    assert "exactly one" in result.output


def test_scan_two_targets_exits_1():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--stdio", "x", "--sse", "http://y"])
    assert result.exit_code == 1
    assert "exactly one" in result.output


def test_scan_unknown_check_exits_1():
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--stdio", "python server.py", "--checks", "MCP-999"]
    )
    assert result.exit_code == 1
    assert "Unknown check ID: MCP-999" in result.output


def test_check_fail_high(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(
        report_with_findings(
            [
                {
                    "check_id": "MCP-012",
                    "check_name": "Secrets in Resources",
                    "severity": "critical",
                    "description": "Secret exposed",
                    "evidence": "AKIA...",
                    "remediation": "Fix",
                }
            ]
        )
    )
    runner = CliRunner()
    result = runner.invoke(main, ["check", "--input", str(report), "--fail-on", "high"])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_check_clean_report_exits_0(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(report_with_findings([]))
    runner = CliRunner()
    result = runner.invoke(main, ["check", "--input", str(report), "--fail-on", "high"])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_check_array_report_fail(tmp_path):
    """`check` accepts the multi-result JSON array from --claude-config --output."""
    report = tmp_path / "multi.json"
    finding = {
        "check_id": "MCP-012",
        "check_name": "Secrets in Resources",
        "severity": "critical",
        "description": "Secret exposed",
        "evidence": "AKIA...",
        "remediation": "Fix",
    }
    report.write_text(
        json.dumps(
            [
                {"scanner": "mcpwn", "findings": [finding]},
                {"scanner": "mcpwn", "findings": []},
            ]
        )
    )
    runner = CliRunner()
    result = runner.invoke(main, ["check", "--input", str(report), "--fail-on", "high"])
    assert result.exit_code == 1
    assert "FAIL: 1 findings" in result.output


def test_check_array_report_clean_exits_0(tmp_path):
    report = tmp_path / "multi.json"
    report.write_text(json.dumps([{"findings": []}, {"findings": []}]))
    runner = CliRunner()
    result = runner.invoke(main, ["check", "--input", str(report), "--fail-on", "high"])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_explicit_severity_flag_overrides_config_threshold(tmp_path):
    """--severity low must win over severity_threshold: high in the config."""
    cfg = tmp_path / "mcpwn.yaml"
    cfg.write_text("severity_threshold: high\n")
    cmd = f"{sys.executable} {VULNERABLE_SERVER}"
    runner = CliRunner()

    # Without --severity: config threshold high filters out MCP-004 medium findings
    no_flag = runner.invoke(
        main,
        [
            "scan",
            "--stdio",
            cmd,
            "--config",
            str(cfg),
            "--checks",
            "MCP-004",
            "--format",
            "json",
        ],
    )
    assert no_flag.exit_code == 1
    assert not any(
        f["severity"] == "medium" for f in json.loads(no_flag.output)["findings"]
    )

    # Explicit --severity low overrides the config threshold
    with_flag = runner.invoke(
        main,
        [
            "scan",
            "--stdio",
            cmd,
            "--config",
            str(cfg),
            "--checks",
            "MCP-004",
            "--severity",
            "low",
            "--format",
            "json",
        ],
    )
    assert with_flag.exit_code == 1
    assert any(
        f["severity"] == "medium" for f in json.loads(with_flag.output)["findings"]
    )
