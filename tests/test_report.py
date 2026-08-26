"""Tests for report generation (JSON and SARIF)."""

from __future__ import annotations

import json

from mcpwn import __version__
from mcpwn.models import Finding, ScanResult, ScanTarget, Severity
from mcpwn.report import to_json, to_sarif


def make_result() -> ScanResult:
    target = ScanTarget(transport="stdio", command="python server.py")
    result = ScanResult(target=target)
    result.findings = [
        Finding(
            check_id="MCP-001",
            check_name="Tool Poisoning",
            severity=Severity.CRITICAL,
            description="Hidden instruction",
            evidence='Matched in tool "x"',
            remediation="Fix it",
        ),
        Finding(
            check_id="MCP-004",
            check_name="SSRF via Tools",
            severity=Severity.MEDIUM,
            description="URL param",
            evidence='Tool "y" accepts URLs',
            remediation="Validate",
        ),
        Finding(
            check_id="MCP-006",
            check_name="Missing Input Validation",
            severity=Severity.LOW,
            description="No schema",
            evidence='Tool "z" has no schema',
            remediation="Add schema",
        ),
    ]
    return result


def test_to_json_parses_and_version():
    data = json.loads(to_json(make_result()))
    assert data["version"] == __version__
    assert data["scanner"] == "mcpwn"
    assert len(data["findings"]) == 3


def test_to_sarif_structure():
    sarif = json.loads(to_sarif(make_result()))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpwn"
    assert run["tool"]["driver"]["version"] == __version__
    assert len(run["results"]) == 3


def test_to_sarif_rules_one_per_check():
    sarif = json.loads(to_sarif(make_result()))
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["MCP-001", "MCP-004", "MCP-006"]
    names = {r["id"]: r["name"] for r in run["tool"]["driver"]["rules"]}
    assert names["MCP-001"] == "ToolPoisoning"  # spaces stripped


def test_to_sarif_level_mapping():
    sarif = json.loads(to_sarif(make_result()))
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["MCP-001"] == "error"
    assert levels["MCP-004"] == "warning"
    assert levels["MCP-006"] == "note"


def test_to_sarif_message_joins_description_and_evidence():
    sarif = json.loads(to_sarif(make_result()))
    text = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "Hidden instruction" in text
    assert "Matched in tool" in text


def test_to_sarif_no_locations():
    sarif = json.loads(to_sarif(make_result()))
    for result in sarif["runs"][0]["results"]:
        assert "locations" not in result
