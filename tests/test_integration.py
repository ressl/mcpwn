"""End-to-end integration tests against the vulnerable demo server."""

from __future__ import annotations

import sys

import pytest
from conftest import VULNERABLE_SERVER

from mcpwn.scanner import Scanner

SAFE_EXPECTED = {
    "MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005",
    "MCP-006", "MCP-008", "MCP-009", "MCP-011", "MCP-012",
}


@pytest.mark.asyncio
async def test_safe_scan_full_server():
    scanner = Scanner()
    result = await scanner.scan_stdio(f"{sys.executable} {VULNERABLE_SERVER}")
    assert result.errors == []
    fired = {f.check_id for f in result.findings}
    assert SAFE_EXPECTED <= fired
    # Safe mode: no confirmed SSRF, no command injection
    assert not any("Confirmed SSRF" in f.description for f in result.findings)
    assert not any(f.check_id == "MCP-013" for f in result.findings)


@pytest.mark.asyncio
async def test_aggressive_scan_adds_probes():
    scanner = Scanner(aggressive=True)
    result = await scanner.scan_stdio(f"{sys.executable} {VULNERABLE_SERVER}")
    assert result.errors == []
    fired = {f.check_id for f in result.findings}
    assert SAFE_EXPECTED <= fired
    assert any("Confirmed SSRF" in f.description for f in result.findings)
    assert any(
        f.check_id == "MCP-013" and "Confirmed command injection" in f.description
        for f in result.findings
    )


@pytest.mark.asyncio
async def test_mcp007_and_mcp010_no_findings_against_server():
    scanner = Scanner()
    result = await scanner.scan_stdio(f"{sys.executable} {VULNERABLE_SERVER}")
    assert not any(f.check_id == "MCP-007" for f in result.findings)
    assert not any(f.check_id == "MCP-010" for f in result.findings)
