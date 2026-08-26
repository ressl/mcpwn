"""Tests for mcpwn.yaml config parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpwn.config import ScanConfig
from mcpwn.models import Severity


def write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "mcpwn.yaml"
    p.write_text(content)
    return p


def test_round_trip(tmp_path):
    p = write_config(
        tmp_path,
        """
severity_threshold: high
timeout: 15
aggressive: true
checks:
  MCP-001:
    enabled: false
  MCP-004:
    internal_ranges:
      - "10.0.0.0/8"
""",
    )
    cfg = ScanConfig.from_file(p)
    assert cfg.severity_threshold == Severity.HIGH
    assert cfg.timeout == 15
    assert cfg.aggressive is True
    assert cfg.disabled_ids() == {"MCP-001"}
    assert cfg.check_options() == {
        "MCP-004": {"internal_ranges": ["10.0.0.0/8"]}
    }


def test_unknown_top_level_key(tmp_path):
    p = write_config(tmp_path, "bogus_key: 1\n")
    with pytest.raises(ValueError, match="Unknown config key"):
        ScanConfig.from_file(p)


def test_empty_file_defaults(tmp_path):
    p = write_config(tmp_path, "")
    cfg = ScanConfig.from_file(p)
    assert cfg.severity_threshold == Severity.LOW
    assert cfg.timeout == 30
    assert cfg.aggressive is False
    assert cfg.disabled_ids() == set()


def test_invalid_severity(tmp_path):
    p = write_config(tmp_path, "severity_threshold: extreme\n")
    with pytest.raises(ValueError):
        ScanConfig.from_file(p)


def test_non_mapping_root(tmp_path):
    p = write_config(tmp_path, "- a\n- b\n")
    with pytest.raises(ValueError, match="root must be a mapping"):
        ScanConfig.from_file(p)
