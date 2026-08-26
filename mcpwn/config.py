"""Config file support for mcpwn (mcpwn.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

KNOWN_TOP_LEVEL_KEYS = {"severity_threshold", "timeout", "aggressive", "checks"}


@dataclass
class CheckConfig:
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanConfig:
    severity_threshold: Severity = Severity.LOW
    timeout: int = 30
    aggressive: bool = False
    checks: dict[str, CheckConfig] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: Path) -> "ScanConfig":
        """Parse a mcpwn.yaml config file into a ScanConfig."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            return cls()

        if not isinstance(raw, dict):
            raise ValueError(f"Config root must be a mapping, got {type(raw).__name__}")

        unknown = set(raw) - KNOWN_TOP_LEVEL_KEYS
        if unknown:
            raise ValueError(f"Unknown config key: {sorted(unknown)[0]}")

        severity_threshold = Severity.LOW
        if "severity_threshold" in raw:
            severity_threshold = Severity(raw["severity_threshold"])

        timeout = int(raw.get("timeout", 30))
        aggressive = bool(raw.get("aggressive", False))

        checks: dict[str, CheckConfig] = {}
        for check_id, check_conf in (raw.get("checks") or {}).items():
            if not isinstance(check_conf, dict):
                raise ValueError(f"Check config for {check_id} must be a mapping")
            enabled = bool(check_conf.get("enabled", True))
            options = {k: v for k, v in check_conf.items() if k != "enabled"}
            checks[check_id] = CheckConfig(enabled=enabled, options=options)

        return cls(
            severity_threshold=severity_threshold,
            timeout=timeout,
            aggressive=aggressive,
            checks=checks,
        )

    def disabled_ids(self) -> set[str]:
        """Return the set of explicitly disabled check IDs."""
        return {cid for cid, conf in self.checks.items() if not conf.enabled}

    def check_options(self) -> dict[str, dict[str, Any]]:
        """Return {check_id: options} for enabled checks."""
        return {cid: conf.options for cid, conf in self.checks.items() if conf.enabled}
