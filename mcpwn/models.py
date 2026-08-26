"""Data models for mcpwn."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]


@dataclass
class Finding:
    check_id: str
    check_name: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    tool_name: str | None = None
    resource_uri: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceInfo:
    uri: str
    name: str
    description: str = ""
    mime_type: str = ""


@dataclass
class PromptInfo:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanTarget:
    transport: str  # "stdio", "sse", or "http"
    command: str | None = None  # for stdio
    url: str | None = None  # for sse
    tools: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
