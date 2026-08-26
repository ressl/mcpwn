"""Report generation for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel

from . import __version__
from .models import ScanResult, Severity


def print_report(result: ScanResult, console: Console | None = None) -> None:
    """Print a rich terminal report."""
    if console is None:
        console = Console()

    # Banner
    console.print()
    console.print(
        Panel(
            f"[bold blue]mcpwn v{__version__}[/bold blue]  🦞\n[dim]MCP Security Scanner[/dim]",
            border_style="blue",
            expand=False,
        )
    )

    # Target info
    target = result.target
    if target.transport == "stdio":
        console.print(f"  [dim]Target:[/dim] {target.command} (stdio)")
    else:
        console.print(f"  [dim]Target:[/dim] {target.url} ({target.transport.upper()})")

    console.print(f"  [dim]Tools found:[/dim] {len(target.tools)}")
    console.print(f"  [dim]Resources found:[/dim] {len(target.resources)}")
    console.print(f"  [dim]Prompts found:[/dim] {len(target.prompts)}")
    console.print()

    if not result.findings:
        console.print("  [green]✅ No findings![/green]")
        console.print()
        return

    console.print("  [bold]Scanning...[/bold]")
    console.print()

    # Findings
    for finding in result.findings:
        sev = finding.severity
        color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "yellow",
            Severity.MEDIUM: "bright_yellow",
            Severity.LOW: "blue",
            Severity.INFO: "white",
        }[sev]

        label = f"  {sev.emoji} {sev.value.upper():8s}  {finding.check_id}  {finding.check_name}"
        console.print(f"[{color}]{label}[/{color}]")
        console.print(f"     {finding.description}")
        if finding.evidence:
            console.print(f"     [dim]{finding.evidence}[/dim]")
        console.print()

    # Summary
    console.print("  " + "─" * 44)
    parts = []
    if result.critical_count:
        parts.append(f"[red]{result.critical_count} critical[/red]")
    if result.high_count:
        parts.append(f"[yellow]{result.high_count} high[/yellow]")
    if result.medium_count:
        parts.append(f"[bright_yellow]{result.medium_count} medium[/bright_yellow]")
    if result.low_count:
        parts.append(f"[blue]{result.low_count} low[/blue]")

    console.print(f"  Results: {len(result.findings)} findings ({', '.join(parts)})")
    console.print(f"  Duration: {result.duration_seconds:.1f}s")

    if result.errors:
        console.print()
        for error in result.errors:
            console.print(f"  [red]⚠ {error}[/red]")

    console.print()


def _result_to_dict(result: ScanResult) -> dict:
    """Convert a scan result to a plain dict (shared by to_json and CLI output)."""
    return {
        "scanner": "mcpwn",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {
            "transport": result.target.transport,
            "command": result.target.command,
            "url": result.target.url,
            "tools_count": len(result.target.tools),
            "resources_count": len(result.target.resources),
            "prompts_count": len(result.target.prompts),
        },
        "summary": {
            "total": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "duration_seconds": round(result.duration_seconds, 2),
        },
        "findings": [
            {
                "check_id": f.check_id,
                "check_name": f.check_name,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "tool_name": f.tool_name,
                "resource_uri": f.resource_uri,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }


def to_json(result: ScanResult) -> str:
    """Convert scan result to JSON string."""
    return json.dumps(_result_to_dict(result), indent=2)


def _sarif_level(severity: Severity) -> str:
    """Map a severity to a SARIF result level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_run(result: ScanResult) -> dict:
    """Build a single SARIF run for one scan result."""
    rules: dict[str, dict] = {}
    for f in result.findings:
        if f.check_id not in rules:
            rules[f.check_id] = {
                "name": f.check_name.replace(" ", ""),
                "description": f.description,
            }

    return {
        "tool": {
            "driver": {
                "name": "mcpwn",
                "version": __version__,
                "informationUri": "https://github.com/ressl/mcpwn",
                "rules": [
                    {
                        "id": cid,
                        "name": info["name"],
                        "shortDescription": {"text": info["description"]},
                    }
                    for cid, info in rules.items()
                ],
            }
        },
        "results": [
            {
                "ruleId": f.check_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f"{f.description} — {f.evidence}"},
            }
            for f in result.findings
        ],
    }


def to_sarif(result: ScanResult) -> str:
    """Convert a scan result to a SARIF 2.1.0 JSON string."""
    return json.dumps(_sarif_log([result]), indent=2)


def _sarif_log(results: list[ScanResult]) -> dict:
    """Build a SARIF log with one run per scan result."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [_sarif_run(r) for r in results],
    }
