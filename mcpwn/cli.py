"""CLI entry point for mcpwn."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .models import Severity
from .report import print_report, to_json
from .scanner import Scanner


@click.group()
@click.version_option(__version__, prog_name="mcpwn")
def main() -> None:
    """mcpwn - Security scanner for MCP servers 🦞"""
    pass


@main.command()
@click.option("--stdio", "stdio_cmd", help="MCP server command (stdio transport)")
@click.option("--sse", "sse_url", help="MCP server URL (SSE transport)")
@click.option("--claude-config", is_flag=True, help="Scan all servers from Claude Desktop config")
@click.option("--checks", help="Comma-separated check IDs (e.g., MCP-001,MCP-002)")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "output_file", type=click.Path(), help="Save report to file")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low")
@click.option("--timeout", type=int, default=30, help="Per-check timeout in seconds")
def scan(
    stdio_cmd: str | None,
    sse_url: str | None,
    claude_config: bool,
    checks: str | None,
    output_format: str,
    output_file: str | None,
    severity: str,
    timeout: int,
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    console = Console()

    if not stdio_cmd and not sse_url and not claude_config:
        console.print("[red]Error: Specify --stdio, --sse, or --claude-config[/red]")
        sys.exit(1)

    check_ids = checks.split(",") if checks else None
    min_severity = Severity(severity)

    scanner = Scanner(
        check_ids=check_ids,
        min_severity=min_severity,
        timeout=timeout,
    )

    if claude_config:
        results = asyncio.run(_scan_claude_config(scanner, console))
    elif stdio_cmd:
        results = [asyncio.run(scanner.scan_stdio(stdio_cmd))]
    else:
        results = [asyncio.run(scanner.scan_sse(sse_url))]

    # Output
    for result in results:
        if output_format == "json":
            json_output = to_json(result)
            if output_file:
                Path(output_file).write_text(json_output)
                console.print(f"[green]Report saved to {output_file}[/green]")
            else:
                click.echo(json_output)
        else:
            print_report(result, console)
            if output_file:
                Path(output_file).write_text(to_json(result))
                console.print(f"  [dim]Report saved to {output_file}[/dim]")

    # Exit code based on findings
    total_critical = sum(r.critical_count for r in results)
    total_high = sum(r.high_count for r in results)
    if total_critical > 0:
        sys.exit(2)
    elif total_high > 0:
        sys.exit(1)


@main.command()
@click.option("--input", "input_file", required=True, type=click.Path(exists=True))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default="high")
def check(input_file: str, fail_on: str) -> None:
    """Check a JSON report and exit with non-zero if findings exceed threshold."""
    data = json.loads(Path(input_file).read_text())
    threshold = Severity(fail_on)

    findings = data.get("findings", [])
    over_threshold = [f for f in findings if Severity(f["severity"]) >= threshold]

    console = Console()
    if over_threshold:
        console.print(f"[red]FAIL: {len(over_threshold)} findings at or above {fail_on}[/red]")
        sys.exit(1)
    else:
        console.print(f"[green]PASS: No findings at or above {fail_on}[/green]")


async def _scan_claude_config(scanner: Scanner, console: Console) -> list:
    """Scan all MCP servers from Claude Desktop config."""
    config_paths = [
        Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
        Path.home() / ".config/claude/claude_desktop_config.json",
    ]

    config_path = None
    for p in config_paths:
        if p.exists():
            config_path = p
            break

    if not config_path:
        console.print("[red]Claude Desktop config not found[/red]")
        return []

    config = json.loads(config_path.read_text())
    servers = config.get("mcpServers", {})

    if not servers:
        console.print("[yellow]No MCP servers found in Claude config[/yellow]")
        return []

    console.print(f"[blue]Found {len(servers)} MCP servers in Claude config[/blue]")

    results = []
    for name, server_config in servers.items():
        console.print(f"\n[bold]Scanning: {name}[/bold]")
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        full_command = f"{command} {' '.join(args)}".strip()

        if full_command:
            result = await scanner.scan_stdio(full_command)
            results.append(result)

    return results


if __name__ == "__main__":
    main()
