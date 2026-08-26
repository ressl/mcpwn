"""CLI entry point for mcpwn."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .checks.registry import CHECK_MAP
from .config import ScanConfig
from .models import Severity
from .report import _result_to_dict, _sarif_log, print_report, to_json
from .scanner import Scanner

DEFAULT_CONFIG_PATH = Path("mcpwn.yaml")
DEFAULT_TIMEOUT = 30
DEFAULT_SEVERITY = "low"


@click.group()
@click.version_option(__version__, prog_name="mcpwn")
def main() -> None:
    """mcpwn - Security scanner for MCP servers 🦞"""
    pass


@main.command()
@click.option("--stdio", "stdio_cmd", help="MCP server command (stdio transport)")
@click.option("--sse", "sse_url", help="MCP server URL (SSE transport)")
@click.option("--http", "http_url", help="MCP server URL (Streamable HTTP transport)")
@click.option("--claude-config", is_flag=True, help="Scan all servers from Claude Desktop config")
@click.option("--config", "config_file", type=click.Path(exists=True), help="Path to mcpwn.yaml config")
@click.option("--checks", help="Comma-separated check IDs (e.g., MCP-001,MCP-002)")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "sarif"]), default="text")
@click.option("--output", "output_file", type=click.Path(), help="Save report to file")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default=DEFAULT_SEVERITY)
@click.option("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-check timeout in seconds")
@click.option(
    "--aggressive",
    is_flag=True,
    help="Enable active probes (internal IPs, callback URLs, injection payloads)",
)
def scan(
    stdio_cmd: str | None,
    sse_url: str | None,
    http_url: str | None,
    claude_config: bool,
    config_file: str | None,
    checks: str | None,
    output_format: str,
    output_file: str | None,
    severity: str,
    timeout: int,
    aggressive: bool,
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    console = Console()

    targets = sum(1 for t in (stdio_cmd, sse_url, http_url) if t) + (1 if claude_config else 0)
    if targets != 1:
        console.print(
            "[red]Error: Specify exactly one of --stdio, --sse, --http, or --claude-config[/red]"
        )
        sys.exit(1)

    # Load config file (explicit --config, else ./mcpwn.yaml when present)
    config: ScanConfig | None = None
    if config_file:
        config = ScanConfig.from_file(Path(config_file))
    elif DEFAULT_CONFIG_PATH.exists():
        config = ScanConfig.from_file(DEFAULT_CONFIG_PATH)

    # Merge precedence: CLI flag > config file > built-in default.
    # ParameterSource distinguishes "explicitly passed" from "click default",
    # so `--severity low` wins even when the config raises the threshold.
    if config is None:
        effective_severity = severity
        effective_timeout = timeout
        effective_aggressive = aggressive
    else:
        source = click.get_current_context().get_parameter_source
        if source("severity") is not click.core.ParameterSource.DEFAULT:
            effective_severity = severity
        else:
            effective_severity = config.severity_threshold.value
        if source("timeout") is not click.core.ParameterSource.DEFAULT:
            effective_timeout = timeout
        else:
            effective_timeout = config.timeout
        effective_aggressive = aggressive or config.aggressive

    if checks:
        check_ids = checks.split(",")
        unknown = [cid for cid in check_ids if cid not in CHECK_MAP]
        if unknown:
            console.print(f"[red]Unknown check ID: {unknown[0]}[/red]")
            sys.exit(1)
    else:
        check_ids = None

    min_severity = Severity(effective_severity)

    scanner = Scanner(
        check_ids=check_ids,
        min_severity=min_severity,
        timeout=effective_timeout,
        aggressive=effective_aggressive,
        disabled=config.disabled_ids() if config else None,
        options=config.check_options() if config else None,
    )
    if effective_aggressive:
        console.print("[yellow]Aggressive mode enabled: probing target with active payloads[/yellow]")

    if claude_config:
        results = asyncio.run(_scan_claude_config(scanner, console))
    elif stdio_cmd:
        results = [asyncio.run(scanner.scan_stdio(stdio_cmd))]
    elif sse_url:
        results = [asyncio.run(scanner.scan_sse(sse_url))]
    elif http_url:
        results = [asyncio.run(scanner.scan_http(http_url))]
    else:
        raise AssertionError("unreachable: target validated")

    # Output
    if output_format == "json":
        if output_file and len(results) > 1:
            Path(output_file).write_text(json.dumps([_result_to_dict(r) for r in results], indent=2))
            console.print(f"[green]Report saved to {output_file}[/green]")
        else:
            for result in results:
                json_output = to_json(result)
                if output_file:
                    Path(output_file).write_text(json_output)
                    console.print(f"[green]Report saved to {output_file}[/green]")
                else:
                    click.echo(json_output)
    elif output_format == "sarif":
        sarif_output = json.dumps(_sarif_log(results), indent=2)
        if output_file:
            Path(output_file).write_text(sarif_output)
            console.print(f"[green]Report saved to {output_file}[/green]")
        else:
            click.echo(sarif_output)
    else:
        for result in results:
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
    """Check JSON report(s) and exit with non-zero if findings exceed threshold.

    Accepts a single scan report or the JSON array produced by
    ``--claude-config --format json --output``.
    """
    data = json.loads(Path(input_file).read_text())
    reports = data if isinstance(data, list) else [data]
    threshold = Severity(fail_on)

    over_threshold = [
        f
        for report in reports
        for f in report.get("findings", [])
        if Severity(f["severity"]) >= threshold
    ]

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
