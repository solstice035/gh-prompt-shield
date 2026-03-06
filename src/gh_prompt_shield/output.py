"""
Output formatters — JSON and rich terminal output.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .patterns import Severity
from .scanner import ScanReport


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}


def output_json(report: ScanReport, file: TextIO = sys.stdout, pretty: bool = True):
    """Write report as JSON."""
    indent = 2 if pretty else None
    json.dump(report.to_dict(), file, indent=indent, ensure_ascii=False)
    file.write("\n")


def output_rich(report: ScanReport, console: Console | None = None, verbose: bool = False):
    """Print a rich formatted report to the terminal."""
    if console is None:
        console = Console(stderr=True)

    repo_name = f"{report.owner}/{report.repo}"

    # Header
    console.print()
    if report.finding_count == 0 and not report.errors:
        console.print(
            Panel(
                f"[bold green]✅ No prompt injection patterns detected[/]\n"
                f"Repository: {repo_name}\n"
                f"Items scanned: {report.items_scanned} "
                f"({report.issues_scanned} issues, {report.prs_scanned} PRs)\n"
                f"Duration: {report.scan_duration_seconds:.1f}s",
                title="[bold]gh-prompt-shield[/]",
                border_style="green",
            )
        )
        return

    if report.errors and not report.findings:
        console.print(
            Panel(
                f"[bold red]⚠️  Scan encountered errors[/]\n\n"
                + "\n".join(f"  • {e}" for e in report.errors),
                title="[bold]gh-prompt-shield[/]",
                border_style="red",
            )
        )
        return

    # Summary panel
    severity_text = ""
    if report.critical_count:
        severity_text += f"[bold red]{report.critical_count} CRITICAL[/]  "
    if report.high_count:
        severity_text += f"[red]{report.high_count} HIGH[/]  "
    if report.medium_count:
        severity_text += f"[yellow]{report.medium_count} MEDIUM[/]  "
    if report.low_count:
        severity_text += f"[blue]{report.low_count} LOW[/]  "

    console.print(
        Panel(
            f"[bold red]⚠️  Prompt injection patterns detected![/]\n\n"
            f"Repository: {repo_name}\n"
            f"Items scanned: {report.items_scanned} "
            f"({report.issues_scanned} issues, {report.prs_scanned} PRs)\n"
            f"Findings: {report.finding_count}\n"
            f"Severity: {severity_text.strip()}\n"
            f"Duration: {report.scan_duration_seconds:.1f}s",
            title="[bold]gh-prompt-shield[/]",
            border_style="red",
        )
    )

    # Findings table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", width=3, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Pattern", width=28)
    table.add_column("Location", width=22)
    table.add_column("Match", ratio=1)

    sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)

    for i, finding in enumerate(sorted_findings, 1):
        sev = finding.severity
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]
        match_text = finding.matched_text
        if len(match_text) > 60:
            match_text = match_text[:57] + "..."

        table.add_row(
            str(i),
            Text(f"{icon} {sev.value.upper()}", style=color),
            finding.pattern_name,
            finding.location,
            match_text,
        )

    console.print(table)

    # Verbose: show details for each finding
    if verbose:
        console.print()
        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.severity
            color = SEVERITY_COLORS[sev]
            console.print(
                Panel(
                    f"[bold]Pattern:[/] {finding.pattern_id} — {finding.pattern_name}\n"
                    f"[bold]Severity:[/] [{color}]{sev.value.upper()}[/]\n"
                    f"[bold]Location:[/] {finding.location}\n"
                    f"[bold]Why dangerous:[/] {finding.description}\n"
                    f"[bold]Matched:[/] [dim]{finding.matched_text}[/]\n"
                    f"[bold]Context:[/] {finding.context}\n"
                    f"[bold]Affected tools:[/] {', '.join(finding.tags) if finding.tags else 'all'}",
                    title=f"Finding #{i}",
                    border_style=color,
                )
            )
