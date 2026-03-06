"""
CLI interface for gh-prompt-shield.

Usage:
    gh-prompt-shield scan owner/repo
    gh-prompt-shield scan owner/repo --profile cline --json
    gh-prompt-shield scan-file path/to/file.md
    gh-prompt-shield list-patterns
"""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .custom_rules import load_custom_rules
from .output import output_json, output_rich
from .patterns import PATTERNS, PatternEngine, get_patterns_for_profile
from .scanner import RepoScanner, TextScanner


console = Console(stderr=True)


def parse_repo(repo_str: str) -> tuple[str, str]:
    """Parse 'owner/repo' or 'https://github.com/owner/repo' into (owner, repo)."""
    repo_str = repo_str.strip().rstrip("/")

    # Handle full URLs
    if "github.com" in repo_str:
        parts = repo_str.split("github.com/")[-1].split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        raise click.BadParameter(f"Cannot parse GitHub URL: {repo_str}")

    # Handle owner/repo
    if "/" in repo_str:
        parts = repo_str.split("/")
        return parts[0], parts[1]

    raise click.BadParameter(
        f"Expected 'owner/repo' or GitHub URL, got: {repo_str}"
    )


@click.group()
@click.version_option(__version__, prog_name="gh-prompt-shield")
def main():
    """🛡️  Scan GitHub issues & PRs for prompt injection patterns.

    Detects prompt injection attempts targeting AI coding tools like
    Cline, Copilot, and Cursor in GitHub repository content.
    """
    pass


@main.command()
@click.argument("repository")
@click.option(
    "--profile", "-p",
    type=click.Choice(["cline", "copilot", "cursor"], case_sensitive=False),
    default=None,
    help="Filter patterns for a specific AI tool.",
)
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings.")
@click.option(
    "--state", "-s",
    type=click.Choice(["open", "closed", "all"]),
    default="open",
    help="Issue/PR state to scan.",
)
@click.option("--comments", is_flag=True, help="Also scan issue/PR comments (slower).")
@click.option("--no-prs", is_flag=True, help="Skip pull requests, scan issues only.")
@click.option("--token", "-t", envvar="GITHUB_TOKEN", help="GitHub personal access token.")
@click.option(
    "--rules", "-r",
    type=click.Path(exists=True),
    default=None,
    help="Path to custom rules YAML file.",
)
@click.option("--max-pages", default=10, type=int, help="Max pages to fetch (100 items/page).")
def scan(repository, profile, json_out, verbose, state, comments, no_prs, token, rules, max_pages):
    """Scan a GitHub repository for prompt injection patterns.

    REPOSITORY can be 'owner/repo' or a full GitHub URL.

    \b
    Examples:
        gh-prompt-shield scan octocat/hello-world
        gh-prompt-shield scan https://github.com/octocat/hello-world
        gh-prompt-shield scan myorg/myrepo --profile cline --json
        gh-prompt-shield scan myorg/myrepo -v --comments
    """
    try:
        owner, repo = parse_repo(repository)
    except click.BadParameter as e:
        console.print(f"[red]Error:[/] {e}")
        sys.exit(2)

    if not json_out:
        console.print(f"[bold]Scanning {owner}/{repo}...[/]")

    with RepoScanner(
        token=token,
        profile=profile,
        scan_comments=comments,
        max_pages=max_pages,
    ) as scanner:
        # Load custom rules if provided
        if rules:
            try:
                custom = load_custom_rules(rules)
                scanner.engine.patterns.extend(custom)
                if not json_out:
                    console.print(f"[dim]Loaded {len(custom)} custom rules from {rules}[/]")
            except Exception as e:
                console.print(f"[red]Error loading custom rules:[/] {e}")
                sys.exit(2)

        try:
            report = scanner.scan(
                owner=owner,
                repo=repo,
                state=state,
                scan_prs=not no_prs,
            )
        except Exception as e:
            if json_out:
                json.dump({"error": str(e), "exit_code": 2}, sys.stdout)
                sys.stdout.write("\n")
            else:
                console.print(f"[red]Error:[/] {e}")
            sys.exit(2)

    if json_out:
        output_json(report, sys.stdout)
    else:
        output_rich(report, console, verbose=verbose)

    sys.exit(report.exit_code)


@main.command("scan-file")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--profile", "-p",
    type=click.Choice(["cline", "copilot", "cursor"], case_sensitive=False),
    default=None,
    help="Filter patterns for a specific AI tool.",
)
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings.")
def scan_file(path, profile, json_out, verbose):
    """Scan a local file for prompt injection patterns.

    \b
    Examples:
        gh-prompt-shield scan-file issue-body.md
        gh-prompt-shield scan-file suspicious.txt --profile cline --json
    """
    scanner = TextScanner(profile=profile)
    findings = scanner.scan_file(path)

    if json_out:
        result = {
            "source": path,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        if not findings:
            console.print(f"[green]✅ No prompt injection patterns found in {path}[/]")
        else:
            console.print(f"[red]⚠️  {len(findings)} finding(s) in {path}[/]")
            for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
                sev_color = {
                    "critical": "bold red", "high": "red",
                    "medium": "yellow", "low": "blue"
                }[f.severity.value]
                console.print(
                    f"  [{sev_color}]{f.severity.value.upper()}[/] "
                    f"{f.pattern_name}: {f.matched_text[:60]}"
                )
                if verbose:
                    console.print(f"    [dim]{f.description}[/]")

    exit_code = 1 if findings else 0
    sys.exit(exit_code)


@main.command("list-patterns")
@click.option(
    "--profile", "-p",
    type=click.Choice(["cline", "copilot", "cursor"], case_sensitive=False),
    default=None,
    help="Filter patterns for a specific AI tool.",
)
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON.")
def list_patterns(profile, json_out):
    """List all detection patterns.

    \b
    Examples:
        gh-prompt-shield list-patterns
        gh-prompt-shield list-patterns --profile cline
        gh-prompt-shield list-patterns --json
    """
    patterns = get_patterns_for_profile(profile)

    if json_out:
        result = [
            {
                "id": p.id,
                "name": p.name,
                "severity": p.severity.value,
                "description": p.description,
                "tags": p.tags,
            }
            for p in patterns
        ]
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    table = Table(title=f"Detection Patterns{f' ({profile})' if profile else ''}")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Name", width=30)
    table.add_column("Severity", width=10)
    table.add_column("Tools", width=20)
    table.add_column("Description", ratio=1)

    for p in patterns:
        sev_color = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "blue"
        }[p.severity.value]
        table.add_row(
            p.id,
            p.name,
            f"[{sev_color}]{p.severity.value.upper()}[/]",
            ", ".join(p.tags) if p.tags else "all",
            p.description[:80] + ("…" if len(p.description) > 80 else ""),
        )

    console.print(table)
    console.print(f"\n[dim]{len(patterns)} patterns loaded[/]")


if __name__ == "__main__":
    main()
