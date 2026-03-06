"""
Scanner — orchestrates GitHub API fetching and pattern detection.

Ties together the GitHubClient and PatternEngine to produce a ScanReport.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .github_client import GitHubClient, GitHubItem
from .patterns import Finding, PatternEngine, Severity


@dataclass
class ScanReport:
    """Complete scan report for a repository."""
    owner: str
    repo: str
    scan_duration_seconds: float = 0.0
    items_scanned: int = 0
    issues_scanned: int = 0
    prs_scanned: int = 0
    comments_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

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

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    @property
    def exit_code(self) -> int:
        """0 = clean, 1 = findings, 2 = errors."""
        if self.errors and not self.findings:
            return 2
        if self.findings:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "repository": f"{self.owner}/{self.repo}",
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "summary": {
                "items_scanned": self.items_scanned,
                "issues_scanned": self.issues_scanned,
                "prs_scanned": self.prs_scanned,
                "comments_scanned": self.comments_scanned,
                "total_findings": self.finding_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "max_severity": self.max_severity.value if self.max_severity else None,
            },
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: f.severity.rank, reverse=True
            )],
            "errors": self.errors,
            "exit_code": self.exit_code,
        }


class RepoScanner:
    """Scans a GitHub repository for prompt injection patterns."""

    def __init__(
        self,
        token: Optional[str] = None,
        profile: Optional[str] = None,
        scan_comments: bool = False,
        max_pages: int = 10,
    ):
        self.client = GitHubClient(token=token, max_pages=max_pages)
        self.engine = PatternEngine(profile=profile)
        self.scan_comments = scan_comments

    def _scan_item(self, item: GitHubItem, owner: str, repo: str) -> list[Finding]:
        """Scan a single issue or PR."""
        findings: list[Finding] = []
        type_label = "issue" if item.item_type == "issue" else "PR"
        loc_prefix = f"{type_label} #{item.number}"

        # Scan title
        findings.extend(self.engine.scan(item.title, f"{loc_prefix} title"))

        # Scan body
        if item.body:
            findings.extend(self.engine.scan(item.body, f"{loc_prefix} body"))

        # Scan comments (optional, costs more API calls)
        if self.scan_comments:
            try:
                comments = self.client.get_comments(owner, repo, item.number)
                for i, comment in enumerate(comments):
                    body = comment.get("body", "")
                    user = comment.get("user", "unknown")
                    if body:
                        findings.extend(
                            self.engine.scan(body, f"{loc_prefix} comment #{i+1} by {user}")
                        )
            except Exception as e:
                pass  # Non-fatal: skip comments on error

        return findings

    def scan(
        self,
        owner: str,
        repo: str,
        state: str = "open",
        scan_prs: bool = True,
    ) -> ScanReport:
        """Scan a repository's issues and PRs for prompt injection patterns."""
        start = time.time()
        report = ScanReport(owner=owner, repo=repo)

        # Verify repo exists
        try:
            self.client.verify_repo(owner, repo)
        except Exception as e:
            report.errors.append(f"Cannot access repository: {e}")
            report.scan_duration_seconds = time.time() - start
            return report

        # Fetch issues (includes PRs from issues endpoint)
        try:
            items = self.client.get_issues(owner, repo, state=state, include_prs=True)
        except Exception as e:
            report.errors.append(f"Failed to fetch issues: {e}")
            report.scan_duration_seconds = time.time() - start
            return report

        # Separate and count
        issues = [i for i in items if i.item_type == "issue"]
        prs = [i for i in items if i.item_type == "pull_request"]

        # If scan_prs is False, filter them out
        if not scan_prs:
            items = issues

        report.issues_scanned = len(issues)
        report.prs_scanned = len(prs) if scan_prs else 0
        report.items_scanned = len(items)

        # Scan each item
        for item in items:
            findings = self._scan_item(item, owner, repo)
            report.findings.extend(findings)

        report.scan_duration_seconds = time.time() - start
        return report

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class TextScanner:
    """Scans arbitrary text (local files, stdin) for prompt injection patterns."""

    def __init__(self, profile: Optional[str] = None):
        self.engine = PatternEngine(profile=profile)

    def scan_text(self, text: str, source: str = "stdin") -> list[Finding]:
        """Scan a text string."""
        return self.engine.scan(text, source)

    def scan_file(self, path: str) -> list[Finding]:
        """Scan a local file."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self.engine.scan(content, f"file:{path}")
