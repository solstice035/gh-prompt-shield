"""
GitHub API client for fetching issues and pull requests.

Uses httpx for async-capable HTTP with proper rate limiting and pagination.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class GitHubItem:
    """Represents a GitHub issue or pull request."""
    number: int
    title: str
    body: str
    item_type: str  # "issue" or "pull_request"
    state: str
    user: str
    url: str
    labels: list[str] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)


class RateLimitError(Exception):
    """Raised when GitHub API rate limit is exceeded."""
    def __init__(self, reset_at: int):
        self.reset_at = reset_at
        wait = max(0, reset_at - int(time.time()))
        super().__init__(f"GitHub API rate limit exceeded. Resets in {wait}s.")


class GitHubClient:
    """Client for GitHub REST API v3."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None, per_page: int = 100, max_pages: int = 10):
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.per_page = min(per_page, 100)
        self.max_pages = max_pages
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            self._headers["Authorization"] = f"Bearer {self.token}"
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers=self._headers,
            timeout=30.0,
            follow_redirects=True,
        )
        self.rate_limit_remaining: Optional[int] = None
        self.rate_limit_reset: Optional[int] = None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _update_rate_limit(self, response: httpx.Response):
        """Track rate limit headers from response."""
        remaining = response.headers.get("x-ratelimit-remaining")
        reset = response.headers.get("x-ratelimit-reset")
        if remaining is not None:
            self.rate_limit_remaining = int(remaining)
        if reset is not None:
            self.rate_limit_reset = int(reset)

    def _get(self, path: str, params: Optional[dict] = None) -> httpx.Response:
        """Make a GET request with rate limit handling."""
        if self.rate_limit_remaining is not None and self.rate_limit_remaining < 5:
            if self.rate_limit_reset and self.rate_limit_reset > int(time.time()):
                raise RateLimitError(self.rate_limit_reset)

        response = self._client.get(path, params=params)
        self._update_rate_limit(response)

        if response.status_code == 403 and "rate limit" in response.text.lower():
            raise RateLimitError(self.rate_limit_reset or int(time.time()) + 60)

        response.raise_for_status()
        return response

    def _paginate(self, path: str, params: Optional[dict] = None) -> list[dict]:
        """Fetch all pages of a paginated endpoint."""
        params = params or {}
        params["per_page"] = self.per_page
        all_items = []

        for page in range(1, self.max_pages + 1):
            params["page"] = page
            response = self._get(path, params)
            items = response.json()
            if not items:
                break
            all_items.extend(items)
            # Check if there are more pages
            link = response.headers.get("link", "")
            if 'rel="next"' not in link:
                break

        return all_items

    def get_issues(
        self,
        owner: str,
        repo: str,
        state: str = "open",
        include_prs: bool = False,
    ) -> list[GitHubItem]:
        """Fetch issues for a repository."""
        raw_items = self._paginate(
            f"/repos/{owner}/{repo}/issues",
            params={"state": state, "sort": "created", "direction": "desc"},
        )

        items = []
        for raw in raw_items:
            is_pr = "pull_request" in raw
            if is_pr and not include_prs:
                continue

            items.append(
                GitHubItem(
                    number=raw["number"],
                    title=raw.get("title", ""),
                    body=raw.get("body") or "",
                    item_type="pull_request" if is_pr else "issue",
                    state=raw.get("state", "unknown"),
                    user=raw.get("user", {}).get("login", "unknown"),
                    url=raw.get("html_url", ""),
                    labels=[l.get("name", "") for l in raw.get("labels", [])],
                )
            )
        return items

    def get_pull_requests(
        self,
        owner: str,
        repo: str,
        state: str = "open",
    ) -> list[GitHubItem]:
        """Fetch pull requests for a repository."""
        raw_items = self._paginate(
            f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "sort": "created", "direction": "desc"},
        )

        items = []
        for raw in raw_items:
            items.append(
                GitHubItem(
                    number=raw["number"],
                    title=raw.get("title", ""),
                    body=raw.get("body") or "",
                    item_type="pull_request",
                    state=raw.get("state", "unknown"),
                    user=raw.get("user", {}).get("login", "unknown"),
                    url=raw.get("html_url", ""),
                    labels=[l.get("name", "") for l in raw.get("labels", [])],
                )
            )
        return items

    def get_comments(self, owner: str, repo: str, issue_number: int) -> list[dict]:
        """Fetch comments for an issue or PR."""
        raw = self._paginate(
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
        )
        return [
            {
                "user": c.get("user", {}).get("login", "unknown"),
                "body": c.get("body") or "",
                "url": c.get("html_url", ""),
            }
            for c in raw
        ]

    def verify_repo(self, owner: str, repo: str) -> dict:
        """Verify a repository exists and is accessible. Returns repo info."""
        response = self._get(f"/repos/{owner}/{repo}")
        return response.json()

    def get_rate_limit(self) -> dict:
        """Get current rate limit status."""
        response = self._get("/rate_limit")
        return response.json()
