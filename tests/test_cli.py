"""Tests for CLI interface."""

from click.testing import CliRunner

from gh_prompt_shield.cli import main, parse_repo


class TestParseRepo:
    def test_owner_repo(self):
        assert parse_repo("octocat/hello-world") == ("octocat", "hello-world")

    def test_github_url(self):
        assert parse_repo("https://github.com/octocat/hello-world") == ("octocat", "hello-world")

    def test_github_url_trailing_slash(self):
        assert parse_repo("https://github.com/octocat/hello-world/") == ("octocat", "hello-world")


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "gh-prompt-shield" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Scan GitHub issues" in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "REPOSITORY" in result.output

    def test_list_patterns(self):
        runner = CliRunner()
        result = runner.invoke(main, ["list-patterns", "--json"])
        assert result.exit_code == 0
        import json
        patterns = json.loads(result.output)
        assert len(patterns) >= 18
        assert all("id" in p for p in patterns)

    def test_list_patterns_profile(self):
        runner = CliRunner()
        result = runner.invoke(main, ["list-patterns", "--profile", "cline", "--json"])
        assert result.exit_code == 0
        import json
        patterns = json.loads(result.output)
        assert all("cline" in p["tags"] for p in patterns)

    def test_scan_file_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan-file", "--help"])
        assert result.exit_code == 0
