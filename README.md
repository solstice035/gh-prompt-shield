# 🛡️ gh-prompt-shield

**Scan GitHub issues & PRs for prompt injection patterns targeting AI coding tools.**

After a [malicious GitHub issue title compromised 4,000+ developer machines](https://www.theregister.com/2025/03/05/github_issue_title_injection/) via Cline's auto-approval mode, it's clear we need a defense layer. `gh-prompt-shield` catches prompt injection attempts in repository content **before** AI coding assistants (Cline, Copilot, Cursor) process them.

## 🎯 What It Does

- Scans GitHub issue/PR **titles and bodies** for known injection patterns
- Detects **18+ attack techniques**: instruction overrides, hidden commands, unicode obfuscation, base64 payloads, tool-specific exploits
- **Severity-rated findings** (critical/high/medium/low) with explanations
- **Tool-specific profiles** — filter for Cline, Copilot, or Cursor patterns
- **JSON output** for CI/CD integration
- **Local file scanning** for pre-commit checks
- **GitHub Action template** included

## 📦 Installation

```bash
pip install gh-prompt-shield
```

Or install from source:

```bash
git clone https://github.com/jeevesbot-io/foundry-20260306-gh-prompt-shield
cd foundry-20260306-gh-prompt-shield
pip install -e ".[dev]"
```

## 🚀 Quick Start

### Scan a GitHub repository

```bash
# Scan all open issues and PRs
gh-prompt-shield scan octocat/hello-world

# Scan with Cline-specific patterns only
gh-prompt-shield scan myorg/myrepo --profile cline

# JSON output for CI integration
gh-prompt-shield scan myorg/myrepo --json

# Verbose output with full finding details
gh-prompt-shield scan myorg/myrepo -v

# Include comment scanning (slower, more API calls)
gh-prompt-shield scan myorg/myrepo --comments

# Scan closed issues too
gh-prompt-shield scan myorg/myrepo --state all
```

### Scan a local file

```bash
gh-prompt-shield scan-file issue-template.md
gh-prompt-shield scan-file suspicious-pr.txt --profile cline --json
```

### List detection patterns

```bash
gh-prompt-shield list-patterns
gh-prompt-shield list-patterns --profile cursor
gh-prompt-shield list-patterns --json
```

## 🔍 Detection Patterns

gh-prompt-shield detects **18+ injection patterns** across 4 severity levels:

### 🔴 Critical

| ID | Pattern | Description |
|----|---------|-------------|
| INJ-001 | System prompt override | "Ignore previous instructions" and variants |
| INJ-002 | Role reassignment | "You are now...", "Act as..." directives |
| INJ-003 | Hidden instruction block | HTML/markdown comments hiding AI instructions |

### 🟠 High

| ID | Pattern | Description |
|----|---------|-------------|
| INJ-004 | Shell command injection | Direct shell/terminal execution instructions |
| INJ-005 | Curl/wget payload | Remote payload download and execution |
| INJ-006 | File system manipulation | Access to .env, SSH keys, credentials |
| INJ-007 | Data exfiltration | Sending secrets to external endpoints |
| INJ-008 | Environment variable access | Extracting API keys and tokens |
| INJ-014 | Cline tool invocation | Direct `<execute_command>` XML tags |

### 🟡 Medium

| ID | Pattern | Description |
|----|---------|-------------|
| INJ-009 | Base64 encoded payload | Obfuscated instructions in base64 |
| INJ-010 | Unicode obfuscation | Zero-width characters hiding content |
| INJ-011 | Hex/octal encoded commands | Encoded command sequences |
| INJ-012 | Markdown smuggling | Hidden instructions in images/details tags |
| INJ-013 | Code fence injection | Instructions disguised as code examples |
| INJ-015 | Copilot directive injection | @workspace/@terminal directive abuse |
| INJ-016 | Cursor composer directive | .cursorrules/@composer manipulation |
| INJ-018 | Suspicious URL + execution | Pastebin/gist URLs with execution language |

### 🔵 Low

| ID | Pattern | Description |
|----|---------|-------------|
| INJ-017 | Excessive special characters | Unusual density of backticks/control chars |

Plus **INJ-B64** — automatic base64 decoding that detects encoded injection payloads.

## 🎭 Tool Profiles

Filter patterns for the AI tool you're protecting:

```bash
# Only patterns relevant to Cline
gh-prompt-shield scan myrepo --profile cline

# Only Copilot-specific patterns
gh-prompt-shield scan myrepo --profile copilot

# Only Cursor-specific patterns
gh-prompt-shield scan myrepo --profile cursor
```

## 📝 Custom Rules

Define your own detection rules in YAML:

```yaml
# custom-rules.yaml
rules:
  - id: CUSTOM-001
    name: Internal tool injection
    description: Detects attempts to invoke our internal deployment tool
    severity: critical
    regex: "(?i)deploy\\s+to\\s+production"
    tags:
      - cline
      - cursor
```

```bash
gh-prompt-shield scan myrepo --rules custom-rules.yaml
```

## 🤖 GitHub Action

Copy `.github/workflows/prompt-shield.yml` from this repo into your project:

```yaml
name: Prompt Shield Scan
on:
  issues:
    types: [opened, edited]
  pull_request:
    types: [opened, edited]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install gh-prompt-shield
      - run: gh-prompt-shield scan ${{ github.repository }} --json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## 🔧 Authentication

Set a GitHub token for API access (higher rate limits, private repo access):

```bash
export GITHUB_TOKEN=ghp_your_token_here
# or
gh-prompt-shield scan myrepo --token ghp_your_token_here
```

Without a token, you're limited to 60 API requests/hour (unauthenticated rate limit).

## 📊 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no injection patterns found |
| 1 | Findings — injection patterns detected |
| 2 | Error — scan failed (auth, network, etc.) |

Use exit codes in CI pipelines:

```bash
gh-prompt-shield scan myrepo --json > results.json || echo "Findings detected!"
```

## 🏗️ Architecture

```
src/gh_prompt_shield/
├── __init__.py          # Package version
├── cli.py               # Click CLI interface
├── patterns.py          # Pattern library & detection engine
├── scanner.py           # GitHub API scanning orchestrator
├── github_client.py     # httpx-based GitHub API client
├── custom_rules.py      # YAML custom rule loader
├── output.py            # Rich terminal & JSON formatters
└── profiles/            # Tool-specific configurations
```

## 🧪 Development

```bash
# Clone and install dev dependencies
git clone https://github.com/jeevesbot-io/foundry-20260306-gh-prompt-shield
cd foundry-20260306-gh-prompt-shield
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check src/ tests/
```

## ⚠️ Limitations

- **Pattern-based detection only** — no ML/AI analysis (deliberate: keeps it fast and predictable)
- **GitHub only** — no GitLab, Bitbucket, or other platforms
- **No real-time monitoring** — scan on-demand or via CI, not webhook-driven
- **No auto-remediation** — flags issues, doesn't close/edit them
- **Rate limits apply** — unauthenticated: 60 req/hr, authenticated: 5,000 req/hr

## 🔮 Future Ideas

- Webhook server for real-time monitoring
- ML-based semantic injection detection
- IDE extensions (VS Code, JetBrains)
- GitLab / Bitbucket support
- Auto-labeling of suspicious issues
- Integration with GitHub Security Advisories

## 📜 License

MIT

---

*Built by [The Foundry](https://github.com/jeevesbot-io) 🏭 — Nightly builds from trending developer pain points.*
