"""
Pattern library for detecting prompt injection in GitHub content.

Each pattern has:
- id: unique identifier
- name: human-readable name
- description: what it detects and why it's dangerous
- severity: critical / high / medium / low
- regex: compiled regex pattern
- tags: which AI tools are particularly vulnerable
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


@dataclass
class Pattern:
    id: str
    name: str
    description: str
    severity: Severity
    regex: re.Pattern
    tags: list[str] = field(default_factory=list)


@dataclass
class Finding:
    pattern_id: str
    pattern_name: str
    severity: Severity
    description: str
    matched_text: str
    location: str  # e.g. "issue #42 title", "pr #10 body"
    context: str  # surrounding text snippet
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity.value,
            "description": self.description,
            "matched_text": self.matched_text,
            "location": self.location,
            "context": self.context,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: list[Pattern] = [
    # --- CRITICAL: Direct instruction override ---
    Pattern(
        id="INJ-001",
        name="System prompt override",
        description=(
            "Attempts to override system-level instructions with phrases like "
            "'ignore previous instructions', 'you are now', 'new role'. "
            "This is the most common prompt injection vector."
        ),
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|existing)\s+(?:instructions?|prompts?|rules?|guidelines?|context)",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-002",
        name="Role reassignment",
        description=(
            "Tries to reassign the AI's role with directives like 'you are now a ...', "
            "'act as', 'pretend you are'. Used to bypass safety constraints."
        ),
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"(?i)(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+(?:if\s+you\s+(?:are|were)|a\b)|pretend\s+(?:you\s+are|to\s+be)|assume\s+the\s+role)\s+",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-003",
        name="Hidden instruction block",
        description=(
            "Uses markdown comments, HTML comments, or invisible characters to hide "
            "instructions from human review while remaining visible to AI parsers."
        ),
        severity=Severity.CRITICAL,
        regex=re.compile(
            r"(?:<!--\s*(?:SYSTEM|INSTRUCTION|PROMPT|AI|AGENT|CLINE|COPILOT|CURSOR)[\s:].*?-->)",
            re.DOTALL | re.IGNORECASE,
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    # --- HIGH: Shell/code execution ---
    Pattern(
        id="INJ-004",
        name="Shell command injection",
        description=(
            "Instructs the AI to execute shell commands, run scripts, or use tools like "
            "curl/wget to download and execute payloads. Common in Cline attacks."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)(?:run|execute|eval|spawn|invoke)\s+(?:the\s+)?(?:following\s+)?(?:command|script|shell|bash|terminal|code)[\s:]+.*(?:[`]{3}|[$][\s(])",
            re.DOTALL,
        ),
        tags=["cline", "cursor"],
    ),
    Pattern(
        id="INJ-005",
        name="Curl/wget payload download",
        description=(
            "Instructs downloading and executing remote payloads via curl, wget, or similar. "
            "Direct code execution vector used in the Cline GitHub issue attack."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)(?:curl|wget|fetch|download)\s+(?:-[sSkLO]+\s+)*(?:https?://\S+).*(?:\|\s*(?:bash|sh|python|node|ruby|perl)|>\s*\S+\.(?:sh|py|js|rb))",
        ),
        tags=["cline"],
    ),
    Pattern(
        id="INJ-006",
        name="File system manipulation",
        description=(
            "Instructs the AI to write, modify, or delete files outside the project scope, "
            "or to access sensitive files like .env, SSH keys, or credentials."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)(?:write|create|modify|edit|append|delete|remove|read|cat|access)\s+(?:the\s+)?(?:file\s+)?(?:~\/|\/etc\/|\/home\/|\.\.\/)?\S*(?:\.env|\.ssh|id_rsa|credentials|\.aws|\.npmrc|\.pypirc|\.netrc|config\.json|secrets?\.)",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    # --- HIGH: Exfiltration ---
    Pattern(
        id="INJ-007",
        name="Data exfiltration attempt",
        description=(
            "Instructs the AI to send data to external URLs, encode secrets, or transmit "
            "environment variables / API keys to attacker-controlled endpoints."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)(?:send|post|transmit|upload|exfiltrate|forward|leak)\s+(?:the\s+)?(?:content|data|secret|key|token|password|env|credential|variable)s?\s+(?:to|via|using)\s+",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-008",
        name="Environment variable access",
        description=(
            "Directly references environment variables or API keys in a way that suggests "
            "extraction: $ENV, process.env, os.environ, etc."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)(?:print|echo|log|output|return|display|show)\s+(?:the\s+)?(?:value\s+of\s+)?(?:\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?|(?:process\.env|os\.environ|ENV)\[?['\"]?\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*)",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    # --- MEDIUM: Obfuscation techniques ---
    Pattern(
        id="INJ-009",
        name="Base64 encoded payload",
        description=(
            "Contains base64-encoded strings that may hide malicious instructions. "
            "Attackers encode injection payloads to bypass simple text filters."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?i)(?:base64|b64|decode|atob)\s*[\(:]?\s*['\"]?[A-Za-z0-9+/=]{40,}",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-010",
        name="Unicode obfuscation",
        description=(
            "Uses zero-width characters, homoglyphs, or other Unicode tricks to hide "
            "malicious content that appears invisible to humans but is parsed by AI tools."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\u180e]{2,}"
            r"|[\u200b\u200c\u200d\u2060\ufeff].*[\u200b\u200c\u200d\u2060\ufeff]",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-011",
        name="Hex/octal encoded commands",
        description=(
            "Contains hex-encoded (\\x41) or octal-encoded (\\101) sequences that "
            "may decode to malicious instructions."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\[0-7]{3}){4,}",
        ),
        tags=["cline", "cursor"],
    ),
    # --- MEDIUM: Instruction smuggling ---
    Pattern(
        id="INJ-012",
        name="Markdown instruction smuggling",
        description=(
            "Hides instructions in markdown elements that render invisibly: "
            "tiny images, zero-width links, or collapsed sections with injections."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?i)(?:\!\[(?:.*?)\]\((?:.*?)\s+['\"](?:ignore|system|instruction|execute).*?['\"].*?\))"
            r"|<details>\s*<summary>.*?</summary>.*?(?:ignore|override|execute|run|system\s+prompt).*?</details>",
            re.DOTALL,
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-013",
        name="Code fence instruction injection",
        description=(
            "Hides AI instructions inside code fences that look like example code "
            "but contain directives the AI may follow."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"```(?:text|plaintext|markdown|md|txt)?\s*\n\s*(?:SYSTEM|INSTRUCTION|AI|IMPORTANT)[\s:]+.*?```",
            re.DOTALL | re.IGNORECASE,
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    # --- MEDIUM: Tool-specific ---
    Pattern(
        id="INJ-014",
        name="Cline tool invocation",
        description=(
            "References Cline-specific tool invocations (execute_command, write_to_file, "
            "read_file, etc.) suggesting an attempt to trigger Cline actions directly."
        ),
        severity=Severity.HIGH,
        regex=re.compile(
            r"(?i)<(?:execute_command|write_to_file|read_file|replace_in_file|search_files|list_files|browser_action|use_mcp_tool|ask_followup_question)\b",
        ),
        tags=["cline"],
    ),
    Pattern(
        id="INJ-015",
        name="Copilot directive injection",
        description=(
            "Uses @workspace, #file, or other Copilot-specific directives in issue/PR "
            "content to manipulate Copilot Chat context."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?i)(?:@workspace|#file:|@terminal|@vscode)\s+(?:ignore|override|instead|forget|run|execute)",
        ),
        tags=["copilot"],
    ),
    Pattern(
        id="INJ-016",
        name="Cursor composer directive",
        description=(
            "Contains Cursor-specific composer directives or references to .cursorrules "
            "in issue content, suggesting an attempt to manipulate Cursor's behavior."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?i)(?:\.cursorrules|@composer|@cursor)\s*[\s:].*(?:ignore|override|always|never|must)\b",
        ),
        tags=["cursor"],
    ),
    # --- LOW: Suspicious patterns ---
    Pattern(
        id="INJ-017",
        name="Excessive special characters",
        description=(
            "Issue title or body contains an unusual density of special characters, "
            "backticks, or control sequences that may indicate obfuscation."
        ),
        severity=Severity.LOW,
        regex=re.compile(
            r"(?:[`]{10,}|[\\]{10,}|[\x00-\x08\x0e-\x1f]{3,})",
        ),
        tags=["cline", "copilot", "cursor"],
    ),
    Pattern(
        id="INJ-018",
        name="Suspicious URL in instructions",
        description=(
            "Contains URLs to raw pastebin, gist, or file-hosting services combined "
            "with execution-like language, suggesting payload delivery."
        ),
        severity=Severity.MEDIUM,
        regex=re.compile(
            r"(?i)(?:pastebin\.com|hastebin\.com|raw\.githubusercontent\.com|gist\.github\.com|transfer\.sh|file\.io|0x0\.st)\S*.*(?:run|execute|source|eval|import|load|include)",
        ),
        tags=["cline", "cursor"],
    ),
]


def get_patterns_for_profile(profile: Optional[str] = None) -> list[Pattern]:
    """Return patterns filtered by tool profile. None returns all patterns."""
    if profile is None:
        return PATTERNS
    profile_lower = profile.lower()
    return [p for p in PATTERNS if profile_lower in p.tags or not p.tags]


class PatternEngine:
    """Core detection engine that scans text against pattern library."""

    def __init__(self, profile: Optional[str] = None, custom_patterns: Optional[list[Pattern]] = None):
        self.patterns = get_patterns_for_profile(profile)
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def scan_text(self, text: str, location: str = "unknown") -> list[Finding]:
        """Scan a text string for injection patterns. Returns list of findings."""
        findings: list[Finding] = []
        for pattern in self.patterns:
            for match in pattern.regex.finditer(text):
                matched = match.group(0)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ").strip()
                if len(context) > 200:
                    context = context[:200] + "…"

                findings.append(
                    Finding(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        matched_text=matched[:200] if len(matched) > 200 else matched,
                        location=location,
                        context=context,
                        tags=pattern.tags,
                    )
                )
        return findings

    def check_base64_payloads(self, text: str, location: str = "unknown") -> list[Finding]:
        """Decode base64 strings and scan the decoded content for injections."""
        findings: list[Finding] = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for match in b64_pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in [
                    "ignore", "override", "execute", "run command",
                    "system prompt", "you are now", "curl", "wget",
                ]):
                    findings.append(
                        Finding(
                            pattern_id="INJ-B64",
                            pattern_name="Decoded base64 injection",
                            severity=Severity.CRITICAL,
                            description=(
                                "A base64-encoded string was decoded and found to contain "
                                "prompt injection keywords. This is a deliberate obfuscation attempt."
                            ),
                            matched_text=decoded[:200],
                            location=location,
                            context=f"Encoded: {match.group(0)[:60]}... → Decoded: {decoded[:100]}",
                            tags=["cline", "copilot", "cursor"],
                        )
                    )
            except Exception:
                pass
        return findings

    def scan(self, text: str, location: str = "unknown") -> list[Finding]:
        """Full scan: regex patterns + base64 decode check."""
        findings = self.scan_text(text, location)
        findings.extend(self.check_base64_payloads(text, location))
        return findings
