"""
Custom rule loading from YAML files.

Users can define additional patterns in YAML format:

```yaml
rules:
  - id: CUSTOM-001
    name: My custom pattern
    description: Detects something specific
    severity: high
    regex: "(?i)my\\s+pattern"
    tags:
      - cline
```
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .patterns import Pattern, Severity


def load_custom_rules(path: str | Path) -> list[Pattern]:
    """Load custom detection rules from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Custom rules file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "rules" not in data:
        return []

    patterns = []
    for rule in data["rules"]:
        try:
            severity = Severity(rule.get("severity", "medium").lower())
            pattern = Pattern(
                id=rule["id"],
                name=rule["name"],
                description=rule.get("description", ""),
                severity=severity,
                regex=re.compile(rule["regex"]),
                tags=rule.get("tags", []),
            )
            patterns.append(pattern)
        except (KeyError, re.error) as e:
            raise ValueError(f"Invalid custom rule '{rule.get('id', '?')}': {e}") from e

    return patterns
