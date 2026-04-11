"""
Core scanner: reads ~/.claude.json and reports hardcoded secrets.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detectors import Pattern, scan_value


CLAUDE_JSON_DEFAULT = Path.home() / ".claude.json"


@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | INFO
    server: str            # MCP server name (or "file-permissions")
    env_key: str           # env variable name
    raw_value: str         # the actual secret (NOT printed — passed to fixer)
    pattern: Pattern | None
    source: str            # file path where found


@dataclass
class ScanResult:
    config_path: Path
    server_count: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "INFO": []}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)


def _check_permissions(path: Path, result: ScanResult) -> None:
    """Warn if ~/.claude.json is world-readable."""
    try:
        mode = os.stat(path).st_mode
        if mode & stat.S_IRGRP or mode & stat.S_IROTH:
            perm_str = oct(mode)[-3:]
            result.findings.append(Finding(
                severity="MEDIUM",
                server="file-permissions",
                env_key=str(path),
                raw_value="",
                pattern=None,
                source=str(path),
            ))
    except OSError:
        pass


def _scan_env_block(
    server_name: str,
    env_block: dict[str, Any],
    source: str,
    result: ScanResult,
) -> None:
    """Scan a single MCP server env block for hardcoded secrets."""
    for key, value in env_block.items():
        if not isinstance(value, str) or not value.strip():
            continue
        pattern = scan_value(value)
        if pattern:
            result.findings.append(Finding(
                severity=pattern.severity,
                server=server_name,
                env_key=key,
                raw_value=value,
                pattern=pattern,
                source=source,
            ))


def scan(config_path: Path | None = None) -> ScanResult:
    """
    Scan a Claude Code config file for hardcoded secrets.

    Checks:
    - MCP server `env` blocks for known secret patterns
    - File permissions (should be 600)
    """
    path = config_path or CLAUDE_JSON_DEFAULT
    result = ScanResult(config_path=path)

    if not path.exists():
        return result

    _check_permissions(path, result)

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return result

    # Claude Code stores MCP servers under different keys depending on scope
    # Global: {"mcpServers": {...}}
    # Project: {"projects": {"path": {"mcpServers": {...}}}}
    source = str(path)

    def _walk_servers(obj: Any, depth: int = 0) -> None:
        if depth > 4 or not isinstance(obj, dict):
            return
        if "mcpServers" in obj:
            servers = obj["mcpServers"]
            if isinstance(servers, dict):
                result.server_count += len(servers)
                for name, cfg in servers.items():
                    if isinstance(cfg, dict) and "env" in cfg:
                        env = cfg["env"]
                        if isinstance(env, dict):
                            _scan_env_block(name, env, source, result)
        for v in obj.values():
            if isinstance(v, dict):
                _walk_servers(v, depth + 1)

    _walk_servers(data)
    return result
