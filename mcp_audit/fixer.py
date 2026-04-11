"""
--fix: migrates hardcoded secrets from ~/.claude.json
to ~/.config/credentials/{server}.env and removes them from the JSON.
"""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .scanner import Finding, ScanResult


CREDS_DIR = Path.home() / ".config" / "credentials"


def _backup(path: Path) -> Path:
    """Create a timestamped backup of a file."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(f".bak.{ts}")
    shutil.copy2(path, backup)
    return backup


def _remove_from_json(data: Any, findings: list[Finding]) -> Any:
    """
    Walk the JSON structure and remove env keys that were flagged as secrets.
    Returns the modified data (in-place mutation + return for clarity).
    """
    # Group findings by server name for fast lookup
    to_remove: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if f.env_key and f.server != "file-permissions":
            to_remove[f.server].add(f.env_key)

    def _walk(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        if "mcpServers" in obj and isinstance(obj["mcpServers"], dict):
            for server_name, cfg in obj["mcpServers"].items():
                if server_name in to_remove and isinstance(cfg, dict):
                    env = cfg.get("env", {})
                    if isinstance(env, dict):
                        for key in to_remove[server_name]:
                            env.pop(key, None)
                        if not env:
                            cfg.pop("env", None)
        for v in obj.values():
            if isinstance(v, dict):
                _walk(v)

    _walk(data)
    return data


def fix(result: ScanResult, dry_run: bool = False) -> list[str]:
    """
    Migrate secrets to ~/.config/credentials/ and clean claude.json.

    Returns list of actions taken (or would-be-taken in dry_run mode).
    """
    actions: list[str] = []
    fixable = [f for f in result.findings if f.server != "file-permissions" and f.raw_value]

    if not fixable:
        return ["Nothing to fix."]

    # Group by server
    by_server: dict[str, list[Finding]] = defaultdict(list)
    for f in fixable:
        by_server[f.server].append(f)

    # 1. Write credentials files
    if not dry_run:
        CREDS_DIR.mkdir(parents=True, exist_ok=True)

    for server, server_findings in by_server.items():
        safe_name = server.replace("/", "_").replace(":", "_").replace(" ", "_")
        env_file = CREDS_DIR / f"mcp_{safe_name}.env"

        lines = [
            f"# mcp-audit: migrated from ~/.claude.json  [{datetime.now().strftime('%Y-%m-%d')}]",
            f"# Server: {server}",
            f"# Source these in your shell profile: source {env_file}",
            "",
        ]
        for f in server_findings:
            lines.append(f"{f.env_key}={f.raw_value}")

        content = "\n".join(lines) + "\n"

        if dry_run:
            actions.append(f"[dry-run] would write {env_file}")
            for f in server_findings:
                actions.append(f"  {f.env_key}=<redacted>")
        else:
            env_file.write_text(content)
            env_file.chmod(0o600)
            actions.append(f"✅ wrote {env_file}  (chmod 600)")

    # 2. Remove from claude.json
    config_path = result.config_path
    if dry_run:
        actions.append(f"[dry-run] would remove {len(fixable)} key(s) from {config_path}")
    else:
        backup = _backup(config_path)
        actions.append(f"✅ backup  {backup}")

        data = json.loads(config_path.read_text())
        data = _remove_from_json(data, fixable)
        config_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        config_path.chmod(0o600)
        actions.append(f"✅ cleaned {config_path}  ({len(fixable)} key(s) removed)")

    # 3. Shell profile instructions
    shell_profile = Path.home() / ".zshrc"
    sourcing_lines = [f'source "{CREDS_DIR}/mcp_{s.replace("/","_").replace(":","_").replace(" ","_")}.env"'
                      for s in by_server]
    actions.append("")
    actions.append("─── Next step ───────────────────────────────────────")
    actions.append(f"Add to {shell_profile}:")
    for line in sourcing_lines:
        actions.append(f"  {line}")
    actions.append("Then restart your shell and Claude Code.")

    return actions
