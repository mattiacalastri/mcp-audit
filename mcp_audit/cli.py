"""
mcp-audit CLI entry point.

Usage:
  mcp-audit                  # scan and report
  mcp-audit --fix            # migrate secrets to ~/.config/credentials/
  mcp-audit --fix --dry-run  # preview fix without touching files
  mcp-audit --watch          # hook mode: silent if clean, one line if CRITICAL
  mcp-audit --config PATH    # scan a specific claude.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .fixer import fix
from .reporter import print_full_report, print_watch
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Security scanner for Claude Code MCP configurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  mcp-audit                    scan ~/.claude.json
  mcp-audit --fix              migrate secrets to ~/.config/credentials/
  mcp-audit --fix --dry-run    preview without writing
  mcp-audit --watch            hook mode (silent if clean)
  mcp-audit --config ~/other.json
        """,
    )
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    parser.add_argument("--config", metavar="PATH", type=Path,
                        help="Path to claude.json (default: ~/.claude.json)")
    parser.add_argument("--fix", action="store_true",
                        help="Migrate hardcoded secrets to ~/.config/credentials/")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview --fix without writing any files")
    parser.add_argument("--watch", action="store_true",
                        help="Hook mode: exit 0 if clean, print warning + exit 1 if CRITICAL")
    parser.add_argument("--json", action="store_true",
                        help="Output findings as JSON (for scripting)")

    args = parser.parse_args(argv)

    result = scan(config_path=args.config)

    # ── watch / hook mode ─────────────────────────────────────────────────────
    if args.watch:
        print_watch(result)
        return 1 if result.has_critical else 0

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json:
        import json
        from .detectors import redact
        output = {
            "version": __version__,
            "config": str(result.config_path),
            "server_count": result.server_count,
            "findings": [
                {
                    "severity": f.severity,
                    "server": f.server,
                    "key": f.env_key,
                    "provider": f.pattern.provider if f.pattern else None,
                    "pattern_name": f.pattern.name if f.pattern else None,
                    "redacted_value": redact(f.raw_value) if f.raw_value else None,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(output, indent=2))
        return 1 if result.has_critical else 0

    # ── standard report ───────────────────────────────────────────────────────
    print_full_report(result)

    # ── fix mode ──────────────────────────────────────────────────────────────
    if args.fix or args.dry_run:
        if not result.findings:
            return 0
        actions = fix(result, dry_run=args.dry_run)
        print()
        for action in actions:
            print(f"  {action}")
        print()

    return 1 if result.has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
