"""
Output formatting for mcp-audit results.
"""

from __future__ import annotations

from .detectors import redact
from .scanner import Finding, ScanResult

# ── ANSI colors ────────────────────────────────────────────────────────────────
R   = "\033[0m"
DIM = "\033[2m"
B   = "\033[1m"
RED = "\033[1;31m"
YLW = "\033[1;33m"
CYN = "\033[1;36m"
GRN = "\033[1;32m"
MGT = "\033[1;35m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YLW,
    "MEDIUM":   CYN,
    "INFO":     DIM,
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟡",
    "MEDIUM":   "🔵",
    "INFO":     "⚪",
}


def _sev(severity: str, text: str) -> str:
    color = SEVERITY_COLOR.get(severity, "")
    return f"{color}{text}{R}"


def print_header(result: ScanResult) -> None:
    w = 54
    print(f"\n  {CYN}{'─' * w}{R}")
    print(f"  {B}mcp-audit{R}  {DIM}scanning {result.config_path}{R}")
    print(f"  {CYN}{'─' * w}{R}\n")
    if result.server_count:
        print(f"  {DIM}{result.server_count} MCP servers found{R}\n")


def print_finding(f: Finding) -> None:
    icon = SEVERITY_ICON.get(f.severity, "·")
    sev  = _sev(f.severity, f"{f.severity:<8}")

    if f.server == "file-permissions":
        print(f"  {icon}  {sev}  {DIM}file-permissions{R}  "
              f"{f.env_key} is not 600 — anyone on this machine can read it")
        return

    provider = f"{f.pattern.provider} {f.pattern.name}" if f.pattern else "Unknown"
    redacted = redact(f.raw_value) if f.raw_value else ""
    print(f"  {icon}  {sev}  {DIM}{f.server:<20}{R}  "
          f"{f.env_key:<30}  {DIM}{provider}{R}  {redacted}")


def print_summary(result: ScanResult) -> None:
    by_sev = result.by_severity
    counts = {s: len(v) for s, v in by_sev.items()}
    w = 54

    print(f"\n  {DIM}{'─' * w}{R}")

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        n = counts.get(sev, 0)
        color = SEVERITY_COLOR[sev]
        parts.append(f"{color}{n} {sev}{R}")
    print("  " + "  ·  ".join(parts))

    if result.has_critical:
        print(f"\n  {RED}Run `mcp-audit --fix` to migrate tokens to {R}"
              f"{DIM}~/.config/credentials/{R}")
    elif not result.findings:
        print(f"\n  {GRN}✓  No secrets found.  Config looks clean.{R}")

    print()


def print_watch(result: ScanResult) -> None:
    """Compact output for SessionStart hook — silent if clean, one line if not."""
    n = sum(1 for f in result.findings if f.severity == "CRITICAL")
    if n == 0:
        return
    servers = {f.server for f in result.findings if f.severity == "CRITICAL"}
    print(f"⚠️  mcp-audit: {n} CRITICAL secret(s) in ~/.claude.json "
          f"({', '.join(sorted(servers))})  →  run `mcp-audit --fix`")


def print_full_report(result: ScanResult) -> None:
    print_header(result)
    if not result.findings:
        print(f"  {GRN}✓  No secrets found.{R}")
    else:
        for f in result.findings:
            print_finding(f)
    print_summary(result)
