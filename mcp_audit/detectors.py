"""
Secret patterns for 15+ providers.
Each pattern targets values likely to appear in MCP server env blocks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    provider: str
    regex: re.Pattern[str]
    severity: str  # CRITICAL | HIGH | MEDIUM


# Ordered by specificity (more specific first to avoid false positives)
PATTERNS: tuple[Pattern, ...] = (
    # ── API keys & tokens ──────────────────────────────────────────────────────
    Pattern("Fine-Grained PAT",   "GitHub",      re.compile(r"github_pat_[A-Za-z0-9_]{50,}"),           "CRITICAL"),
    Pattern("Personal Access Token", "GitHub",   re.compile(r"ghp_[A-Za-z0-9]{36,}"),                  "CRITICAL"),
    Pattern("App Installation Token","GitHub",   re.compile(r"ghs_[A-Za-z0-9]{36,}"),                  "CRITICAL"),
    Pattern("OAuth Token",        "GitHub",      re.compile(r"gho_[A-Za-z0-9]{36,}"),                  "CRITICAL"),
    Pattern("API Key",            "Anthropic",   re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{80,}"),   "CRITICAL"),
    Pattern("API Key",            "OpenAI",      re.compile(r"sk-[A-Za-z0-9]{48,}"),                   "CRITICAL"),
    Pattern("Bot Token",          "Telegram",    re.compile(r"\d{8,11}:[A-Za-z0-9_\-]{35,}"),          "CRITICAL"),
    Pattern("Access Token",       "Supabase",    re.compile(r"sbp_[A-Za-z0-9]{30,}"),                  "CRITICAL"),
    Pattern("Service Role JWT",   "Supabase",    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{20,}"), "HIGH"),
    Pattern("Secret Key (live)",  "Stripe",      re.compile(r"sk_live_[A-Za-z0-9]{24,}"),              "CRITICAL"),
    Pattern("Secret Key (test)",  "Stripe",      re.compile(r"sk_test_[A-Za-z0-9]{24,}"),              "HIGH"),
    Pattern("Restricted Key",     "Stripe",      re.compile(r"rk_(?:live|test)_[A-Za-z0-9]{24,}"),     "CRITICAL"),
    Pattern("Access Key ID",      "AWS",         re.compile(r"AKIA[0-9A-Z]{16}"),                      "CRITICAL"),
    Pattern("API Key",            "Google",      re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                "CRITICAL"),
    Pattern("Bot Token",          "Slack",       re.compile(r"xoxb-[0-9\-A-Za-z]{50,}"),              "CRITICAL"),
    Pattern("User Token",         "Slack",       re.compile(r"xoxp-[0-9\-A-Za-z]{50,}"),              "CRITICAL"),
    Pattern("API Key",            "ElevenLabs",  re.compile(r"sk_[a-f0-9]{32,}"),                      "CRITICAL"),
    Pattern("API Token",          "HuggingFace", re.compile(r"hf_[A-Za-z0-9]{30,}"),                  "CRITICAL"),
    Pattern("API Token",          "Replicate",   re.compile(r"r8_[A-Za-z0-9]{30,}"),                  "CRITICAL"),
    Pattern("API Key",            "fal.ai",      re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-zA-Z0-9]{20,}"), "CRITICAL"),
    Pattern("Token",              "Railway",     re.compile(r"[a-f0-9]{32}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"), "HIGH"),
    Pattern("API Key",            "n8n",         re.compile(r"n8n_api_[A-Za-z0-9]{40,}"),              "CRITICAL"),
    Pattern("Access Token",       "LinkedIn",    re.compile(r"AQX[A-Za-z0-9_\-]{50,}"),               "CRITICAL"),
)


def scan_value(value: str) -> Pattern | None:
    """Return the first matching pattern for a string value, or None."""
    for pattern in PATTERNS:
        if pattern.regex.search(value):
            return pattern
    return None


def redact(value: str, keep: int = 6) -> str:
    """Redact a secret value, keeping only first and last N chars."""
    if len(value) <= keep * 2 + 3:
        return "*" * len(value)
    return f"{value[:keep]}{'·' * 6}{value[-keep:]}"
