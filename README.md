# mcp-audit

> **"I found 8 hardcoded tokens in my Claude Code config after 873 sessions."**

Security scanner for Claude Code MCP configurations.  
Finds hardcoded API keys in `~/.claude.json` and migrates them safely.

```
🔴 CRITICAL  github          GITHUB_TOKEN          ghp_ChJx······4GTfUS  GitHub Personal Access Token
🔴 CRITICAL  supabase-bot    SUPABASE_ACCESS_TOKEN  sbp_4a58······1c89    Supabase Access Token
🔵 MEDIUM    file-perms      ~/.claude.json is 644 — should be 600

  2 CRITICAL  ·  0 HIGH  ·  1 MEDIUM  ·  0 INFO

  Run `mcp-audit --fix` to migrate tokens to ~/.config/credentials/
```

## Why this exists

The official Claude Code MCP setup docs show:
```json
{ "env": { "API_KEY": "sk-your-real-token-here" } }
```

No warning. No alternative. So 75%+ of advanced users have real tokens sitting in a plain JSON file, sometimes with `644` permissions.

`~/.claude.json` is not code — people don't treat it like a secret. But it is.

## Install

```bash
pip install mcp-audit
```

Or run directly:
```bash
pipx run mcp-audit
```

## Usage

```bash
# Scan ~/.claude.json and report
mcp-audit

# Preview what --fix would do (no files written)
mcp-audit --fix --dry-run

# Migrate secrets to ~/.config/credentials/ and clean claude.json
mcp-audit --fix

# Hook mode: silent if clean, one warning line if CRITICAL
mcp-audit --watch

# JSON output for scripting
mcp-audit --json

# Scan a specific config
mcp-audit --config ~/other.json
```

## SessionStart Hook

Add to `~/.claude/settings.json` to get a silent security check every session:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "mcp-audit --watch"
          }
        ]
      }
    ]
  }
}
```

Silent if everything is clean. One line warning if it finds a CRITICAL token.

## What it detects

| Provider     | Pattern type              | Severity |
|-------------|---------------------------|----------|
| GitHub      | PAT, Fine-Grained, OAuth  | CRITICAL |
| Anthropic   | API Key                   | CRITICAL |
| OpenAI      | API Key                   | CRITICAL |
| Telegram    | Bot Token                 | CRITICAL |
| Supabase    | Access Token, JWT         | CRITICAL / HIGH |
| Stripe      | Secret Key (live/test)    | CRITICAL / HIGH |
| AWS         | Access Key ID             | CRITICAL |
| Google      | API Key                   | CRITICAL |
| Slack       | Bot / User Token          | CRITICAL |
| ElevenLabs  | API Key                   | CRITICAL |
| HuggingFace | API Token                 | CRITICAL |
| Replicate   | API Token                 | CRITICAL |
| fal.ai      | API Key                   | CRITICAL |
| n8n         | API Key                   | CRITICAL |
| File perms  | ~/.claude.json not 600    | MEDIUM   |

## How `--fix` works

1. Extracts each hardcoded secret from the MCP server `env` block
2. Writes it to `~/.config/credentials/mcp_{server}.env` (chmod 600)
3. Removes the key from `~/.claude.json` (backs up first)
4. Prints the `source` commands to add to your shell profile

Your MCP servers will then inherit the env vars from your shell — no secrets in JSON.

## License

MIT — Mattia Calastri / Astra Digital
