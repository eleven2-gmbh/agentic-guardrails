# Security policy

agentic-guardrails is a set of guard rails, not a security boundary (see
[docs/design-notes.md](docs/design-notes.md), "Known limits"). A command that the hook lets
through without asking is a bug worth reporting, but the macOS sandbox and the managed
settings are what actually hold.

## Reporting

Please report weaknesses by email to **info@eleven2.de**, not as a public issue. Useful are:
the Claude Code version, the tool call (or shell command) that got through, what you expected,
and the hook's decision from `~/Library/Logs/claude-guard/decisions.jsonl` if you have it.

We confirm receipt within five working days and tell you what we plan to do.

## Supported versions

Only the latest release receives fixes.

Weaknesses in Claude Code itself, its sandbox or its auto mode belong to Anthropic:
https://www.anthropic.com/responsible-disclosure-policy
