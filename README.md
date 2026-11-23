# agentic-guardrails

Hardening for [Claude Code](https://code.claude.com) on a developer's Mac: root-owned
managed settings, the macOS sandbox with a network allowlist, a PreToolUse hook that reads
every shell command before it runs, and package protection against supply-chain attacks.
One policy file per layer (product baseline, organisation, machine) is the single source
for all of it.

Maintained by [eleven2 gmbh](https://www.eleven2.de).

## What it does

| Layer | What it enforces | Where |
|---|---|---|
| Managed settings | bypass mode off; reads and writes outside the working directories blocked; credential files denied; `ask` for `git push`, cloud CLIs, gists; only managed hooks, only managed permission rules and sandbox read paths | `managed-settings.json`, generated, root-owned |
| Sandbox | every Bash command runs in Seatbelt; network only to an allowlist (registries, code hosts, documentation, the organisation's own domains); ssh through the sandbox proxy, so the allowlist holds for ssh too | `managed-settings.json`, `bin/ssh-proxy.py` |
| Hook | reads each command: git network options that start programs, `git push` in any spelling, `gh` writes, ssh commands that change a server or let data leave it, reads of secrets and logs with personal data on servers, package installs without Socket Firewall, dependency changes in manifests, project settings that open outside folders | `hooks/guard.py` |
| Package protection | installs only through [Socket Firewall](https://socket.dev), a release-age window of 7 days for npm, pip, uv and Composer, no install scripts, wheels only | `baseline.json`, `snippets/` |
| Auto-mode text | the classifier is told the same rules the hook enforces | generated into `managed-settings.json` |

The hook is a guard rail, not a security boundary: it sees only the text of a tool call.
The boundaries are the sandbox, the network allowlist and the root-owned settings. See
[docs/design-notes.md](docs/design-notes.md).

## Where it applies

| Surface | Covered |
|---|---|
| Claude Code in the terminal, VS Code, JetBrains | yes |
| Desktop app, Code tab; Agent SDK on the same machine | yes (they read the same managed settings) |
| Subagents, background agents, forks | yes (hooks fire for their tool calls, managed restrictions apply) |
| Agents with `isolation: "worktree"`; Cowork on the local machine | probably; not tested |
| Cloud sessions, remote agents, the Claude chat app | no |

## Layout

| Path | Content |
|---|---|
| `baseline.json` | the product's rules, the same on every machine; ids, `locked` entries, `baseline_version` |
| `<config>/org.json` | your organisation: name, own domains, ssh hosts (your folder, not part of the product) |
| `<config>/local.<host>.json` | this machine: working directories, projects for `/patch-check`, agent socket |
| `<config>/policy.json` | generated from the three; the hook reads it |
| `<config>/managed-settings.json` | generated; Claude Code reads it |
| `build.py` | merges the layers, checks them, writes both files; `--diff`, `--check`, `--audit` |
| `hooks/guard.py` | the PreToolUse and SessionStart hook |
| `bin/ssh-proxy.py` | ssh `ProxyCommand` through the sandbox's HTTP proxy |
| `launchd/claude-ssh-agent.plist` | template for an ssh-agent with a fixed socket the sandbox may reach |
| `scripts/` | `guard-log.py` (decision log), `patch-scan.sh` (read-only patch check), `ssh-key-rotate.sh` |
| `skills/` | `/dep-check` (vet a package before adding it), `/patch-check` |
| `snippets/` | npm, pip, Composer, ssh and shell configuration the installer adds |
| `examples/` | an example organisation and machine layer |
| `tests/` | `test_guard.py` (hook), `test_build.py` (layer merge); tests of your own configuration live in your folder |

## Configure

Keep your configuration in a folder of your own, outside this repository (it holds your
organisation's facts, and it can live in a private repository that pins this one as a
submodule). Copy `examples/org.example.json` to `<your folder>/org.json` and
`examples/local.example.json` to `<your folder>/local.<short host name>.json`, then edit
them. A layer may only

- `add` facts: own domains, ssh hosts, working directories, documentation hosts, sandbox paths,
- `set` values without a security direction: names, descriptions, the log path, the LaunchAgent label,
- `tighten` rules: more secret or personal-data patterns, more always-ask tools, a longer release-age window,
- make `exceptions` (`off`, `shadow`, `set`) with an `id`, a `reason` and an `expires` date.

Entries the baseline lists under `locked` cannot be changed at all. `build.py` refuses
unknown keys, unknown or duplicate ids, values of the wrong type, expired exceptions and
a baseline version outside the layer's `requires_baseline`.

```
./build.py --config ~/my-guardrails --diff   # what would change
./build.py --config ~/my-guardrails          # write policy.json and managed-settings.json there
/usr/bin/python3 -I tests/test_guard.py && /usr/bin/python3 -I tests/test_build.py
```

Tests of your own configuration (for example that your domains reach every list) go into
the same folder as `test_*.py`; `install.sh` runs them before installing. Without
`--config`, `build.py` and `install.sh` use `config/` in this checkout, which git ignores.

## Install

Requirements: macOS, Claude Code 2.1.314 or later, `/usr/bin/python3` (3.9, standard
library only), Homebrew Python 3.14 for the ssh proxy.

```
./build.py --config ~/my-guardrails --audit   # in your own terminal: what in ~/.claude
                                             # and project settings stops applying
./install.sh --config ~/my-guardrails         # checks build and tests, then installs with sudo
```

After installing, restart every Claude Code session. `uninstall.sh` removes everything
again.

## Maintain

- Every decision of the hook is logged (`~/Library/Logs/claude-guard/decisions.jsonl`
  by default). `scripts/guard-log.py` shows which rule asks how often.
- A rule that asks often and is always confirmed is a warning sign: narrow it instead of
  getting used to clicking.
- After every Claude Code update, repeat a short acceptance test: one case that must ask,
  one that must stay silent, one control case.

## Licence

Copyright 2026 eleven2 gmbh. Licensed under the Apache License 2.0, see [LICENSE](LICENSE).

## Security

To report a weakness in the guard rails, see [SECURITY.md](SECURITY.md).
