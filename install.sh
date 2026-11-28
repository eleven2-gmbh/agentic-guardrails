#!/bin/bash
# Installs the Claude Code base protection incl. package protection.
# Run as your normal user:  ./install.sh [--config DIR]   (asks for sudo for the system part)
# DIR holds org.json, local.<host>.json and the policy.json and managed-settings.json that
# build.py --config DIR generated there; any test_*.py in DIR runs before installing, with
# AGENTIC_GUARDRAILS_DIR set to this checkout. If DIR/product-version names a tag (v1.2.3),
# this checkout must be clean and exactly at that tag, else nothing is installed.
# Without --config, config/ in this checkout and the generated files next to build.py.
set -euo pipefail
CONF=""
if [ "${1:-}" = "--config" ]; then
  [ -d "${2:-}" ] || { echo "ERROR: --config needs an existing folder" >&2; exit 1; }
  CONF=$(cd "$2" && pwd)
elif [ $# -gt 0 ]; then
  echo "usage: $0 [--config DIR]" >&2; exit 2
fi
cd "$(dirname "$0")"
GEN="${CONF:-.}"
BUILD_ARGS=()
[ -n "$CONF" ] && BUILD_ARGS=(--config "$CONF")

SYS="/Library/Application Support/ClaudeCode"
# LaunchAgent name of the ssh-agent, from install.launchagent_label in policy.json.
# Only letters, digits, dots and dashes: it ends up in a path, a plist and launchctl.
LABEL=$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["install"]["launchagent_label"])' "$GEN/policy.json")
[[ "$LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo "install.launchagent_label invalid: $LABEL" >&2; exit 1; }
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
# Release-age window for the terminal's npm, pip and Composer: the same days as the policy
# (package_protection.min_release_age_days), written into the snippets below.
DAYS=$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["package_protection"]["min_release_age_days"])' "$GEN/policy.json")
[[ "$DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "package_protection.min_release_age_days invalid: $DAYS" >&2; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)

# Socket Firewall Free: pinned release (>= 7 days old) and its SHA-256 from the GitHub release
SFW_VERSION="v1.16.0"
SFW_ARM64_SHA="29df049df2ef705a8ce726c6c41fe73a6034f6b1cd0d87f3f15a780d074b6d83"
SFW_X86_SHA="b574931bc2b3c36a9bf07ac07b9c07894f8cd314efc91bc5e4fe1c371b56adca"
SFW_BIN="/usr/local/bin/sfw"

echo "1/7 Checking files"
# The configuration may pin the product version it was built and tested with. Then only a
# clean checkout of exactly that tag installs, never work in progress (README, Configure).
if [ -n "$CONF" ] && [ -f "$CONF/product-version" ]; then
  PIN=$(tr -d '[:space:]' < "$CONF/product-version")
  [[ "$PIN" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || { echo "ERROR: $CONF/product-version must hold one tag like v1.2.3, not '$PIN'" >&2; exit 1; }
  [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ] \
    || { echo "ERROR: $CONF/product-version needs a git checkout of agentic-guardrails here" >&2; exit 1; }
  [ -z "$(git status --porcelain)" ] \
    || { echo "ERROR: this checkout has uncommitted changes (git status). Installing only from $PIN." >&2; exit 1; }
  git tag --points-at HEAD | grep -qx "$PIN" \
    || { echo "ERROR: this checkout is at $(git describe --tags --always), the configuration pins $PIN." >&2
         echo "       Run: git -C \"$PWD\" checkout $PIN" >&2; exit 1; }
  echo "    product $PIN, checkout clean"
elif [ -n "$CONF" ]; then
  echo "    NOTE: no $CONF/product-version, installing this checkout as it is"
fi
export AGENTIC_GUARDRAILS_DIR="$PWD"
/usr/bin/sed "s/@LABEL@/$LABEL/g" launchd/claude-ssh-agent.plist > "${TMPDIR:-/tmp}/ssh-agent-$STAMP.plist"
/usr/bin/plutil -lint "${TMPDIR:-/tmp}/ssh-agent-$STAMP.plist" >/dev/null
/usr/bin/python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$GEN/policy.json"
# policy.json and managed-settings.json are generated from the layers; stop if they differ
/usr/bin/python3 -I build.py --check ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}
/usr/bin/python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$GEN/managed-settings.json"
# the product's tests, then the configuration's own (test_*.py in the config folder)
for t in tests/test_*.py ${CONF:+"$CONF"/test_*.py}; do
  [ -f "$t" ] || continue
  /usr/bin/python3 -I "$t"
done

# Claude Code would merge every file in managed-settings.d into the managed settings,
# past policy.json and build.py (docs/design-notes.md, 9). Refuse to install next to one.
if [ -e "$SYS/managed-settings.d" ]; then
  echo "ERROR: $SYS/managed-settings.d exists. Check it and remove it first (docs/design-notes.md, 9)." >&2
  exit 1
fi

echo "2/7 System part (sudo): $SYS"
sudo /usr/bin/install -d -o root -g wheel -m 755 "$SYS" "$SYS/hooks" "$SYS/bin"
for f in managed-settings.json policy.json; do
  if [ -f "$SYS/$f" ]; then
    sudo cp -p "$SYS/$f" "$SYS/$f.bak-$STAMP"
  fi
done
sudo /usr/bin/install -o root -g wheel -m 644 "$GEN/managed-settings.json" "$SYS/managed-settings.json"
# policy.json must be root-owned too: the hook reads it, and a writable policy would let
# any process relax the rules (data classes, own hosts, working directories)
sudo /usr/bin/install -o root -g wheel -m 644 "$GEN/policy.json" "$SYS/policy.json"
sudo /usr/bin/install -o root -g wheel -m 755 hooks/guard.py "$SYS/hooks/guard.py"
sudo /usr/bin/install -o root -g wheel -m 755 bin/ssh-proxy.py "$SYS/bin/ssh-proxy.py"

echo "3/7 ssh-agent with a fixed socket (LaunchAgent)"
mkdir -p "$HOME/Library/LaunchAgents"
/bin/launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
mv "${TMPDIR:-/tmp}/ssh-agent-$STAMP.plist" "$PLIST"
/bin/launchctl bootstrap "gui/$(id -u)" "$PLIST"
# the agent loads the key from the login keychain, which can take longer than a moment;
# wait up to 15 s for it instead of a fixed pause
i=0
until SSH_AUTH_SOCK="$HOME/.ssh-agent/agent.sock" /usr/bin/ssh-add -l >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "    ERROR: agent has no key after 15 s (log: /tmp/$LABEL.log)"; exit 1
  fi
  sleep 0.5
done
echo "    agent running, key loaded"

echo "4/7 ssh config block at the top of ~/.ssh/config"
if grep -q '>>> Claude-Code-Sandbox' "$HOME/.ssh/config"; then
  echo "    already present, unchanged"
else
  cp -p "$HOME/.ssh/config" "$HOME/.ssh/config.bak-$STAMP"
  { cat snippets/ssh-config.txt; echo; cat "$HOME/.ssh/config.bak-$STAMP"; } > "$HOME/.ssh/config"
  chmod 600 "$HOME/.ssh/config"
  echo "    inserted (backup: ~/.ssh/config.bak-$STAMP)"
fi

echo "5/7 Socket Firewall $SFW_VERSION to $SFW_BIN (checksum verified)"
case "$(uname -m)" in
  arm64)  SFW_ASSET="sfw-free-macos-arm64";  SFW_SHA="$SFW_ARM64_SHA" ;;
  x86_64) SFW_ASSET="sfw-free-macos-x86_64"; SFW_SHA="$SFW_X86_SHA" ;;
  *) echo "    ERROR: unknown architecture $(uname -m)"; exit 1 ;;
esac
if [ -f "$SFW_BIN" ] && [ "$(/usr/bin/shasum -a 256 "$SFW_BIN" | cut -d' ' -f1)" = "$SFW_SHA" ]; then
  if [ "$(/usr/bin/stat -f %Su "$SFW_BIN")" != "root" ]; then
    sudo /usr/sbin/chown root:wheel "$SFW_BIN" && sudo /bin/chmod 755 "$SFW_BIN"
    echo "    already installed, checksum ok, now owned by root"
  else
    echo "    already installed, checksum ok, owned by root"
  fi
else
  TMPD=$(mktemp -d)
  trap 'rm -rf "$TMPD"' EXIT
  /usr/bin/curl -fsSL -o "$TMPD/sfw" \
    "https://github.com/SocketDev/sfw-free/releases/download/$SFW_VERSION/$SFW_ASSET"
  GOT=$(/usr/bin/shasum -a 256 "$TMPD/sfw" | cut -d' ' -f1)
  if [ "$GOT" != "$SFW_SHA" ]; then
    echo "    ERROR: checksum mismatch ($GOT). Aborted, nothing installed."; exit 1
  fi
  sudo /usr/bin/install -d -o root -g wheel -m 755 /usr/local/bin
  sudo /usr/bin/install -o root -g wheel -m 755 "$TMPD/sfw" "$SFW_BIN"
  echo "    installed, checksum ok"
fi

echo "6/7 Audit tools via brew: osv-scanner, pip-audit"
for f in osv-scanner pip-audit; do
  if brew list --formula "$f" >/dev/null 2>&1; then echo "    $f already there"; else brew install "$f"; fi
done

echo "7/7 Skills /dep-check, /patch-check and package settings for the terminal"
for s in dep-check patch-check; do
  mkdir -p "$HOME/.claude/skills/$s"
  # the skills name the release-age window; write the policy's days into them
  /usr/bin/sed "s/ 7 days/ $DAYS days/g" "skills/$s/SKILL.md" > "$HOME/.claude/skills/$s/SKILL.md"
  echo "    Skill: ~/.claude/skills/$s/SKILL.md"
done
COMPOSER_CONF="${COMPOSER_HOME:-$HOME/.composer}/config.json"
if [ ! -f "$COMPOSER_CONF" ]; then
  mkdir -p "$(dirname "$COMPOSER_CONF")"
  /usr/bin/sed "s/\"7 days\"/\"$DAYS days\"/" snippets/composer-config.json > "$COMPOSER_CONF"
  echo "    Composer: $COMPOSER_CONF created (release age $DAYS days)"
elif grep -q '"cooldown"' "$COMPOSER_CONF"; then
  if grep -q "\"$DAYS days\"" "$COMPOSER_CONF"; then
    echo "    Composer: release age $DAYS days already in $COMPOSER_CONF, unchanged"
  else
    echo "    NOTE: $COMPOSER_CONF has another release age than the policy ($DAYS days). Please change \"period\" yourself."
  fi
else
  echo "    NOTE: $COMPOSER_CONF already exists, not changed. Please copy the release age from snippets/composer-config.json yourself."
fi
NPMRC="$HOME/.npmrc"
if [ -f "$NPMRC" ] && grep -qE '>>> (package protection|Paket-Schutz)' "$NPMRC"; then
  if grep -qx "min-release-age=$DAYS" "$NPMRC"; then
    echo "    ~/.npmrc: already present, unchanged"
  else
    echo "    NOTE: ~/.npmrc has another min-release-age than the policy ($DAYS days). Please change it yourself."
  fi
else
  [ -f "$NPMRC" ] && cp -p "$NPMRC" "$NPMRC.bak-$STAMP"
  { [ -f "$NPMRC.bak-$STAMP" ] && cat "$NPMRC.bak-$STAMP" && echo
    /usr/bin/sed "s/^min-release-age=7\$/min-release-age=$DAYS/" snippets/npmrc.txt; } > "$NPMRC.new"
  mv "$NPMRC.new" "$NPMRC"
  echo "    ~/.npmrc: block added"
fi
if [ -d "$HOME/Library/Application Support/pip" ]; then
  PIPCONF="$HOME/Library/Application Support/pip/pip.conf"
else
  PIPCONF="$HOME/.config/pip/pip.conf"
fi
if [ -f "$PIPCONF" ]; then
  if grep -qE 'package protection|Paket-Schutz' "$PIPCONF"; then
    if grep -q "uploaded-prior-to = P${DAYS}D" "$PIPCONF"; then echo "    pip.conf: already present, unchanged"
    else echo "    NOTE: $PIPCONF has another uploaded-prior-to than the policy (P${DAYS}D). Please change it yourself."
    fi
  else echo "    NOTE: $PIPCONF already exists, not changed. Please copy the values from snippets/pip.conf yourself."
  fi
else
  mkdir -p "$(dirname "$PIPCONF")"
  /usr/bin/sed "s/P7D/P${DAYS}D/" snippets/pip.conf > "$PIPCONF"
  echo "    pip.conf: $PIPCONF created"
fi

echo
echo "Done. Restart every running Claude Code session (VS Code: reload the window)."
