#!/bin/bash
# Removes the Claude Code base protection again. Run as your normal user.
set -uo pipefail
cd "$(dirname "$0")"
SYS="/Library/Application Support/ClaudeCode"
# LaunchAgent name of the ssh-agent, from install.launchagent_label in policy.json.
# Only letters, digits, dots and dashes: it ends up in a path, a plist and launchctl.
# Read from the installed policy, so uninstall needs no --config; else from this checkout.
POL="$SYS/policy.json"; [ -r "$POL" ] || POL="policy.json"
LABEL=$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["install"]["launchagent_label"])' "$POL")
[[ "$LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo "install.launchagent_label invalid: $LABEL" >&2; exit 1; }
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

sudo rm -f "$SYS/managed-settings.json" "$SYS/policy.json" "$SYS/hooks/guard.py" \
           "$SYS/bin/ssh-proxy.py"
/bin/launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null; rm -f "$PLIST"
# remove the marked block from ~/.ssh/config
/usr/bin/sed -i '.bak-uninstall' '/^# >>> Claude-Code-Sandbox/,/^# <<< Claude-Code-Sandbox/d' "$HOME/.ssh/config"

# package protection (also removes blocks from older installs with the German marker)
sudo rm -f /usr/local/bin/sfw
rm -rf "$HOME/.claude/skills/dep-check" "$HOME/.claude/skills/patch-check"
COMPOSER_CONF="${COMPOSER_HOME:-$HOME/.composer}/config.json"
if [ -f "$COMPOSER_CONF" ] && cmp -s "$COMPOSER_CONF" snippets/composer-config.json; then
  rm "$COMPOSER_CONF"
fi
[ -f "$HOME/.npmrc" ] && /usr/bin/sed -E -i '.bak-uninstall' '/^# >>> (package protection|Paket-Schutz)/,/^# <<< (package protection|Paket-Schutz)/d' "$HOME/.npmrc"
for c in "$HOME/Library/Application Support/pip/pip.conf" "$HOME/.config/pip/pip.conf"; do
  [ -f "$c" ] && grep -qE 'package protection|Paket-Schutz' "$c" && rm -f "$c"
done
echo "osv-scanner and pip-audit stay installed (remove: brew uninstall osv-scanner pip-audit)."
echo "Removed. Restart the Claude Code sessions."
