#!/bin/bash
# Rotates the ssh key on your own servers: ~/.ssh/id_rsa -> ~/.ssh/id_ed25519
# (docs/design-notes.md, 10). Run in your own terminal, not in the sandbox.
#
#   ssh-key-rotate.sh add        host...   add the new key (login with the old key), then test
#   ssh-key-rotate.sh test       host...   test login with the new key only
#   ssh-key-rotate.sh remove-old host...   remove the old key (login with the new key), a backup stays
#
# Every connection uses exactly one key: User, HostName and Port come from `ssh -G`, and it connects with
# `-F /dev/null` so IdentityFile lines from ~/.ssh/config are not offered as well. The test also checks the
# ssh output that the server accepted exactly the expected key.
# Agent: the current one (SSH_AUTH_SOCK); the passphrase of id_ed25519 comes from the keychain (UseKeychain).
set -u

NEW_KEY="$HOME/.ssh/id_ed25519"
NEW_PUB="$NEW_KEY.pub"
OLD_KEY="$HOME/.ssh/id_rsa"
OPTS=(-F /dev/null -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes -o ForwardAgent=no
      -o ControlMaster=no -o ControlPath=none -o UseKeychain=yes -o AddKeysToAgent=yes)

mode=${1:-}
[ $# -ge 2 ] || { sed -n '5,7p' "$0" | sed 's/^# *//'; exit 2; }
shift
[ -r "$NEW_PUB" ] || { echo "missing: $NEW_PUB" >&2; exit 1; }
new_blob=$(cut -d' ' -f2 "$NEW_PUB")
new_fp=$(ssh-keygen -lf "$NEW_PUB" | cut -d' ' -f2)

# key_ssh <key> <host> <command>: connect with this key only
key_ssh() {
  local id=$1 h=$2 g hn u p; shift 2
  g=$(ssh -G "$h" 2>/dev/null) || { echo "ssh -G $h failed" >&2; return 255; }
  if grep -qiE '^(proxycommand|proxyjump) ' <<<"$g"; then echo "ProxyCommand/ProxyJump set, not supported" >&2; return 255; fi
  hn=$(awk '$1=="hostname"{print $2; exit}' <<<"$g")
  u=$(awk '$1=="user"{print $2; exit}' <<<"$g")
  p=$(awk '$1=="port"{print $2; exit}' <<<"$g")
  ssh "${OPTS[@]}" ${KEY_SSH_VERBOSE:+-v} -o IdentityFile="$id" -o User="$u" -o Port="$p" "$hn" "$@"
}
ssh_new() { key_ssh "$NEW_KEY" "$@"; }
ssh_old() { key_ssh "$OLD_KEY" "$@"; }
# ok only if the server accepted the new key (fingerprint)
check() { KEY_SSH_VERBOSE=1 key_ssh "$NEW_KEY" "$1" true </dev/null 2>&1 >/dev/null | grep 'Server accepts key:' | grep -qF "$new_fp"; }

# Runs on the server (POSIX sh). stdin: the line with the new public key.
REMOTE_ADD='IFS= read -r k; b=$(printf "%s\n" "$k" | cut -d" " -f2); umask 077; f="$HOME/.ssh/authorized_keys"
mkdir -p "$HOME/.ssh" && touch "$f" || exit 1
if grep -qF "$b" "$f"; then echo "already present"; else printf "%s\n" "$k" >> "$f" && echo "added"; fi'

# stdin: "<old blob> <new blob>". Aborts if the new key would be missing afterwards.
REMOTE_REMOVE='read -r o n; f="$HOME/.ssh/authorized_keys"
grep -qF "$o" "$f" || { echo "old key not present (any more)"; exit 0; }
bak="$f.bak-rsa-$(date +%Y%m%d%H%M%S)"; cp -p "$f" "$bak" || exit 1
grep -vF "$o" "$bak" > "$f.tmp"
grep -qF "$n" "$f.tmp" || { rm -f "$f.tmp"; echo "ABORTED: new key missing in $f"; exit 1; }
cat "$f.tmp" > "$f" && rm -f "$f.tmp" && echo "removed (backup: $bak)"'

rc=0
for h in "$@"; do
  printf '%-45s ' "$h"
  case "$mode" in
    add)
      out=$(ssh_old "$h" "$REMOTE_ADD" < "$NEW_PUB" 2>&1) || { echo "ERROR while adding: $out"; rc=1; continue; }
      if check "$h"; then echo "$out, Test ok"; else echo "$out, TEST FAILED"; rc=1; fi ;;
    test)
      if check "$h"; then echo "ok"; else echo "FAILED"; rc=1; fi ;;
    remove-old)
      check "$h" || { echo "skipped: new key does not work"; rc=1; continue; }
      old_blob=$(ssh-keygen -y -f "$OLD_KEY" | cut -d' ' -f2) || { echo "old key not readable"; exit 1; }
      out=$(printf '%s %s\n' "$old_blob" "$new_blob" | ssh_new "$h" "$REMOTE_REMOVE" 2>&1) || rc=1
      if check "$h"; then echo "$out, Test ok"; else echo "$out, TEST AFTERWARDS FAILED"; rc=1; fi ;;
    *) echo "unknown mode: $mode" >&2; exit 2 ;;
  esac
done
exit $rc
