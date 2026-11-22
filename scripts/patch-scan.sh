#!/bin/bash
# /patch-check: read-only scan of the active projects. Installs and changes nothing.
# Usage: bash patch-scan.sh <output file>  (e.g. in the Claude session scratchpad, never inside a repo)

OUT="${1:?usage: patch-scan.sh <output file>}"
# Projects and their root come from patch_scan in policy.json (the checkout's, else the
# installed one), so the list is configuration and not part of the script.
HERE="$(cd "$(dirname "$0")" && pwd)"
POLICY="$HERE/../policy.json"
[ -f "$POLICY" ] || POLICY="/Library/Application Support/ClaudeCode/policy.json"
read_policy() { /usr/bin/python3 -I -c '
import json, os, sys
p = json.load(open(sys.argv[1], encoding="utf-8")).get("patch_scan") or {}
if sys.argv[2] == "root":
    print(os.path.expanduser(p.get("root", "~")))
else:
    for x in p.get("projects", []):
        print(x)
' "$POLICY" "$1"; }
D="$(read_policy root)" || { echo "policy.json not readable: $POLICY" >&2; exit 1; }
PROJECTS="$(read_policy projects)"
[ -n "$PROJECTS" ] || { echo "no projects in patch_scan.projects ($POLICY)" >&2; exit 1; }

# Find files without descending into dependency or VCS folders
ffind() { find "$1" \( -name node_modules -o -name vendor -o -name .git -o -name .venv -o -name venv \) -prune -o -name "$2" -type f -print 2>/dev/null; }

{
echo "# patch-scan $(date '+%F %T')"
for p in $PROJECTS; do
  r="$D/$p"
  echo
  echo "################ $p"
  [ -d "$r" ] || { echo "!! folder missing"; continue; }
  cd "$r" || continue

  echo "== runtime constraints"
  for f in .nvmrc .node-version .python-version .tool-versions; do
    ffind . "$f" | while read -r x; do echo "$x: $(head -1 "$x")"; done
  done
  ffind . composer.json | while read -r x; do echo "$x php: $(grep -o '"php" *: *"[^"]*"' "$x" | head -1)"; done
  ffind . package.json | while read -r x; do e=$(grep -A2 '"engines"' "$x" | tr -d '\n '); [ -n "$e" ] && echo "$x $e"; done
  ffind . Dockerfile | while read -r x; do grep -iH '^FROM' "$x"; done

  echo "== osv-scanner"
  osv-scanner scan source -r . 2>&1 | tail -n 120

  ffind . package-lock.json | while read -r x; do
    dd=$(dirname "$x"); echo "== npm audit --omit=dev ($dd)"
    (cd "$dd" && command npm audit --omit=dev 2>&1 | tail -n 60)
    echo "== npm outdated ($dd)"
    (cd "$dd" && command npm outdated 2>&1 | head -n 60)
  done

  ffind . composer.lock | while read -r x; do
    dd=$(dirname "$x"); echo "== composer audit ($dd)"
    (cd "$dd" && composer audit --locked --no-plugins --no-scripts --no-interaction 2>&1 | tail -n 60)
    echo "== composer outdated --direct ($dd)"
    (cd "$dd" && composer outdated --direct --locked --no-plugins --no-scripts --no-interaction 2>&1 | head -n 60)
  done

  find . -maxdepth 4 -name node_modules -prune -o -name pyvenv.cfg -type f -print 2>/dev/null | while read -r x; do
    v=$(dirname "$x"); echo "== venv $v: $("$v/bin/python" -V 2>&1)"
    echo "-- pip-audit"
    PIPAPI_PYTHON_LOCATION="$v/bin/python" pip-audit 2>&1 | tail -n 60
    echo "-- pip list --outdated"
    "$v/bin/python" -m pip list --outdated --disable-pip-version-check 2>&1 | head -n 60
  done
done
echo
echo "# done $(date '+%T')"
} 2>&1 | tee "$OUT"
echo
echo ">> result: $OUT"
