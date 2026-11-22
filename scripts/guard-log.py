#!/usr/bin/env python3
"""Reads the hook's decision log and says which rules fire how often.

    ./scripts/guard-log.py                 summary of the last 7 days
    ./scripts/guard-log.py --days 30       other period
    ./scripts/guard-log.py --rule ssh.data the calls one rule decided
    ./scripts/guard-log.py --asks          every question, newest first
    ./scripts/guard-log.py --shadow        what a shadow rule would have asked

Use it to decide whether a rule earns its questions: a rule that asks a lot and is
always approved is a candidate for a narrower pattern in policy.json, one that never
fires may be dead. docs/design-notes.md, 1.

Must run on /usr/bin/python3 (3.9): standard library only.
"""
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_PATHS = ("/Library/Application Support/ClaudeCode/policy.json",
                os.path.join(HERE, os.pardir, "policy.json"))


def log_path():
    for p in POLICY_PATHS:
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return os.path.expanduser(json.load(f)["logging"]["path"])
    sys.exit("policy.json not found")


def read(path, days):
    cutoff = datetime.datetime.now() - datetime.timedelta(days=days)
    out = []
    files = [path] + ["%s.%d" % (path, i) for i in range(1, 4)]
    for f in files:
        if not os.path.exists(f):
            continue
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if datetime.datetime.fromisoformat(rec["t"]) >= cutoff:
                        out.append(rec)
                except (ValueError, KeyError):
                    continue
    return sorted(out, key=lambda r: r["t"])


def arg(name, default=None):
    if name in sys.argv:
        i = sys.argv.index(name)
        return sys.argv[i + 1] if i + 1 < len(sys.argv) else default
    return default


def main():
    path = log_path()
    days = int(arg("--days", "7"))
    recs = read(path, days)
    if not recs:
        print("No entries in the last %d days (%s)." % (days, path))
        print("The sandbox may not write to this path; the hook runs outside it.")
        print("If this stays empty, check in your terminal whether the file grows.")
        return 0

    rule = arg("--rule")
    if rule:
        for r in recs:
            if rule in r.get("rules", []) or any(s["rule"] == rule
                                                 for s in r.get("shadow", [])):
                print("%s  %-5s  %s" % (r["t"], r["decision"], r.get("command", "")))
        return 0
    if "--asks" in sys.argv:
        for r in reversed(recs):
            if r["decision"] in ("ask", "deny"):
                print("%s  %-5s  %-22s %s" % (r["t"], r["decision"],
                                              ",".join(r.get("rules", []))[:22],
                                              r.get("command", "")))
        return 0
    if "--shadow" in sys.argv:
        for r in recs:
            for s in r.get("shadow", []):
                print("%s  %-22s %s" % (r["t"], s["rule"], r.get("command", "")))
        return 0

    counts, by_rule, by_tool = {}, {}, {}
    for r in recs:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1
        by_tool[r.get("tool", "?")] = by_tool.get(r.get("tool", "?"), 0) + 1
        for x in r.get("rules", []):
            by_rule[x] = by_rule.get(x, 0) + 1
        for s in r.get("shadow", []):
            key = s["rule"] + " (shadow)"
            by_rule[key] = by_rule.get(key, 0) + 1
    total = len(recs)
    print("%d entries in the last %d days, %s" % (total, days, path))
    print("  " + ", ".join("%s: %d" % (k, counts[k]) for k in sorted(counts)))
    print("\nRules that asked (most frequent first):")
    if not by_rule:
        print("  none")
    for name, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        share = 100.0 * n / total
        print("  %-28s %4d  (%4.1f %% of all entries)" % (name, n, share))
    print("\nTools: " + ", ".join("%s %d" % (k, v) for k, v in
                                      sorted(by_tool.items(), key=lambda kv: -kv[1])))
    noisy = [n for n, c in by_rule.items() if c >= 10 and not n.endswith("(shadow)")]
    if noisy:
        print("\nFrequent questions: " + ", ".join(sorted(noisy)))
        print("Look at them with --rule <name>. Questions wear out (design notes, 1): when a")
        print("rule asks often and is always approved, narrow its pattern in policy.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
