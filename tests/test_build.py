"""Tests for the layer merge in build.py (docs/design-notes.md, 8): what an organisation or machine
layer may do over baseline.json, and everything it must not do.

Run: /usr/bin/python3 -I tests/test_build.py
"""
import copy
import datetime
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("build", os.path.join(HERE, "..", "build.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

ORG = json.load(open(os.path.join(HERE, "fixtures", "org.json"), encoding="utf-8"))
LOCAL = json.load(open(os.path.join(HERE, "fixtures", "local.json"), encoding="utf-8"))
TMP = tempfile.mkdtemp(prefix="buildtest-")
TODAY = datetime.date(2026, 11, 21)
verbose = "-v" in sys.argv
fails = total = 0


def check(label, ok):
    global fails, total
    total += 1
    fails += not ok
    if verbose or not ok:
        print(f"{'ok  ' if ok else 'FAIL'} {label}")


def merged(org_changes=None, local_changes=None):
    """(policy, None) or (None, error text) for the fixture layers with changes."""
    org, local = copy.deepcopy(ORG), copy.deepcopy(LOCAL)
    for layer, changes in ((org, org_changes), (local, local_changes)):
        for k, v in (changes or {}).items():
            if v is None:
                layer.pop(k, None)
            else:
                layer[k] = v
    paths = []
    for name, layer in (("org.json", org), ("local.json", local)):
        p = os.path.join(TMP, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(layer, f)
        paths.append(p)
    try:
        return build.effective(paths[0], paths[1], today=TODAY), None
    except build.LayerError as e:
        return None, str(e)


def refused(label, contains, **kw):
    p, err = merged(**kw)
    check(f"refused: {label}", p is None and contains in (err or ""))
    if p is not None or contains not in (err or ""):
        print(f"     message: {err!r}")


def exc(**kw):
    e = {"id": "personal.access-log", "action": "off", "reason": "Test",
         "expires": "2027-01-01"}
    e.update(kw)
    return {"exceptions": [e]}


# --- the fixture layers build, and the result is what the hook reads -------------
P, err = merged()
check("fixture layers build " + (err or ""), P is not None)
check("organisation set", P["organization"]["name"] == ORG["set"]["organization.name"])
check("own domains added", [d["domain"] for d in P["domains"]["own"]]
      == [d["domain"] for d in ORG["add"]["domains.own"]])
check("patterns are plain strings for guard.py",
      all(isinstance(x, str) for c in ("secret_files", "personal_files")
          for x in P["data_classes"][c]["patterns"]))
check("baseline_version is in the policy", P["baseline_version"] == "1.0.0")
check("locked pattern secret.env is present",
      any("\\.env" in x for x in P["data_classes"]["secret_files"]["patterns"]))

# --- set: only values without a security direction ----------------------------
refused("set of a value with a security direction", "is not allowed",
        local_changes={"set": {"package_protection.require_sfw": False}})
refused("set of an unknown key", "is not allowed",
        local_changes={"set": {"foo.bar": 1}})
p, _ = merged(local_changes={"set": {"logging.enabled": False}})
check("set of an allowed value", p is not None and p["logging"]["enabled"] is False)

# --- add: facts, never into a tighten list ---------------------------------------
refused("add into a tighten list", "tighten list",
        local_changes={"add": {"data_classes.secret_files.patterns":
                               [{"id": "x", "pattern": "x"}]}})
refused("add into an unknown list", "is not allowed",
        local_changes={"add": {"always_ask.git_network_outside_sandbox": ["git gc"]}})
refused("duplicate domain", "already exists",
        local_changes={"add": {"domains.own": [ORG["add"]["domains.own"][0]]}})
refused("domain the baseline already has", "already exists",
        local_changes={"add": {"domains.documentation": ["owasp.org"]}})
refused("add without a list", "needs a list",
        local_changes={"add": {"ssh.hosts": {"host": "x"}}})
p, _ = merged(local_changes={"add": {"domains.documentation": ["docs.example.dev"]}})
check("add of a documentation domain", p is not None and "docs.example.dev" in p["domains"]["documentation"])

# --- tighten: only stricter ------------------------------------------------------
refused("tighten that loosens (age 3 days)", "not stricter",
        local_changes={"tighten": {"package_protection.min_release_age_days": 3}})
p, _ = merged(local_changes={"tighten": {"package_protection.min_release_age_days": 14}})
check("tighten to 14 days", p is not None
      and p["package_protection"]["min_release_age_days"] == 14)
refused("tighten of the minimum version downwards", "not stricter",
        local_changes={"tighten": {"claude_code.required_minimum_version": "2.1.0"}})
p, _ = merged(local_changes={"tighten": {"data_classes.personal_files.patterns":
                                         [{"id": "personal.audit", "pattern": "audit\\.log"}]}})
check("tighten by a pattern", p is not None
      and "audit\\.log" in p["data_classes"]["personal_files"]["patterns"])
refused("tighten into an add list", "add list",
        local_changes={"tighten": {"domains.own": []}})

# --- exceptions: id, reason, expiry; never on locked entries --------------------
p, _ = merged(local_changes=exc())
check("exception off removes the pattern", p is not None
      and not any("access" in x for x in p["data_classes"]["personal_files"]["patterns"]))
refused("exception without reason", "without reason", local_changes=exc(reason=""))
refused("exception without expiry", "without expires", local_changes=exc(expires=""))
refused("exception with a broken date", "not a date", local_changes=exc(expires="soon"))
refused("expired exception", "expired", local_changes=exc(expires="2026-11-20"))
refused("exception on a locked pattern", "locked", local_changes=exc(id="secret.env"))
refused("exception on a locked path", "locked",
        local_changes=exc(id="credentials.read_deny:~/.ssh/id_*"))
refused("exception on a locked value", "locked",
        local_changes=exc(id="package_protection.require_sfw", action="set", value=False))
refused("exception on an unknown id", "does not exist", local_changes=exc(id="personal.nonexistent"))
refused("exception with an unknown action", "unknown", local_changes=exc(action="gone"))
refused("exception set on a value without direction", "action set only",
        local_changes=exc(id="logging.enabled", action="set", value=False))
p, _ = merged(local_changes=exc(id="claude_code.lock_lower_scopes", action="set", value=False))
check("exception set loosens the lock on the lower scopes",
      p is not None and p["claude_code"]["lock_lower_scopes"] is False)
p, _ = merged(local_changes=exc(id="ssh.write", action="shadow"))
check("exception shadow puts the rule into shadow mode",
      p is not None and p["shadow_rules"]["ids"] == ["ssh.write"])
p, _ = merged(local_changes=exc(id="credentials.read_deny:~/.aws/**"))
check("exception off on a plain list entry", p is not None
      and "~/.aws/**" not in p["credentials"]["read_deny"])

# --- shape of values and entries (the schema build.py checks itself) ------------
refused("set with the wrong type", "baseline's type", local_changes={"set": {"logging.enabled": "no"}})
refused("set of a list with non-text", "baseline's type",
        org_changes={"set": {"organization.source_control": [1]}})
refused("tighten with the wrong type", "baseline's type",
        local_changes={"tighten": {"package_protection.min_release_age_days": "14"}})
refused("domain without purposes", "purposes",
        local_changes={"add": {"domains.own": [{"domain": "x.example"}]}})
refused("domain with an unknown purpose", "purposes",
        local_changes={"add": {"domains.own": [{"domain": "x.example", "purposes": ["everything"]}]}})
refused("domain that is none", "not a domain name",
        local_changes={"add": {"domains.own": [{"domain": "x example", "purposes": ["network"]}]}})
refused("host with a space", "needs host",
        local_changes={"add": {"ssh.hosts": [{"host": "web 9"}]}})
refused("pattern that is not a regular expression", "not a regular expression",
        local_changes={"tighten": {"data_classes.secret_files.patterns":
                                   [{"id": "secret.broken", "pattern": "(("}]}})
refused("empty entry", "non-empty text",
        local_changes={"add": {"working_directories.paths": [""]}})
refused("pattern id that already exists", "appears twice",
        local_changes={"tighten": {"data_classes.personal_files.patterns":
                                   [{"id": "secret.env", "pattern": "x"}]}})
refused("the same exception twice", "does not exist", local_changes={"exceptions": [
    {"id": "personal.access-log", "action": "off", "reason": "a", "expires": "2027-01-01"},
    {"id": "personal.access-log", "action": "off", "reason": "b", "expires": "2027-01-01"}]})

# --- layer shape and baseline version --------------------------------------------
refused("unknown key in the layer", "unknown keys",
        local_changes={"overrides": {}})
refused("requires_baseline missing", "requires_baseline missing",
        local_changes={"requires_baseline": None})
refused("baseline version does not match", "requires baseline",
        org_changes={"requires_baseline": ">=2.0 <3"})
refused("requires_baseline not readable", "not readable",
        org_changes={"requires_baseline": "^1.0"})
check("version comparison", build.version_ok("1.2.0", ">=1.0 <2")
      and not build.version_ok("2.0.0", ">=1.0 <2") and build.version_ok("1.0", "==1.0.0"))
check("versions numeric, not as text", build.version_tuple("2.1.314")
      > build.version_tuple("2.1.99"))

# --- renamed ids: an exception with an old id keeps working, with a hint ---------
orig_read = build.read_json


def read_with_rename(path):
    obj = orig_read(path)
    if path == build.BASELINE:
        obj["renamed"] = {"personal.alt-access": "personal.access-log"}
    return obj


build.read_json = read_with_rename
p, err = merged(local_changes=exc(id="personal.alt-access"))
build.read_json = orig_read
check("renamed id maps to the new one " + (err or ""), p is not None
      and not any("access" in x for x in p["data_classes"]["personal_files"]["patterns"]))

# --- the examples in examples/ build ------------------------------------------
EX = os.path.join(HERE, "..", "examples")
try:
    ex = build.effective(os.path.join(EX, "org.example.json"),
                         os.path.join(EX, "local.example.json"), today=TODAY)
    ex_err = ""
except build.LayerError as e:
    ex, ex_err = None, str(e)
check("examples/ build " + ex_err, ex is not None
      and not any("mail" in x for x in ex["data_classes"]["personal_files"]["patterns"]))
# Your own layers are not checked here: they live in your --config folder, with its own tests.
check("examples/ carry the baseline version", ex is not None
      and ex["baseline_version"] == build.read_json(build.BASELINE)["baseline_version"])

shutil.rmtree(TMP)
print(f"{total} layer checks, FAILURES: {fails}")
sys.exit(1 if fails else 0)
