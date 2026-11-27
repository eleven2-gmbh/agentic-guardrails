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
# the hint goes to stderr; caught here so it does not read like a note about the own
# configuration in the output of install.sh
import contextlib
import io
_hint = io.StringIO()
with contextlib.redirect_stderr(_hint):
    p, err = merged(local_changes=exc(id="personal.alt-access"))
build.read_json = orig_read
check("renamed id maps to the new one " + (err or ""), p is not None
      and not any("access" in x for x in p["data_classes"]["personal_files"]["patterns"]))
check("renamed id: the hint names the new id and --migrate",
      "personal.alt-access is now called personal.access-log" in _hint.getvalue()
      and "--migrate" in _hint.getvalue())

# --- layer_format: missing means 1, newer than the product stops ----------------
p, err = merged(local_changes={"layer_format": 1})
check("layer_format 1 builds " + (err or ""), p is not None)
refused("layer_format newer than the product", "newer than this product",
        local_changes={"layer_format": build.LAYER_FORMAT + 1})
refused("layer_format not a number", "whole number", local_changes={"layer_format": "1"})
refused("layer_format true", "whole number", local_changes={"layer_format": True})

# --- migrate_layer: format steps and renamed paths -------------------------------
build.LAYER_FORMAT, build.FORMAT_STEPS = 2, {1: lambda l: dict(l, note=["step ran"])}
m, notes = build.migrate_layer({"requires_baseline": ">=1.0 <2"}, {}, {}, "t")
check("format step runs and records the new format",
      m.get("layer_format") == 2 and m["note"] == ["step ran"] and notes)
build.LAYER_FORMAT, build.FORMAT_STEPS = 1, {}
paths = {"patch_scan.root": "patch_scan.base", "credentials.read_deny": "credentials.deny"}
m, notes = build.migrate_layer(
    {"set": {"logging.enabled": True, "patch_scan.root": "~/c"},
     "exceptions": [{"id": "credentials.read_deny:~/.aws/**"},
                    {"id": "personal.alt-access"}]},
    {"personal.alt-access": "personal.access-log"}, paths, "t")
check("renamed path in set, order kept",
      list(m["set"]) == ["logging.enabled", "patch_scan.base"])
check("renamed list path inside an exception id",
      m["exceptions"][0]["id"] == "credentials.deny:~/.aws/**")
check("renamed id in an exception", m["exceptions"][1]["id"] == "personal.access-log")
check("one note per change", len(notes) == 3)
try:
    build.migrate_layer({"set": {"patch_scan.root": "a", "patch_scan.base": "b"}}, {},
                        paths, "t")
    check("rename onto a key the layer already has is refused", False)
except build.LayerError as e:
    check("rename onto a key the layer already has is refused", "by hand" in str(e))
m, notes = build.migrate_layer(ORG, {}, {}, "t")
check("a current layer stays unchanged", m == ORG and not notes)

# --- the baseline's renames point at something that exists ------------------------
BASE, BPOL = build.load_baseline()
BIDS = build.index_ids(BPOL)
for old, new in (BASE.get("renamed") or {}).items():
    check("renamed {} -> {}: new exists, old is gone".format(old, new),
          new in BIDS and old not in BIDS)
for old, new in (BASE.get("renamed_paths") or {}).items():
    known = build.SETTABLE | build.ADD_LISTS | build.TIGHTEN_LISTS | set(build.TIGHTEN_VALUES)
    check("renamed path {} -> {}: new is a layer path, old is not".format(old, new),
          new in known and old not in known)

# --- describe: the rules as data, consistent with build.py ------------------------
D = build.describe()
check("describe carries both versions", D["baseline_version"] == BASE["baseline_version"]
      and D["layer_format"] == build.LAYER_FORMAT)
check("describe lists every layer path", set(D["set"]) == build.SETTABLE
      and set(D["add"]) == build.ADD_LISTS
      and set(D["tighten"]) == build.TIGHTEN_LISTS | set(build.TIGHTEN_VALUES))
check("describe never offers a locked id for an exception",
      not set(D["locked"]) & (set(D["exceptions"]["off"]) | set(D["exceptions"]["set"])))
check("describe is JSON", json.loads(json.dumps(D)) == D)
LAYER_PATHS = build.SETTABLE | build.ADD_LISTS | build.TIGHTEN_LISTS | set(build.TIGHTEN_VALUES)
check("every layer path has an explanation, and only those",
      set(build.HELP) == LAYER_PATHS and all(build.HELP[p].strip() for p in LAYER_PATHS))
check("describe carries the explanations",
      all(D[op][p]["help"] == build.HELP[p] for op in ("set", "add", "tighten") for p in D[op]))
check("describe: requires_baseline accepts the baseline",
      build.version_ok(BASE["baseline_version"], D["requires_baseline"]))

# --- schema: generated, current, and accepted in a layer ----------------------------
SCH = build.schema()
check("layer.schema.json in the checkout is current (run ./build.py --schema > layer.schema.json)",
      open(build.SCHEMA_FILE, encoding="utf-8").read() == build.schema_text())
props = SCH["properties"]
check("schema knows every layer key", set(props) == build.LAYER_KEYS)
check("schema lists every layer path, and no other",
      set(props["set"]["properties"]) == build.SETTABLE
      and set(props["add"]["properties"]) == build.ADD_LISTS
      and set(props["tighten"]["properties"]) == build.TIGHTEN_LISTS | set(build.TIGHTEN_VALUES))
check("schema refuses unknown keys like build.py", SCH["additionalProperties"] is False
      and all(props[op]["additionalProperties"] is False for op in ("set", "add", "tighten")))
check("schema explains every path",
      all(build.HELP[p] in props[op]["properties"][p]["description"]
          for op in ("set", "add", "tighten") for p in props[op]["properties"]))
check("schema never offers a locked id",
      not set(props["exceptions"]["items"]["properties"]["id"]["examples"]) & set(D["locked"]))
p, err = merged(org_changes={"$schema": "../agentic-guardrails/layer.schema.json"})
check("a layer with $schema builds " + (err or ""), p is not None)

orig_tag = build.checkout_tag
build.checkout_tag = lambda: "v9.8.7"
check("at a release tag, $schema is that release's URL", build.schema_ref(TMP)
      == "https://raw.githubusercontent.com/eleven2-gmbh/agentic-guardrails/v9.8.7/layer.schema.json")
build.checkout_tag = lambda: None
check("between releases, $schema is the path to the checkout's file",
      os.path.samefile(os.path.join(TMP, build.schema_ref(TMP)), build.SCHEMA_FILE))
build.checkout_tag = orig_tag

# --- init: both templates build, nothing is overwritten -----------------------------
for tpl in build.TEMPLATES:
    folder = os.path.join(TMP, "init-" + tpl)
    try:
        written = build.init(folder, tpl, host="testhost")
        ierr = ""
    except build.LayerError as e:
        written, ierr = [], str(e)
    check("init {} writes two layers that build {}".format(tpl, ierr),
          [os.path.basename(f) for f in written] == ["org.json", "local.testhost.json"])
    for f in written:
        layer = json.load(open(f, encoding="utf-8"))
        check("init {}: {} names the schema first".format(tpl, os.path.basename(f)),
              list(layer)[0] == "$schema" and layer["$schema"] == build.schema_ref(folder))
    try:
        build.init(folder, tpl, host="testhost")
        check("init {} refuses to overwrite".format(tpl), False)
    except build.LayerError as e:
        check("init {} refuses to overwrite".format(tpl), "already present" in str(e))
try:
    build.init(os.path.join(TMP, "init-bad"), "fancy")
    check("init refuses an unknown template", False)
except build.LayerError as e:
    check("init refuses an unknown template", "unknown" in str(e))

# --- migrate: dry run writes nothing, --write writes, then current ------------------
import contextlib
import io

mdir = os.path.join(TMP, "migrate")
os.makedirs(mdir)
old_layer = dict(LOCAL, exceptions=[dict(exc()["exceptions"][0], id="personal.alt-access")])
with open(os.path.join(mdir, "local.box.json"), "w", encoding="utf-8") as f:
    json.dump(old_layer, f)
with open(os.path.join(mdir, "org.json"), "w", encoding="utf-8") as f:
    f.write(build.layer_text(ORG))
build.read_json = read_with_rename
saved = build.CONFIG
build.CONFIG = mdir
with contextlib.redirect_stdout(io.StringIO()) as out:
    n_dry = build.migrate(write=False)
dry_file = json.load(open(os.path.join(mdir, "local.box.json"), encoding="utf-8"))
with contextlib.redirect_stdout(io.StringIO()):
    n_write = build.migrate(write=True)
    n_after = build.migrate(write=False)
build.CONFIG = saved
build.read_json = orig_read
new_file = json.load(open(os.path.join(mdir, "local.box.json"), encoding="utf-8"))
check("migrate dry run finds one file and writes nothing",
      n_dry == 1 and dry_file == old_layer and "personal.access-log" in out.getvalue())
check("migrate --write writes the new id", n_write == 1
      and new_file["exceptions"][0]["id"] == "personal.access-log")
check("after migrate everything is current", n_after == 0)

# --- release age: one value for every package manager ------------------------------
p, err = merged(local_changes={"tighten": {"package_protection.min_release_age_days": 14}})
env = p["package_protection"]["env"]
check("a stricter release age reaches npm, pip, uv and Composer " + (err or ""),
      env["npm_config_min_release_age"] == "14" and env["PIP_UPLOADED_PRIOR_TO"] == "P14D"
      and env["UV_EXCLUDE_NEWER"] == "P14D" and env["COMPOSER_POLICY_COOLDOWN_PERIOD"] == "14 days")
check("... and the managed settings' env", build.build(p)["env"]["UV_EXCLUDE_NEWER"] == "P14D")
base_env = build.read_json(build.BASELINE)["policy"]["package_protection"]["env"]
P7, _ = merged()
check("the baseline's env already says what its release age says",
      P7["package_protection"]["env"] == base_env)
for snip, text in (("snippets/npmrc.txt", "min-release-age=7\n"), ("snippets/pip.conf", "P7D"),
                   ("snippets/composer-config.json", '"7 days"'),
                   ("skills/dep-check/SKILL.md", " 7 days"), ("skills/patch-check/SKILL.md", " 7 days")):
    check("{} carries the 7 days install.sh replaces".format(snip),
          text in open(os.path.join(HERE, "..", snip), encoding="utf-8").read()
          and build.read_json(build.BASELINE)["policy"]["package_protection"]["min_release_age_days"] == 7)

# --- read boundary and MCP list (design notes, 12) ------------------------------------
P0, _ = merged()
ms = build.build(P0, "darwin")
fs = ms["sandbox"]["filesystem"]
check("blockReadsOutsideWorkingDirectories is no longer written",
      "blockReadsOutsideWorkingDirectories" not in ms["permissions"]
      and ms["permissions"]["blockWritesOutsideWorkingDirectories"] is True)
check("macOS: denyRead holds /Users and /Volumes",
      {"/Users", "/Volumes"} <= set(fs["denyRead"]) and "/home" not in fs["denyRead"])
check("macOS: the per-user folders are resolved, no placeholder left",
      not any(x.startswith("@") for x in fs["denyRead"]))
if sys.platform == "darwin":
    check("macOS: denyRead holds the per-user folders 0, T and C",
          all(os.path.realpath(os.confstr(k)) in fs["denyRead"] for k in (65536, 65537, 65538)))
    check("macOS: allowRead holds exactly the xcrun cache in T, expanded",
          os.path.join(os.path.realpath(os.confstr(65537)), "xcrun_db") in fs["allowRead"]
          and not any(x.startswith("@") for x in fs["allowRead"]))
check("Linux: an allow_read entry with a per-user placeholder is dropped",
      not any("xcrun_db" in x or x.startswith("@")
              for x in build.build(P0, "linux")["sandbox"]["filesystem"]["allowRead"]))
bad = copy.deepcopy(P0)
bad["sandbox"]["allow_read"].append("@nope/x")
try:
    build.build(bad, "darwin")
    check("an unknown placeholder in allow_read stops the build", False)
except build.LayerError:
    check("an unknown placeholder in allow_read stops the build", True)
check("Linux: denyRead holds /home, /mnt, /media",
      build.build(P0, "linux")["sandbox"]["filesystem"]["denyRead"] == ["/home", "/mnt", "/media"])
work = [os.path.expanduser(d) for d in P0["working_directories"]["paths"]]
check("allowRead: working directories first, absolute, no '.'",
      fs["allowRead"][:len(work)] == work and "." not in fs["allowRead"]
      and all(x.startswith(("/", "~/")) for x in fs["allowRead"]))
check("allowRead: no folder that holds tokens",
      not {"~/.npmrc", "~/.composer", "~/.config/git", "~/.bashrc", "~/.profile",
           "~/.bash_profile"} & set(fs["allowRead"]))
# start roots: "." only with roots, and a root must lie strictly below the home folder
p, err = merged(local_changes={"add": {"working_directories.roots": ["~/Documents"]}})
check("roots: '.' joins allowRead, once, after the absolute paths " + (err or ""),
      p is not None and build.build(p, "darwin")["sandbox"]["filesystem"]["allowRead"]
      .count(".") == 1 and build.build(p, "darwin")["sandbox"]["filesystem"]["allowRead"][-1] == ".")
check("roots: the policy carries them for the hook",
      p is not None and p["working_directories"]["roots"] == ["~/Documents"])
check("roots: the baseline has none", P0["working_directories"]["roots"] == [])
for root in ("~", "~/", "/", "/tmp", os.path.dirname(os.path.realpath(os.path.expanduser("~"))),
             "~/../x"):
    p, err = merged(local_changes={"add": {"working_directories.roots": [root]}})
    try:
        build.build(p, "darwin") if p is not None else None
        stopped = p is None and "roots" in (err or "")
    except build.LayerError as e:
        stopped = "must lie inside the home folder" in str(e)
    check(f"roots: {root} stops the build", stopped)
p, err = merged(local_changes={"tighten": {"working_directories.roots": ["~/Documents"]}})
check("roots: not through tighten", p is None)
check("the hook also sees Read, Grep and Glob",
      all(t in ms["hooks"]["PreToolUse"][0]["matcher"].split("|") for t in ("Read", "Grep", "Glob")))
check("allowedMcpServers absent while restrict_servers is off", "allowedMcpServers" not in ms)
p, err = merged(local_changes={"tighten": {"mcp.restrict_servers": True},
                               "add": {"mcp.allowed_servers": ["docs"]}})
check("restrict_servers writes allowedMcpServers by name " + (err or ""),
      p is not None and build.build(p)["allowedMcpServers"] == [{"serverName": "docs"}])
p, err = merged(local_changes={"add": {"read_boundary.macos": ["/opt/homebrew/var"]}})
check("a layer cannot add to the boundary through add", p is None)
p, err = merged(local_changes={"tighten": {"read_boundary.macos": ["/opt/homebrew/var"]}})
check("a layer can widen the boundary through tighten " + (err or ""),
      p is not None and "/opt/homebrew/var" in build.build(p, "darwin")["sandbox"]["filesystem"]["denyRead"])
bad = copy.deepcopy(P0)
bad["read_boundary"]["macos"].append("@nope")
try:
    build.build(bad, "darwin")
    check("an unknown placeholder stops the build", False)
except build.LayerError:
    check("an unknown placeholder stops the build", True)

# --- the command line behaves like one ------------------------------------------------
import subprocess


def cli(*args):
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "build.py")] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return r.returncode, r.stdout + r.stderr


code, out = cli("--help")
check("--help shows the commands", code == 0 and "usage: ./build.py" in out and "--init DIR" in out)
code, out = cli("--version")
check("--version", code == 0 and out.startswith("agentic-guardrails ") and "baseline" in out)
for bad, says in ((["--chekc"], "unrecognized arguments"), (["--write"], "only goes with --migrate"),
                  (["--host", "x"], "only go with --init"), (["--check", "--diff"], "not allowed with"),
                  (["--init", TMP, "--config", TMP], "leave out --config")):
    code, out = cli(*bad)
    check("refused with a usage line: {}".format(" ".join(bad)), code == 2 and says in out
          and "usage:" in out)
code, out = cli("--config", os.path.join(TMP, "nope"))
check("missing folder: says how to create it", code == 2 and "./build.py --init" in out)
empty = os.path.join(TMP, "empty-folder")
os.makedirs(empty)
code, out = cli("--config", empty, "--diff")
check("folder without org.json: says how to create the layers",
      code == 2 and "has no org.json" in out and "--init" in out)
with open(os.path.join(empty, "org.json"), "w", encoding="utf-8") as f:
    f.write(build.layer_text(ORG))
code, out = cli("--config", empty, "--check")
check("no machine layer for this machine: names it and the way out",
      code == 2 and "no machine layer for this machine" in out and "--local FILE" in out)

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
