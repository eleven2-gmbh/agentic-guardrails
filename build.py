#!/usr/bin/env python3
"""Builds policy.json and managed-settings.json from three layers (docs/design-notes.md, 8).

    baseline.json              the product's rules, the same on every machine
    <config>/org.json          facts about the organisation
    <config>/local.<host>.json facts about this machine (short host name)

<config> is the folder given with --config DIR, else config/ in this checkout. Keep it
outside the product repository (it holds your organisation's facts); the generated
policy.json and managed-settings.json are written next to the layers in that folder.

Run after every change to one of them:

    ./build.py [--config DIR]  writes policy.json and managed-settings.json
    ./build.py --check         only reports whether both are up to date (for tests/CI)
    ./build.py --diff          shows what would change in both
    ./build.py --audit         lists Claude Code's own settings below managed (design notes, 9);
                               read only, run it in your own terminal
    ./build.py --effective [--org F] [--local F]
                               prints the merged policy (tests use it with fixtures)
    --local F                  another machine layer than <config>/local.<host>.json
    ./build.py --describe      prints the layer rules as JSON (for an editor or a UI)
    ./build.py --init DIR [--template empty|example] [--host NAME]
                               creates org.json and local.<host>.json in DIR, never overwrites
    ./build.py --migrate [--write]
                               brings the layers in <config> to the current layer_format and
                               to ids and paths the baseline renamed; shows a diff, writes
                               only with --write

The organisation and machine layers may only `add` facts (own domains, hosts, folders),
`set` values the baseline marks as settable, `tighten` rules, and make `exceptions` with
an id, a reason and an expiry date. Entries the baseline lists under `locked` cannot be
changed at all. Unknown keys, unknown or duplicate ids, expired exceptions and a
baseline version outside `requires_baseline` stop the build.

Why one source: the same facts used to live in three places - the sandbox network list,
the WebFetch list in the hook, and the auto-mode text for the classifier. They had
drifted apart. Now the auto-mode text is generated from the same data the hook enforces.

Must run on /usr/bin/python3 (3.9): standard library only.
"""
import copy
import datetime
import json
import re
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "baseline.json")
# Without --config the layers live in config/ and the outputs next to build.py (the
# layout before the product was split off); with --config both live in that folder.
CONFIG = os.path.join(HERE, "config")
POLICY = os.path.join(HERE, "policy.json")
TARGET = os.path.join(HERE, "managed-settings.json")
HOOK = "/usr/bin/python3 -I '/Library/Application Support/ClaudeCode/hooks/guard.py'"
GENERATED = ("GENERATED FROM baseline.json, org.json and local.<host>.json BY build.py - "
             "DO NOT EDIT BY HAND. Change those and run build.py")


class LayerError(Exception):
    pass


# --------------------------------------------------------------- layers ------
# Which keys a layer may touch, and how. Kept here and not in baseline.json on purpose:
# what counts as stricter is part of the product, like the parsers in guard.py.

# Lists of facts. Adding to them is the point of a layer (own domains, servers, folders).
ADD_LISTS = {
    "domains.own", "domains.package_registries", "domains.security_sources",
    "domains.code_hosts", "domains.os_packages", "domains.documentation",
    "webfetch.extra_hosts", "ssh.hosts", "working_directories.paths",
    "patch_scan.projects", "sandbox.allow_read", "sandbox.allow_write",
    "sandbox.allow_unix_sockets",
}
# Lists where an extra entry means more questions or more protection.
TIGHTEN_LISTS = {
    "data_classes.secret_files.patterns", "data_classes.personal_files.patterns",
    "credentials.files", "credentials.read_deny", "credentials.env_vars",
    "always_ask.tools", "always_ask.extra_ask", "logging.log_silent_tools",
}
# Single values and the direction that is stricter.
TIGHTEN_VALUES = {
    "package_protection.min_release_age_days": "higher",
    "package_protection.require_sfw": "true",
    "data_classes.secret_files.ask": "true",
    "data_classes.personal_files.ask": "true",
    "claude_code.lock_lower_scopes": "true",
    "claude_code.required_minimum_version": "higher-version",
}
# Values without a security direction: names, descriptions, paths, switches about the
# environment. sfw_works_in_sandbox describes whether sfw runs in the sandbox (design notes, 6).
SETTABLE = {
    "organization.name", "organization.person", "organization.description",
    "organization.primary_use", "organization.source_control", "organization.remote_targets",
    "ssh.search_domain", "install.launchagent_label", "patch_scan.root",
    "logging.enabled", "logging.path", "logging.max_command_chars", "logging.max_bytes",
    "logging.keep_files", "package_protection.sfw_works_in_sandbox",
}
LAYER_KEYS = {"note", "layer_format", "requires_baseline", "set", "add", "tighten",
              "exceptions"}

# The shape of a layer file (the keys above and what they mean). It changes independently
# of the baseline's content, so it has its own number. A layer without `layer_format` is
# format 1. When the format changes, FORMAT_STEPS[n] turns a format-n layer into n+1, and
# `--migrate` writes the result (design notes, 8).
LAYER_FORMAT = 1
FORMAT_STEPS = {}


def migrate_layer(layer, renamed_ids, renamed_paths, name):
    """(migrated copy, notes): the layer in the current format, with ids and paths the
    baseline renamed replaced. The same function serves the build (in memory, with a
    note) and `--migrate` (written to the file), so both always agree."""
    if not isinstance(layer, dict):
        raise LayerError("{}: a layer must be a JSON object".format(name))
    layer, notes = copy.deepcopy(layer), []
    fmt = layer.get("layer_format", 1)
    if not isinstance(fmt, int) or isinstance(fmt, bool) or fmt < 1:
        raise LayerError("{}: layer_format must be a whole number from 1".format(name))
    if fmt > LAYER_FORMAT:
        raise LayerError("{}: layer_format {} is newer than this product understands ({}). "
                         "Check out the product version the layer was written for".format(
                             name, fmt, LAYER_FORMAT))
    while fmt < LAYER_FORMAT:
        layer = FORMAT_STEPS[fmt](layer)
        notes.append("layer format {} -> {}".format(fmt, fmt + 1))
        fmt += 1
        layer["layer_format"] = fmt

    def new_path(path):
        return renamed_paths.get(path, path)

    def new_id(i):
        if i in renamed_ids:
            return renamed_ids[i]
        if i in renamed_paths:
            return renamed_paths[i]
        head, sep, tail = i.partition(":")
        if sep and head in renamed_paths:
            return renamed_paths[head] + ":" + tail
        return i

    for op in ("set", "add", "tighten"):
        section = layer.get(op)
        if not isinstance(section, dict) or not any(k in renamed_paths for k in section):
            continue
        out = {}
        for k, v in section.items():
            n = new_path(k)
            if n in out or (n != k and n in section):
                raise LayerError("{}: {} {} was renamed to {}, which the layer already has. "
                                 "Merge the two by hand".format(name, op, k, n))
            if n != k:
                notes.append("{} {} is now called {}".format(op, k, n))
            out[n] = v
        layer[op] = out
    for ex in layer.get("exceptions") or []:
        if isinstance(ex, dict) and isinstance(ex.get("id"), str):
            n = new_id(ex["id"])
            if n != ex["id"]:
                notes.append("exception id {} is now called {}".format(ex["id"], n))
                ex["id"] = n
    return layer, notes


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise LayerError("{} missing".format(shown(path)))
    except ValueError as e:
        raise LayerError("{}: not valid JSON ({})".format(shown(path), e))


def version_tuple(v):
    parts = str(v).split(".")
    if not all(x.isdigit() for x in parts):
        raise LayerError("version {!r} is not a dotted number".format(v))
    return tuple(int(x) for x in parts) + (0,) * (3 - len(parts))


def version_ok(version, spec):
    """`>=1.0 <2`: every comparator separated by blanks must hold."""
    have = version_tuple(version)
    ops = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b,
           "<": lambda a, b: a < b, "==": lambda a, b: a == b}
    for part in str(spec).split():
        m = re.match(r"^(>=|<=|>|<|==)?(\d+(?:\.\d+)*)$", part)
        if not m:
            raise LayerError("requires_baseline: {!r} not readable".format(part))
        if not ops[m.group(1) or "=="](have, version_tuple(m.group(2))):
            return False
    return True


def get_path(obj, path):
    cur = obj
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            raise LayerError("{}: does not exist in the baseline".format(path))
        cur = cur[k]
    return cur


def set_path(obj, path, value):
    keys = path.split(".")
    cur = get_path(obj, ".".join(keys[:-1])) if len(keys) > 1 else obj
    if not isinstance(cur, dict):
        raise LayerError("{}: does not exist in the baseline".format(path))
    if keys[-1] not in cur:
        raise LayerError("{}: does not exist in the baseline".format(path))
    cur[keys[-1]] = value


def entry_id(list_path, entry):
    """Stable id of a list entry: its own `id`, else `<list>:<value>` for strings, the
    domain or host for those objects."""
    if isinstance(entry, dict):
        for k in ("id", "domain", "host"):
            if entry.get(k):
                return "{}:{}".format(list_path, entry[k]) if k != "id" else entry["id"]
        raise LayerError("{}: entry without id: {!r}".format(list_path, entry))
    return "{}:{}".format(list_path, entry)


def all_lists(policy):
    return sorted(ADD_LISTS | TIGHTEN_LISTS)


def index_ids(policy):
    """id -> (list path, entry) for every entry of every list a layer can name."""
    out = {}
    for lp in all_lists(policy):
        for e in get_path(policy, lp):
            i = entry_id(lp, e)
            if i in out:
                raise LayerError("id {} appears twice".format(i))
            out[i] = (lp, e)
    return out


PURPOSES = {"network", "webfetch", "trusted"}


def check_entry(where, path, e):
    """The shape of one list entry. This is the schema: build.py checks it itself, so the
    standard library is enough (no JSON-Schema package)."""
    def bad(msg):
        raise LayerError("{}: {}: {} ({!r})".format(where, path, msg, e))
    if path == "domains.own":
        if not isinstance(e, dict) or not isinstance(e.get("domain"), str) or not e["domain"]:
            bad("needs domain")
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
                        e["domain"]):
            bad("domain is not a domain name")
        purp = e.get("purposes")
        if not isinstance(purp, list) or not purp or not set(purp) <= PURPOSES:
            bad("purposes must be a selection of {}".format(", ".join(sorted(PURPOSES))))
        if not isinstance(e.get("wildcard", False), bool):
            bad("wildcard must be true or false")
    elif path == "ssh.hosts":
        if not isinstance(e, dict) or not isinstance(e.get("host"), str) or \
                not re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*$", e.get("host") or ""):
            bad("needs host (letters, digits, dot, dash)")
        if not isinstance(e.get("role", ""), str):
            bad("role must be text")
    elif path.startswith("data_classes."):
        if isinstance(e, str):
            pat = e
        elif isinstance(e, dict) and isinstance(e.get("id"), str) and \
                isinstance(e.get("pattern"), str):
            pat = e["pattern"]
        else:
            bad("needs id and pattern")
        try:
            re.compile(pat)
        except re.error as x:
            bad("pattern is not a regular expression: {}".format(x))
    elif not isinstance(e, str) or not e.strip():
        bad("entry must be non-empty text")


def same_type(old, new):
    """bool is an int in Python; a setting must keep exactly the baseline's type."""
    return type(old) is type(new) or (type(old) in (int, float) and type(new) in (int, float)
                                      and not isinstance(new, bool))


def stricter(direction, old, new):
    if direction == "higher":
        return new >= old
    if direction == "true":
        return bool(new) or not bool(old)
    if direction == "higher-version":
        return version_tuple(new) >= version_tuple(old)
    raise AssertionError(direction)


def apply_layer(policy, layer, name, locked, today, shadow):
    """Apply one organisation or machine layer to the policy, in place."""
    unknown = set(layer) - LAYER_KEYS
    if unknown:
        raise LayerError("{}: unknown keys {}".format(name, ", ".join(sorted(unknown))))
    req = layer.get("requires_baseline")
    if not req:
        raise LayerError("{}: requires_baseline missing".format(name))
    if not version_ok(policy["baseline_version"], req):
        raise LayerError("{}: requires baseline {}, present is {}".format(
            name, req, policy["baseline_version"]))

    for path, value in (layer.get("set") or {}).items():
        if path not in SETTABLE:
            raise LayerError("{}: set {} is not allowed (only {})".format(
                name, path, ", ".join(sorted(SETTABLE))))
        old = get_path(policy, path)
        if not same_type(old, value) or (isinstance(value, list)
                                         and not all(isinstance(x, str) for x in value)):
            raise LayerError("{}: set {}: {!r} does not have the baseline's type ({})".format(
                name, path, value, type(old).__name__))
        set_path(policy, path, value)

    for op, allowed in (("add", ADD_LISTS), ("tighten", TIGHTEN_LISTS)):
        for path, entries in (layer.get(op) or {}).items():
            if op == "tighten" and path in TIGHTEN_VALUES:
                old = get_path(policy, path)
                if not same_type(old, entries):
                    raise LayerError("{}: tighten {}: {!r} does not have the baseline's type "
                                     "({})".format(name, path, entries, type(old).__name__))
                if not stricter(TIGHTEN_VALUES[path], old, entries):
                    raise LayerError("{}: tighten {}: {!r} is not stricter than {!r}".format(
                        name, path, entries, old))
                set_path(policy, path, entries)
                continue
            if path not in allowed:
                hint = " (this is a tighten list)" if path in TIGHTEN_LISTS else \
                    " (this is an add list)" if path in ADD_LISTS else ""
                raise LayerError("{}: {} {} is not allowed{}".format(name, op, path, hint))
            if not isinstance(entries, list):
                raise LayerError("{}: {} {} needs a list".format(name, op, path))
            target = get_path(policy, path)
            have = {entry_id(path, e) for e in target}
            for e in entries:
                check_entry(name, path, e)
                i = entry_id(path, e)
                if i in have:
                    raise LayerError("{}: {} {}: id {} already exists".format(name, op, path, i))
                have.add(i)
                target.append(copy.deepcopy(e))

    ids = index_ids(policy)
    for ex in layer.get("exceptions") or []:
        missing = [k for k in ("id", "action", "reason", "expires") if not ex.get(k)]
        if missing:
            raise LayerError("{}: exception without {}: {!r}".format(name, ", ".join(missing), ex))
        try:
            expires = datetime.date.fromisoformat(str(ex["expires"]))
        except ValueError:
            raise LayerError("{}: exception {}: expires {!r} is not a date (YYYY-MM-DD)".format(
                name, ex["id"], ex["expires"]))
        if expires < today:
            raise LayerError("{}: exception {} expired on {}. Extend it (with a reason) "
                             "or remove it".format(name, ex["id"], expires))
        i, action = ex["id"], ex["action"]
        if i in locked:
            raise LayerError("{}: {} is locked, no exception possible".format(name, i))
        if action == "off":
            if i not in ids:
                raise LayerError("{}: exception {}: this id does not exist".format(name, i))
            lp, e = ids.pop(i)
            get_path(policy, lp).remove(e)
        elif action == "shadow":
            shadow.append(i)  # a rule id of guard.py, see the decision log
        elif action == "set":
            if i not in TIGHTEN_VALUES:
                raise LayerError("{}: exception {}: action set only for {}".format(
                    name, i, ", ".join(sorted(TIGHTEN_VALUES))))
            if "value" not in ex:
                raise LayerError("{}: exception {}: value missing".format(name, i))
            if not same_type(get_path(policy, i), ex["value"]):
                raise LayerError("{}: exception {}: value {!r} does not have the "
                                 "baseline's type".format(name, i, ex["value"]))
            set_path(policy, i, ex["value"])
        else:
            raise LayerError("{}: exception {}: action {!r} unknown (off, shadow, set)".format(
                name, i, action))


def check_locked(policy, base_policy, locked):
    """Every locked entry is still there with its baseline value."""
    ids = index_ids(policy)
    base_ids = index_ids(base_policy)
    for i in locked:
        if i in base_ids:
            if i not in ids or ids[i][1] != base_ids[i][1]:
                raise LayerError("locked entry {} is missing or changed".format(i))
        elif get_path(policy, i) != get_path(base_policy, i):
            raise LayerError("locked value {} is changed".format(i))


def flatten_patterns(policy):
    """guard.py reads data-class patterns as plain strings."""
    for cls in ("secret_files", "personal_files"):
        dc = policy["data_classes"][cls]
        dc["patterns"] = [x["pattern"] if isinstance(x, dict) else x for x in dc["patterns"]]


def shown(path):
    """A path for messages: relative inside the checkout, in full outside it."""
    rel = os.path.relpath(path, HERE)
    return path if rel.startswith("..") else rel


def host_layer():
    return os.path.join(CONFIG, "local.{}.json".format(socket.gethostname().split(".")[0]))


def load_baseline():
    """(baseline.json, its policy with baseline_version), checked."""
    base = read_json(BASELINE)
    for k in ("baseline_version", "policy", "locked"):
        if k not in base:
            raise LayerError("baseline.json: {} missing".format(k))
    version_tuple(base["baseline_version"])
    for k in ("renamed", "renamed_paths"):
        if not isinstance(base.get(k) or {}, dict):
            raise LayerError("baseline.json: {} must map old to new".format(k))
    policy = copy.deepcopy(base["policy"])
    policy["baseline_version"] = base["baseline_version"]
    for lp in all_lists(policy):
        for e in get_path(policy, lp):
            check_entry("baseline.json", lp, e)
    index_ids(policy)
    base_ids = index_ids(policy)
    for i in base["locked"]:
        if i not in base_ids:
            get_path(policy, i)  # raises for a locked key that does not exist
    return base, policy


def renames(base):
    return base.get("renamed") or {}, base.get("renamed_paths") or {}


def effective(org_path=None, local_path=None, today=None):
    """The merged policy: baseline, then organisation, then machine."""
    base, policy = load_baseline()
    base_policy = copy.deepcopy(policy)
    locked = set(base["locked"])
    today = today or datetime.date.today()
    shadow = []
    for path in (org_path or os.path.join(CONFIG, "org.json"), local_path or host_layer()):
        layer, notes = migrate_layer(read_json(path), *renames(base), name=shown(path))
        for n in notes:
            print("Note: {}: {}. Run ./build.py --migrate to write it into the file".format(
                shown(path), n), file=sys.stderr)
        apply_layer(policy, layer, shown(path), locked, today, shadow)
    check_locked(policy, base_policy, locked)
    ids = policy["shadow_rules"]["ids"]
    policy["shadow_rules"]["ids"] = ids + [x for x in shadow if x not in ids]
    flatten_patterns(policy)
    out = {"note": [GENERATED], "version": 1}
    out.update(policy)
    return out


def load():
    with open(POLICY, encoding="utf-8") as f:
        return json.load(f)


def domain_entries(p, purpose):
    """Own domains for one purpose, wildcards expanded."""
    out = []
    for d in p["domains"]["own"]:
        if purpose not in d["purposes"]:
            continue
        out.append(d["domain"])
        if d.get("wildcard"):
            out.append("*." + d["domain"])
    return out


def network_domains(p):
    dom = p["domains"]
    out = (dom["package_registries"] + dom["security_sources"] + dom["code_hosts"]
           + dom["os_packages"])
    # a wildcard entry in the sandbox list covers the bare domain too
    for d in p["domains"]["own"]:
        if "network" in d["purposes"]:
            out.append(d["domain"])
            if d.get("wildcard"):
                out.append("*." + d["domain"])
    return dedup(out)


def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def ssh_host_list(p):
    """Host names for the auto-mode text, short names marked once."""
    short = [h["host"] for h in p["ssh"]["hosts"] if "." not in h["host"]]
    full = [h["host"] for h in p["ssh"]["hosts"] if "." in h["host"]]
    return short, full


def auto_mode_environment(p):
    """The text the auto-mode classifier reads. Generated, so it says the same as the
    hook enforces: reading is free, changes ask, and data leaving a server asks."""
    org = p["organization"]
    short, full = ssh_host_list(p)
    trusted = ", ".join("*." + d["domain"] for d in p["domains"]["own"]
                        if "trusted" in d["purposes"])
    hosts = ", ".join(short + full)
    sd = p["ssh"]["search_domain"]
    secret_note = ("Credentials (.env, keys and certificate keys, shadow, "
                   "my.cnf, debian.cnf) and personal data (access, mail and "
                   "auth logs, login records) ")
    return [
        "$defaults",
        "Organization: {} ({}), {}. Primary use: {}".format(
            org["name"], org["person"], org["description"], org["primary_use"]),
        "Source control: " + "; ".join(org["source_control"]),
        "Trusted internal domains: " + trusted,
        ("Authorized ssh targets: the user ({}) administers these servers, either as owner "
         "or on behalf of the customer, and authorizes Claude to connect to them via ssh as "
         "root: {} (short names mean <name>.{}). Read-only ssh commands on these hosts need "
         "no per-call request, also in loops over several hosts: reading state, versions and "
         "loaded modules, configuration files, logs, service status, configtest, and checking "
         "for exposed .git directories or similar. This is authorized administration of the "
         "user's own infrastructure, not unauthorized access or reconnaissance"
         ).format("{}, {}".format(org["person"], org["name"]), hosts, sd),
        ("Sensitive remote targets: every server reached via ssh is a production server: "
         + org.get("remote_targets", "the organization's production systems") +
         ". Every change on these hosts needs an explicit request from "
         "the user naming the host and the change: editing or creating files (including *.bak "
         "backup copies), reloading, restarting or stopping services, deleting data, changing "
         "firewall rules, users, keys or certificates, and package installs or upgrades"),
        ("Sensitive data locations & audiences: .env files, server config under /etc, databases "
         "and logs on customer servers contain credentials and personal data of customers and "
         "their users; they must not leave those servers or the repository. Reading them into "
         "the conversation sends them to the model provider, which counts as leaving the "
         "server: " + secret_note + "therefore need an explicit request from the user, as does "
         "any command on a server that sends data to a host other than localhost or one of the "
         "user's own. Operational data (configuration without secrets, versions, service "
         "status, error logs, journalctl, syslog) is free to read"),
    ]


def build(p):
    cred = p["credentials"]
    aa = p["always_ask"]
    tool_globs = ["Bash({} *)".format(t) for t in aa["tools"]]
    excluded = ([g for cmd in aa["git_network_outside_sandbox"]
                 for g in ((cmd, cmd + " *") if cmd in ("git push", "git pull", "git fetch")
                           else (cmd + " *",))]
                + (["gh *"] if aa.get("gh_outside_sandbox") else [])
                + ["{} *".format(t) for t in aa["tools"]])
    cc = p["claude_code"]
    lock = bool(cc["lock_lower_scopes"])
    out = {
        "note": GENERATED,
        "permissions": {
            "disableBypassPermissionsMode": "disable",
            "blockReadsOutsideWorkingDirectories": True,
            "blockWritesOutsideWorkingDirectories": True,
            # the working directories live in one place only (design notes, 9)
            "additionalDirectories": [os.path.expanduser(d)
                                      for d in p["working_directories"]["paths"]],
            "deny": ["Read({})".format(x) for x in cred["read_deny"]],
            "ask": aa["extra_ask"] + ["Bash(git push)", "Bash(git push *)"] + tool_globs,
        },
        "env": p["package_protection"]["env"],
        "enableAllProjectMcpServers": False,
        "allowManagedHooksOnly": True,
        # managed settings are the only source of permission rules (design notes, 9)
        "allowManagedPermissionRulesOnly": lock,
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": HOOK}]}],
            "PreToolUse": [{
                "matcher": "Bash|Monitor|PowerShell|BashOutput|WebFetch|Edit|Write|MultiEdit"
                           "|NotebookEdit",
                "hooks": [{"type": "command", "command": HOOK}],
            }],
        },
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "autoAllowBashIfSandboxed": True,
            "excludedCommands": dedup(excluded),
            "filesystem": {
                "allowManagedReadPathsOnly": lock,
                "allowRead": p["sandbox"]["allow_read"],
                "allowWrite": p["sandbox"]["allow_write"],
            },
            "credentials": {
                "files": [{"path": x, "mode": "deny"} for x in cred["files"]],
                "envVars": [{"name": x, "mode": "deny"} for x in cred["env_vars"]],
            },
            "network": {
                "strictAllowlist": True,
                "allowManagedDomainsOnly": True,
                "allowLocalBinding": True,
                "allowUnixSockets": [os.path.expanduser(s)
                                     for s in p["sandbox"]["allow_unix_sockets"]],
                "allowedDomains": network_domains(p),
            },
        },
        "autoMode": {"environment": auto_mode_environment(p)},
    }
    if cc.get("required_minimum_version"):
        out["requiredMinimumVersion"] = cc["required_minimum_version"]
    return out


# ------------------------------------------------------------------- audit --
# Claude Code's own settings files below managed (design notes, 9). Once managed settings
# set allowManagedPermissionRulesOnly and allowManagedReadPathsOnly, their permission
# rules, additionalDirectories and sandbox allowRead no longer apply. The audit lists
# what is there, so it can be taken over into the policy first. Read only; it must run
# in the user's terminal, because the sandbox keeps ~/.claude away from Claude.

SYS_DIR = "/Library/Application Support/ClaudeCode"
PRUNE = {"node_modules", ".git", "vendor", ".venv", "venv", "dist", "build", "Library"}
SECRETISH = re.compile(r"(?i)((?:pass(?:word)?|token|secret|key|auth\w*)[=: ]+)\S+"
                       r"|\b(?=[A-Za-z0-9_+/=-]*\d)(?=[A-Za-z0-9_+/=-]*[A-Za-z])"
                       r"[A-Za-z0-9_+/=-]{20,}\b")


def redact(s):
    return SECRETISH.sub(lambda m: (m.group(1) or "") + "«redacted»", s)


def settings_files(p):
    """~/.claude/settings.json plus every .claude/settings*.json below the project root,
    the working directories and the current directory."""
    found = [os.path.expanduser("~/.claude/settings.json"),
             os.path.expanduser("~/.claude/settings.local.json")]
    roots = [os.path.expanduser(p.get("patch_scan", {}).get("root", "~/Documents"))]
    roots += p["working_directories"]["paths"] + [os.getcwd()]
    for root in roots:
        base = root.rstrip("/").count("/")
        for d, dirs, files in os.walk(root):
            depth = d.count("/") - base
            dirs[:] = [x for x in dirs if x not in PRUNE and (x == ".claude" or
                                                               not x.startswith("."))]
            if depth > 7:
                dirs[:] = []
            if os.path.basename(d) == ".claude":
                found += [os.path.join(d, f) for f in files
                          if f in ("settings.json", "settings.local.json")]
                dirs[:] = []
    out, seen = [], set()
    for f in found:
        r = os.path.realpath(f)
        if os.path.isfile(r) and r not in seen:
            seen.add(r)
            out.append(f)
    return out


def audit(p):
    work = set(os.path.realpath(x) for x in p["working_directories"]["paths"])
    total = {"allow": 0, "ask/deny": 0, "dirs": 0, "read": 0}
    print("Audit of the Claude Code settings below managed (read only)\n")
    # Inside the sandbox ~/.claude cannot be read, and a missing file would look like an
    # empty one. Stop instead of reporting "nothing found".
    try:
        os.listdir(os.path.expanduser("~/.claude"))
    except FileNotFoundError:
        pass
    except OSError as e:
        print("~/.claude not readable ({}). Is this running in the sandbox? Run it in "
              "your own terminal.".format(e.strerror))
        return 2
    dropin = os.path.join(SYS_DIR, "managed-settings.d")
    print("managed-settings.d: " + ("PRESENT - must go, see docs/design-notes.md, 9"
                                    if os.path.exists(dropin) else "absent (correct)"))
    for path in settings_files(p):
        try:
            with open(path, encoding="utf-8") as f:
                s = json.load(f)
        except (OSError, ValueError) as e:
            print("\n== {}\n   not readable: {}".format(path, e))
            continue
        if not isinstance(s, dict):
            continue
        perm = s.get("permissions") or {}
        fs = (s.get("sandbox") or {}).get("filesystem") or {}
        lines = []
        for kind in ("allow", "ask", "deny"):
            for rule in perm.get(kind) or []:
                tag = "stops applying" if kind == "allow" else "stops applying, candidate for tighten"
                lines.append("   {:5} {}   [{}]".format(kind, redact(str(rule)), tag))
                total["allow" if kind == "allow" else "ask/deny"] += 1
        for d in perm.get("additionalDirectories") or []:
            known = os.path.realpath(os.path.expanduser(d)) in work
            lines.append("   dir   {}   [{}]".format(
                d, "in working_directories" if known else "MISSING from working_directories"))
            total["dirs"] += 1
        for d in fs.get("allowRead") or []:
            lines.append("   read  {}   [stops applying]".format(d))
            total["read"] += 1
        if perm.get("defaultMode"):
            lines.append("   defaultMode: {}".format(perm["defaultMode"]))
        if s.get("autoMode"):
            lines.append("   autoMode: {} (check whether the lock covers it)".format(
                ", ".join(sorted(s["autoMode"]))))
        if s.get("hooks"):
            lines.append("   hooks: {} (already locked: allowManagedHooksOnly)".format(
                ", ".join(sorted(s["hooks"]))))
        rest = sorted(k for k in s if k not in ("permissions", "sandbox", "autoMode",
                                                 "hooks", "$schema"))
        if (s.get("sandbox") or {}):
            rest.append("sandbox(" + ", ".join(sorted(s["sandbox"])) + ")")
        if rest:
            lines.append("   other keys: " + ", ".join(rest))
        print("\n== " + path)
        print("\n".join(lines) if lines else "   (no permissions, no folders)")
    print("\nTotal: {allow} allow rules, {ask/deny} ask/deny rules, {dirs} folders, "
          "{read} allowRead entries".format(**total))
    print("Values that look like passwords or tokens are redacted; for env and "
          "other keys only the names are shown.")
    return 0


# ------------------------------------------------- describe, init, migrate --
# What a configuration tool (the optional UI, an editor, a script) needs, so that none of
# them repeats the rules above. The product works without any of them.

def json_type(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, list):
        return "list of text"
    return "text"


def entry_kind(path):
    """The entry shapes check_entry knows."""
    if path == "domains.own":
        return "domain"   # {"domain", "purposes": [...], "wildcard": bool}
    if path == "ssh.hosts":
        return "host"     # {"host", "role", "note"}
    if path.startswith("data_classes."):
        return "pattern"  # {"id", "pattern"} with a regular expression
    return "text"


def describe():
    """The layer rules as data: what may be set, added, tightened and excepted."""
    base, policy = load_baseline()
    locked = set(base["locked"])
    ids = index_ids(policy)
    ren_ids, ren_paths = renames(base)
    return {
        "note": ["Generated by build.py --describe from build.py and baseline.json. "
                 "build.py remains the check; this only describes it."],
        "baseline_version": base["baseline_version"],
        "layer_format": LAYER_FORMAT,
        "requires_baseline": default_requires(base["baseline_version"]),
        "layer_keys": sorted(LAYER_KEYS),
        "set": {p: {"type": json_type(get_path(policy, p)), "baseline": get_path(policy, p)}
                for p in sorted(SETTABLE)},
        "add": {p: {"entry": entry_kind(p), "baseline": get_path(policy, p)}
                for p in sorted(ADD_LISTS)},
        "tighten": dict(
            [(p, {"entry": entry_kind(p), "baseline": get_path(policy, p)})
             for p in sorted(TIGHTEN_LISTS)]
            + [(p, {"type": json_type(get_path(policy, p)), "direction": d,
                    "baseline": get_path(policy, p)})
               for p, d in sorted(TIGHTEN_VALUES.items())]),
        "exceptions": {
            "actions": ["off", "set", "shadow"],
            "off": [i for i in sorted(ids) if i not in locked],
            "set": [p for p in sorted(TIGHTEN_VALUES) if p not in locked],
            "shadow": "a rule id of hooks/guard.py (see scripts/guard-log.py)",
        },
        "locked": sorted(locked),
        "purposes": sorted(PURPOSES),
        "renamed": ren_ids,
        "renamed_paths": ren_paths,
    }


def default_requires(version):
    major, minor = version_tuple(version)[:2]
    return ">={}.{} <{}".format(major, minor, major + 1)


def layer_text(layer):
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


TEMPLATES = ("empty", "example")


def init(folder, template="empty", host=None):
    """A new configuration folder with an organisation and a machine layer. Refuses to
    overwrite anything; the result is checked with effective() before it is reported."""
    if template not in TEMPLATES:
        raise LayerError("--template: {!r} unknown ({})".format(template, ", ".join(TEMPLATES)))
    folder = os.path.abspath(os.path.expanduser(folder))
    host = host or socket.gethostname().split(".")[0]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9-]*$", host):
        raise LayerError("--host: {!r} is not a short host name".format(host))
    base, _ = load_baseline()
    req = default_requires(base["baseline_version"])
    head = {"layer_format": LAYER_FORMAT, "requires_baseline": req}
    if template == "example":
        ex = os.path.join(HERE, "examples")
        org, local = (dict(read_json(os.path.join(ex, f)), **head)
                      for f in ("org.example.json", "local.example.json"))
    else:
        org = dict({"note": ["Organisation layer. set: values without a security "
                             "direction, add: facts, tighten: stricter only. See README."]},
                   **head)
        org["set"] = {"organization.name": "", "organization.person": "",
                      "organization.description": "", "organization.primary_use": "",
                      "organization.source_control": [], "organization.remote_targets": ""}
        org["add"] = {"domains.own": [], "ssh.hosts": []}
        local = dict({"note": ["Machine layer for {}. An exception needs an id, a reason "
                               "and an expiry date. See README.".format(host)]}, **head)
        local["add"] = {"working_directories.paths": []}
        local["exceptions"] = []
    files = [(os.path.join(folder, "org.json"), org),
             (os.path.join(folder, "local.{}.json".format(host)), local)]
    present = [f for f, _ in files if os.path.exists(f)]
    if present:
        raise LayerError("--init: {} already present, nothing written".format(
            ", ".join(present)))
    os.makedirs(folder, exist_ok=True)
    for f, layer in files:
        with open(f, "x", encoding="utf-8") as fh:
            fh.write(layer_text(layer))
    try:
        effective(files[0][0], files[1][0])
    except LayerError:
        for f, _ in files:
            os.remove(f)
        raise
    return [f for f, _ in files]


def layer_files():
    """org.json and every machine layer in the configuration folder."""
    names = sorted(n for n in os.listdir(CONFIG)
                   if n == "org.json" or re.match(r"^local\.[A-Za-z0-9-]+\.json$", n))
    return [os.path.join(CONFIG, n) for n in names]


def migrate(write=False):
    """Bring every layer in the configuration folder to the current format and names.
    Without write, only shows what would change. Returns the number of changed files."""
    import difflib
    base, _ = load_baseline()
    changed = 0
    for path in layer_files():
        old = read_json(path)
        new, notes = migrate_layer(old, *renames(base), name=shown(path))
        if new == old:
            print("{} is current".format(os.path.basename(path)))
            continue
        changed += 1
        print("{}:".format(os.path.basename(path)))
        for n in notes:
            print("  " + n)
        cur = read_text(path)
        sys.stdout.writelines(difflib.unified_diff(
            cur.splitlines(True), layer_text(new).splitlines(True),
            os.path.basename(path) + " (now)", os.path.basename(path) + " (migrated)"))
        if write:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(layer_text(new))
            print("  written")
    if changed and not write:
        print("Nothing written. Run with --write to write it, then ./build.py")
    elif changed:
        print("Now run ./build.py and your tests, then commit the layers together")
    return changed


def arg(name):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        raise LayerError("{} needs a path".format(name))
    return None


def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def use_config(folder):
    """Read the layers from folder and write the generated files there."""
    global CONFIG, POLICY, TARGET
    folder = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(folder):
        raise LayerError("--config: {} is not a folder".format(folder))
    CONFIG = folder
    POLICY = os.path.join(folder, "policy.json")
    TARGET = os.path.join(folder, "managed-settings.json")


def main():
    try:
        if "--describe" in sys.argv:
            sys.stdout.write(json.dumps(describe(), indent=2, ensure_ascii=False) + "\n")
            return 0
        if arg("--init"):
            for f in init(arg("--init"), arg("--template") or "empty", arg("--host")):
                print("{} written".format(f))
            print("  edit them, then: ./build.py --config {}".format(arg("--init")))
            print("  pin the product: put the tag you build with (e.g. v1.2.3) into "
                  "product-version there")
            return 0
        if arg("--config"):
            use_config(arg("--config"))
        if "--migrate" in sys.argv:
            changed = migrate("--write" in sys.argv)
            return 1 if changed and "--write" not in sys.argv else 0
        p = effective(arg("--org"), arg("--local"))
    except LayerError as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 2
    if "--effective" in sys.argv:
        sys.stdout.write(json.dumps(p, indent=2, ensure_ascii=False) + "\n")
        return 0
    if "--audit" in sys.argv:
        return audit(p)
    outputs = [(POLICY, json.dumps(p, indent=2, ensure_ascii=False) + "\n"),
               (TARGET, json.dumps(build(p), indent=2, ensure_ascii=False) + "\n")]
    if "--check" in sys.argv:
        stale = [os.path.basename(f) for f, new in outputs if read_text(f) != new]
        if not stale:
            print("policy.json and managed-settings.json are up to date")
            return 0
        print("{} {} from the layers: run ./build.py".format(" and ".join(stale),
                                                    "differs" if len(stale) == 1 else "differ"))
        return 1
    if "--diff" in sys.argv:
        import difflib
        changed = False
        for f, new in outputs:
            d = list(difflib.unified_diff(read_text(f).splitlines(True), new.splitlines(True),
                                          os.path.basename(f) + " (now)",
                                          os.path.basename(f) + " (from the layers)"))
            sys.stdout.writelines(d)
            changed = changed or bool(d)
        return 1 if changed else 0
    for f, new in outputs:
        old = read_text(f)
        if old == new:
            print("{} unchanged".format(os.path.basename(f)))
            continue
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("{} written{}".format(os.path.basename(f), "" if old else " (new)"))
    print("  after changes, install them (install.sh, README: Install)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
