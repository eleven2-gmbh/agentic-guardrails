#!/usr/bin/env python3
"""Builds policy.json and managed-settings.json from three layers (docs/design-notes.md, 8).

    baseline.json              the product's rules, the same on every machine
    <config>/org.json          facts about the organisation
    <config>/local.<host>.json facts about this machine (short host name)

<config> is the folder given with --config DIR, else config/ in this checkout. Keep it
outside the product repository (it holds your organisation's facts); the generated
policy.json and managed-settings.json are written next to the layers in that folder.

Run after every change to one of them (./build.py --help lists every command):

    ./build.py [--config DIR]  writes policy.json and managed-settings.json
    ./build.py --check         only reports whether both are up to date (for tests/CI)
    ./build.py --diff          shows what would change in both
    ./build.py --audit         lists Claude Code's own settings below managed (design notes, 9);
                               read only, run it in your own terminal
    ./build.py --selftest      checks the read boundary (design notes, 12): in your terminal it
                               lays out canary files, run by Claude Code it tries to reach them
    ./build.py --effective [--org F] [--local F]
                               prints the merged policy (tests use it with fixtures)
    --local F                  another machine layer than <config>/local.<host>.json
    ./build.py --describe      prints the layer rules as JSON (for an editor or a UI)
    ./build.py --schema        prints layer.schema.json, a JSON Schema of a layer for editors
                               (completion, explanations); kept in the checkout, tests check it
    ./build.py --init DIR [--template empty|example] [--host NAME]
                               creates org.json and local.<host>.json in DIR, never overwrites
    ./build.py --migrate [--write]
                               brings the layers in <config> to the current layer_format and
                               to ids and paths the baseline renamed; shows a diff, writes
                               only with --write
    ./build.py --ui [--config DIR]
                               the optional configuration UI on 127.0.0.1 (ui/, docs/config-ui.md);
                               it runs these same commands and never install.sh

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
    "working_directories.roots",
    "patch_scan.projects", "sandbox.allow_read", "sandbox.allow_write",
    "sandbox.allow_unix_sockets", "read_boundary.file_tools_extra", "mcp.allowed_servers",
}
# Lists where an extra entry means more questions or more protection.
TIGHTEN_LISTS = {
    "data_classes.secret_files.patterns", "data_classes.personal_files.patterns",
    "credentials.files", "credentials.read_deny", "credentials.env_vars",
    "always_ask.tools", "always_ask.extra_ask", "logging.log_silent_tools",
    "read_boundary.macos", "read_boundary.linux",
}
# Single values and the direction that is stricter.
TIGHTEN_VALUES = {
    "package_protection.min_release_age_days": "higher",
    "package_protection.require_sfw": "true",
    "data_classes.secret_files.ask": "true",
    "data_classes.personal_files.ask": "true",
    "claude_code.lock_lower_scopes": "true",
    "claude_code.required_minimum_version": "higher-version",
    "mcp.restrict_servers": "true",
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
# What each layer path does, for --describe and the tools on top of it. Kept next to the
# sets above, so a new path without an explanation fails tests/test_build.py.
HELP = {
    "organization.name": "Name of the organisation in the auto-mode text the classifier reads.",
    "organization.person": "The person who works on this machine; the auto-mode text names "
                           "them as the one who administers the servers.",
    "organization.description": "One line about the organisation, for the auto-mode text.",
    "organization.primary_use": "What Claude Code is mainly used for here, for the auto-mode text.",
    "organization.source_control": "Where the code lives (e.g. a GitHub organisation), one per "
                                   "line, for the auto-mode text.",
    "organization.remote_targets": "What the ssh servers are (e.g. web servers, customer portal); "
                                   "the auto-mode text treats them all as production.",
    "ssh.search_domain": "Domain that short host names in ssh hosts belong to: web01 means "
                         "web01.<search domain>.",
    "install.launchagent_label": "Name of the LaunchAgent that runs the ssh-agent with a fixed "
                                 "socket. To change it later, run uninstall.sh first.",
    "patch_scan.root": "Folder the projects in patch scan projects are relative to; /patch-check "
                       "and the --audit search start here.",
    "logging.enabled": "Whether the hook writes its decision log.",
    "logging.path": "File of the hook's decision log (read with scripts/guard-log.py).",
    "logging.max_command_chars": "Commands in the log are cut to this many characters.",
    "logging.max_bytes": "Size in bytes at which the log file is rotated.",
    "logging.keep_files": "How many rotated log files are kept.",
    "package_protection.sfw_works_in_sandbox": "Whether Socket Firewall works inside the sandbox. "
                                               "While false, a package install is handed to your "
                                               "terminal right away.",
    "domains.own": "Your own domains. network: reachable from the sandbox; webfetch: WebFetch "
                   "without a question; trusted: named as internal in the auto-mode text. "
                   "Subdomains adds *.domain.",
    "domains.package_registries": "Package registries the sandbox may reach and WebFetch may "
                                  "read without a question.",
    "domains.security_sources": "Vulnerability and package-health services (OSV, deps.dev); "
                                "sandbox network and WebFetch.",
    "domains.code_hosts": "Code hosts the sandbox may reach (git over https, archives, raw files).",
    "domains.os_packages": "Operating-system package mirrors the sandbox may reach.",
    "domains.documentation": "Documentation sites WebFetch may read without a question. Not "
                             "added to the sandbox network.",
    "webfetch.extra_hosts": "Further hosts WebFetch may read without a question, without opening "
                            "them to the sandbox network.",
    "ssh.hosts": "Your servers. The auto-mode text names them as authorized ssh targets: reading "
                 "is free, every change asks. Add new servers to known_hosts as well.",
    "working_directories.paths": "Folders Claude Code may read and write (additionalDirectories). "
                                 "git network commands run there without a question.",
    "working_directories.roots": "Folders (inside your home folder) whose git checkouts "
                                 "Claude Code may read when a session starts in one: the "
                                 "sandbox opens the start folder (\".\"). A session that "
                                 "starts elsewhere inside the read boundary gets no shell "
                                 "commands. Empty: only the working directories.",
    "patch_scan.projects": "Projects /patch-check scans for outdated packages, relative to patch "
                           "scan root. Read only by the script, not by the hook.",
    "sandbox.allow_read": "Paths inside the read boundary that commands in the sandbox may read "
                          "(package caches, single config files). A leading ~ is your home "
                          "folder, a leading @darwin_user_temp_dir (or another per-user "
                          "placeholder of read boundary macos) that folder. Never a folder "
                          "that can hold tokens.",
    "sandbox.allow_write": "Extra paths commands in the sandbox may write (e.g. package caches).",
    "sandbox.allow_unix_sockets": "Unix sockets the sandbox may connect to, e.g. the ssh-agent "
                                  "socket.",
    "data_classes.secret_files.patterns": "Regular expressions for files with credentials; reading "
                                          "a matching file (also on a server) asks first.",
    "data_classes.personal_files.patterns": "Regular expressions for files with personal data "
                                            "(access and mail logs); reading one asks first.",
    "read_boundary.macos": "Folders (macOS) where reading ends: inside them commands in the "
                           "sandbox and Read, Grep, Glob only reach the working directories "
                           "and the allow_read paths. @darwin_user_dir, @darwin_user_temp_dir "
                           "and @darwin_user_cache_dir are the per-user data, temporary and "
                           "cache folders of all apps (/private/var/folders/<id>/0, T, C).",
    "read_boundary.linux": "Folders (Linux) where reading ends, like read boundary macos. "
                           "Generated, not yet tested on Linux.",
    "read_boundary.file_tools_extra": "Further paths inside the read boundary that only Read, "
                                      "Grep and Glob may read (Claude's memory, skills, plans); "
                                      "* stands for one folder name.",
    "mcp.restrict_servers": "Allow only the MCP servers in allowed servers (allowedMcpServers); "
                            "with an empty list none starts.",
    "mcp.allowed_servers": "Names of the MCP servers that may start while restrict servers is on.",
    "credentials.files": "Files and folders the sandbox hides from every command.",
    "credentials.read_deny": "Paths the Read tool is denied (permission rules Read(...)).",
    "credentials.env_vars": "Environment variables the sandbox removes from every command.",
    "always_ask.tools": "Command-line tools that always ask and run outside the sandbox, because "
                        "they need the keychain or a local socket.",
    "always_ask.extra_ask": "Further permission rules that always ask, e.g. Read(**/.env) or "
                            "Bash(gh gist *).",
    "logging.log_silent_tools": "Calls that are logged even when the hook lets them through "
                                "silently (ssh, git-network).",
    "package_protection.min_release_age_days": "Release-age window for packages in days: npm, "
                                               "pip, uv and Composer install no release younger "
                                               "than this (in Claude Code and, via install.sh, in "
                                               "your terminal).",
    "package_protection.require_sfw": "Package installs only run through Socket Firewall (sfw).",
    "data_classes.secret_files.ask": "Whether reading a file that matches the secret patterns asks.",
    "data_classes.personal_files.ask": "Whether reading a file that matches the personal-data "
                                       "patterns asks.",
    "claude_code.lock_lower_scopes": "Managed settings become the only source of permission rules "
                                     "and sandbox read paths; rules from ~/.claude and projects stop "
                                     "applying (check with --audit).",
    "claude_code.required_minimum_version": "Oldest Claude Code version allowed to start; it must "
                                            "know every setting this product writes.",
}
# "$schema" only points an editor at layer.schema.json (--schema); the build ignores it.
LAYER_KEYS = {"$schema", "note", "layer_format", "requires_baseline", "set", "add", "tighten",
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
DOMAIN_RE = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
HOST_RE = r"^[A-Za-z0-9][A-Za-z0-9.-]*$"


def check_entry(where, path, e):
    """The shape of one list entry. This is the schema: build.py checks it itself, so the
    standard library is enough (no JSON-Schema package)."""
    def bad(msg):
        raise LayerError("{}: {}: {} ({!r})".format(where, path, msg, e))
    if path == "domains.own":
        if not isinstance(e, dict) or not isinstance(e.get("domain"), str) or not e["domain"]:
            bad("needs domain")
        if not re.match(DOMAIN_RE, e["domain"]):
            bad("domain is not a domain name")
        purp = e.get("purposes")
        if not isinstance(purp, list) or not purp or not set(purp) <= PURPOSES:
            bad("purposes must be a selection of {}".format(", ".join(sorted(PURPOSES))))
        if not isinstance(e.get("wildcard", False), bool):
            bad("wildcard must be true or false")
    elif path == "ssh.hosts":
        if not isinstance(e, dict) or not isinstance(e.get("host"), str) or \
                not re.match(HOST_RE, e.get("host") or ""):
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
    release_age_env(policy)
    out = {"note": [GENERATED], "version": 1}
    out.update(policy)
    return out


# The package managers' own settings for the release-age window (design notes, 6), all
# from package_protection.min_release_age_days, so a stricter window reaches every one.
RELEASE_AGE_ENV = {"npm_config_min_release_age": "{}", "PIP_UPLOADED_PRIOR_TO": "P{}D",
                   "UV_EXCLUDE_NEWER": "P{}D", "COMPOSER_POLICY_COOLDOWN_PERIOD": "{} days"}


def release_age_env(policy):
    pp = policy["package_protection"]
    days = pp["min_release_age_days"]
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise LayerError("package_protection.min_release_age_days: {!r} is not a whole number "
                         "of days".format(days))
    for key, fmt in RELEASE_AGE_ENV.items():
        pp["env"][key] = fmt.format(days)


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


# The per-user folders of all apps under /private/var/folders/<id>/ (getconf DARWIN_USER_*):
# 0 holds the apps' and services' data, T their temporary files, C their caches.
# hooks/guard.py carries the same table.
DARWIN_USER_DIRS = {
    "@darwin_user_dir": 65536,        # _CS_DARWIN_USER_DIR, .../0
    "@darwin_user_temp_dir": 65537,   # _CS_DARWIN_USER_TEMP_DIR, .../T
    "@darwin_user_cache_dir": 65538,  # _CS_DARWIN_USER_CACHE_DIR, .../C
}


def darwin_user_dir(name):
    """The per-user folder behind a placeholder for the building user, None when unknown."""
    try:
        d = os.confstr(DARWIN_USER_DIRS[name])
    except (ValueError, OSError):
        d = None
    return os.path.realpath(d) if d else None


def allow_read(p, system=None):
    """sandbox.allow_read with a leading per-user placeholder expanded
    (@darwin_user_temp_dir/xcrun_db); such an entry is dropped off macOS.
    hooks/guard.py resolves the same list the same way."""
    system = system or sys.platform
    out = []
    for entry in p["sandbox"]["allow_read"]:
        if entry.startswith("@"):
            name, _, rest = entry.partition("/")
            if name not in DARWIN_USER_DIRS:
                raise LayerError("sandbox.allow_read: unknown placeholder {}".format(name))
            if system != "darwin":
                continue
            d = darwin_user_dir(name)
            if not d:
                continue
            entry = os.path.join(d, rest) if rest else d
        out.append(entry)
    return out


def read_boundary(p, system=None):
    """The roots where reading ends on this system (design notes, 12), expanded.
    hooks/guard.py resolves the same list the same way."""
    system = system or sys.platform
    rb = p["read_boundary"]
    out = []
    for entry in rb["macos"] if system == "darwin" else rb["linux"]:
        if entry in DARWIN_USER_DIRS:
            entry = darwin_user_dir(entry) if system == "darwin" else None
        elif entry.startswith("@"):
            raise LayerError("read_boundary: unknown placeholder {}".format(entry))
        if entry:
            out.append(os.path.expanduser(entry))
    return dedup(out)


def start_roots(p):
    """working_directories.roots, expanded. Each must lie strictly inside the home
    folder: a root at ~ or above would let a checkout of the home folder itself (dotfiles)
    open the credentials next to it (design notes, 12)."""
    home = os.path.realpath(os.path.expanduser("~"))
    out = []
    for r in p["working_directories"].get("roots") or []:
        d = os.path.realpath(os.path.expanduser(r))
        if not d.startswith(home.rstrip("/") + "/"):
            raise LayerError("working_directories.roots: {} must lie inside the home "
                             "folder, below it".format(r))
        out.append(d)
    return out


def build(p, system=None):
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
            # reading ends at the sandbox's denyRead and, for Read/Grep/Glob, in the hook
            # (design notes, 12); the static proof of blockReadsOutsideWorkingDirectories
            # asked for nearly every shell command
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
                           "|NotebookEdit|Read|Grep|Glob|NotebookRead|LS",
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
                "denyRead": read_boundary(p, system),
                # "." is the folder the session started in; only with start roots,
                # whose rule the hook enforces (design notes, 12)
                "allowRead": dedup([os.path.expanduser(d)
                                    for d in p["working_directories"]["paths"]]
                                   + allow_read(p, system)
                                   + (["."] if start_roots(p) else [])),
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
    if p["mcp"]["restrict_servers"]:
        out["allowedMcpServers"] = [{"serverName": n} for n in p["mcp"]["allowed_servers"]]
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
    mcp_audit(p)
    return 0


def mcp_servers(p):
    """{server name: [where it is configured]} from ~/.claude.json and .mcp.json files."""
    found = {}

    def add(names, where):
        for n in names or {}:
            found.setdefault(n, []).append(where)
    user = os.path.expanduser("~/.claude.json")
    try:
        with open(user, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    add(cfg.get("mcpServers"), "~/.claude.json")
    for proj, pc in (cfg.get("projects") or {}).items():
        if isinstance(pc, dict):
            add(pc.get("mcpServers"), "~/.claude.json, project " + proj)
    for root in p["working_directories"]["paths"] + [os.getcwd()]:
        path = os.path.join(os.path.expanduser(root), ".mcp.json")
        try:
            with open(path, encoding="utf-8") as f:
                add((json.load(f) or {}).get("mcpServers"), path)
        except (OSError, ValueError):
            pass
    return found


def mcp_audit(p):
    m = p["mcp"]
    allowed = set(m["allowed_servers"])
    print("\nMCP servers (mcp.restrict_servers is {}):".format(
        "on" if m["restrict_servers"] else "off"))
    servers = mcp_servers(p)
    for name in sorted(servers):
        state = "in allowed_servers" if name in allowed else "NOT in allowed_servers"
        print("   {}   [{}]   {}".format(name, state, "; ".join(servers[name])))
    if not servers:
        print("   none configured in ~/.claude.json or .mcp.json (claude.ai connectors and "
              "the IDE server are not listed there)")


# --------------------------------------------------------------- selftest --
# The read boundary (design notes, 12) depends on how Claude Code turns denyRead and
# allowRead into a Seatbelt profile, and that changed between versions. --selftest checks
# it after every update. In the user's terminal it lays out canary files (random text, no
# secret) in places the boundary must hide; run by Claude Code inside the sandbox it tries
# to reach them and the places that must stay readable.

CANARY = ".agentic-guardrails-canary"


def canary_dirs(p):
    """Folders inside the read boundary that are neither working directories nor allowed."""
    home = os.path.expanduser("~")
    dirs = [os.path.join(home, x) for x in ("Downloads", "Documents", "Library", ".config",
                                            ".claude")]
    if sys.platform == "darwin":
        dirs += [darwin_user_dir(x) for x in p["read_boundary"]["macos"]
                 if x in DARWIN_USER_DIRS]
    return [d for d in dirs if d and os.path.isdir(d)]


def in_sandbox():
    """True when writing to the home folder is refused, as the sandbox does."""
    probe = os.path.join(os.path.expanduser("~"), ".agentic-guardrails-probe")
    try:
        with open(probe, "w"):
            pass
    except PermissionError:
        return True
    os.unlink(probe)
    return False


def aliases(path):
    """The same file under other names: upper case (APFS ignores case), the data-volume
    firmlink, a .. detour."""
    out = [("path", path)]
    if sys.platform == "darwin":
        out.append(("other case", path.upper() if path != path.upper() else path.lower()))
        out.append(("firmlink", "/System/Volumes/Data" + path))
    d, b = os.path.split(path)
    out.append((".. detour", os.path.join(d, "..", os.path.basename(d), b)))
    return out


def selftest(p):
    if not in_sandbox():
        made = 0
        for d in canary_dirs(p):
            f = os.path.join(d, CANARY)
            if not os.path.exists(f):
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write("agentic-guardrails canary {}, no secret\n".format(
                        os.urandom(8).hex()))
                made += 1
            print("canary  " + f)
        print("\n{} new canary files. This terminal is outside the sandbox, so nothing was "
              "tested.\nNow let Claude Code run the same command (it runs in the sandbox), and "
              "ask it to open one canary\nwith the Read tool: the hook must refuse it.".format(made))
        return 0
    fails = []

    def result(label, ok, detail=""):
        print("{}  {}{}".format("ok  " if ok else "FAIL", label, "  " + detail if detail else ""))
        if not ok:
            fails.append(label)

    def readable(path):
        try:
            if os.path.isdir(path):
                os.listdir(path)
            else:
                with open(path, "rb") as fh:
                    fh.read(1)
            return True, ""
        except OSError as e:
            return False, e.strerror or type(e).__name__

    # the managed settings that apply
    try:
        with open(os.path.join(SYS_DIR, "managed-settings.json"), encoding="utf-8") as f:
            ms = json.load(f)
    except (OSError, ValueError) as e:
        ms = {}
        result("managed settings readable", False, str(e))
    deny = ((ms.get("sandbox") or {}).get("filesystem") or {}).get("denyRead") or []
    want = read_boundary(p)
    result("managed settings carry the read boundary", set(want) <= set(deny),
           "missing: " + ", ".join(sorted(set(want) - set(deny))) if set(want) - set(deny)
           else "")
    result("blockReadsOutsideWorkingDirectories is gone",
           "blockReadsOutsideWorkingDirectories" not in (ms.get("permissions") or {}))

    # must be hidden
    # The boundary refuses even lstat (EPERM, tested 2026-11-25), so os.path.lexists says
    # False for a hidden canary. Only ENOENT means it is missing.
    canaries = [os.path.join(d, CANARY) for d in canary_dirs(p)]
    present, missing = [], []
    for c in canaries:
        try:
            os.lstat(c)
            present.append(c)
        except FileNotFoundError:
            missing.append(c)
        except OSError:
            present.append(c)
    for c in missing:
        result("canary file present: " + c, False,
               "run ./build.py --selftest in your terminal first")
    if not canaries:
        result("canary files present", False, "no hidden folder found to test")
    for c in present:
        for kind, alias in aliases(c):
            ok, why = readable(alias)
            result("hidden ({}): {}".format(kind, alias), not ok, why)
        link = os.path.join(os.environ.get("TMPDIR") or "/tmp", "agr-selftest-link")
        try:
            if os.path.lexists(link):
                os.unlink(link)
            os.symlink(c, link)
            ok, why = readable(link)
            result("hidden (symlink in $TMPDIR): " + c, not ok, why)
        finally:
            if os.path.lexists(link):
                os.unlink(link)
        here = os.getcwd()
        try:
            os.chdir(os.path.dirname(c))
            ok, why = readable(CANARY)
        except OSError as e:
            ok, why = False, e.strerror
        finally:
            os.chdir(here)
        result("hidden (relative after cd): " + c, not ok, why)
    for d in ("/Volumes", os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")):
        if os.path.isdir(d):
            ok, why = readable(d)
            result("hidden (listing): " + d, not ok, why)

    # must stay readable
    for d in p["working_directories"]["paths"]:
        d = os.path.expanduser(d)
        if os.path.isdir(d):
            ok, why = readable(d)
            result("readable (working directory): " + d, ok, why)
    for d in allow_read(p):
        d = os.path.expanduser(d)
        if os.path.exists(d):
            ok, why = readable(d)
            result("readable (allow_read): " + d, ok, why)
    # "." opens the start folder; run from a checkout below a root that is not a working
    # directory, this shows that Claude Code still resolves it that way (design notes, 12)
    here = os.path.realpath(os.getcwd())
    if "." in (((ms.get("sandbox") or {}).get("filesystem") or {}).get("allowRead") or []) \
            and any(here.startswith(r + "/") for r in start_roots(p)):
        ok, why = readable(here)
        result("readable (start folder, \".\"): " + here, ok, why)
    tmp = os.environ.get("TMPDIR") or ""
    if tmp:
        f = os.path.join(tmp, "agr-selftest.txt")
        try:
            with open(f, "w") as fh:
                fh.write("x")
            with open(f) as fh:
                ok = fh.read() == "x"
            os.unlink(f)
            result("write and read in $TMPDIR", ok)
        except OSError as e:
            result("write and read in $TMPDIR", False, e.strerror)
    import subprocess
    # /usr/bin/python3 and /usr/bin/git are Xcode shims: without their cache in T
    # (xcrun_db) every call starts xcodebuild and reports EPERM
    shim = [["/usr/bin/python3", "-c", "pass"]] if sys.platform == "darwin" else []
    for cmd in shim + [["git", "config", "--global", "--get", "core.excludesfile"],
                       ["git", "log", "-1", "--format=%h"], ["npm", "config", "get", "registry"]]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            print("skip  {}  ({})".format(" ".join(cmd), type(e).__name__))
            continue
        blocked = "Operation not permitted" in r.stderr or "EPERM" in r.stderr
        result("runs: " + " ".join(cmd), not blocked, r.stderr.strip()[:120] if blocked else "")
    print("\n{} failures. Known limits (design notes, 12): stat on a hidden folder still "
          "answers, a hidden file\nshows that it exists (EPERM, not ENOENT), and the "
          "scratchpads of other sessions under\n/private/tmp/claude-<uid> stay "
          "readable.".format(len(fails)))
    return 1 if fails else 0


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
        "set": {p: {"type": json_type(get_path(policy, p)), "baseline": get_path(policy, p),
                    "help": HELP[p]} for p in sorted(SETTABLE)},
        "add": {p: {"entry": entry_kind(p), "baseline": get_path(policy, p), "help": HELP[p]}
                for p in sorted(ADD_LISTS)},
        "tighten": dict(
            [(p, {"entry": entry_kind(p), "baseline": get_path(policy, p), "help": HELP[p]})
             for p in sorted(TIGHTEN_LISTS)]
            + [(p, {"type": json_type(get_path(policy, p)), "direction": d,
                    "baseline": get_path(policy, p), "help": HELP[p]})
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


SCHEMA_FILE = os.path.join(HERE, "layer.schema.json")
# The schema of a released version, for "$schema" in a layer: independent of where the
# configuration folder lies, and pinned to the same tag as product-version.
SCHEMA_URL = ("https://raw.githubusercontent.com/eleven2-gmbh/agentic-guardrails/{}/"
              "layer.schema.json")


def checkout_tag():
    """The release tag (v1.2.3) this checkout is exactly at, else None."""
    import subprocess
    try:
        r = subprocess.run(["git", "-C", HERE, "tag", "--points-at", "HEAD"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    tags = [t for t in r.stdout.split() if re.match(r"^v\d+\.\d+\.\d+$", t)]
    return sorted(tags, key=lambda t: version_tuple(t[1:]))[-1] if tags else None


def schema_ref(folder):
    """What --init writes as "$schema": the release URL when this checkout is at a tag,
    else the path to layer.schema.json relative to the folder."""
    tag = checkout_tag()
    if tag:
        return SCHEMA_URL.format(tag)
    return os.path.relpath(os.path.realpath(SCHEMA_FILE), os.path.realpath(folder))


def schema():
    """A JSON Schema of a layer, for editors: completion of every path, its explanation on
    hover, unknown keys flagged while typing. Generated from describe(); build.py remains
    the check (the schema cannot express everything, e.g. duplicate ids or locked entries).
    """
    d = describe()

    def value_schema(t):
        return {"boolean": {"type": "boolean"}, "integer": {"type": "integer"},
                "number": {"type": "number"},
                "list of text": {"type": "array", "items": {"type": "string"}}}.get(
                    t, {"type": "string"})

    entry = {
        "domain": {"type": "object", "required": ["domain", "purposes"], "properties": {
            "domain": {"type": "string", "pattern": DOMAIN_RE},
            "purposes": {"type": "array", "minItems": 1, "uniqueItems": True,
                         "items": {"enum": sorted(PURPOSES)}},
            "wildcard": {"type": "boolean", "description": "also *.<domain>"}}},
        "host": {"type": "object", "required": ["host"], "properties": {
            "host": {"type": "string", "pattern": HOST_RE},
            "role": {"type": "string"}, "note": {"type": "string"}}},
        "pattern": {"anyOf": [{"type": "string"}, {
            "type": "object", "required": ["id", "pattern"], "properties": {
                "id": {"type": "string"},
                "pattern": {"type": "string", "description": "a regular expression"}}}]},
        "text": {"type": "string", "minLength": 1},
    }

    def described(info, extra=""):
        return "{}{}\nBaseline: {}".format(info["help"], extra, json.dumps(
            info["baseline"], ensure_ascii=False))

    def list_prop(info):
        return {"type": "array", "items": entry[info["entry"]], "description": described(info)}

    def value_prop(info):
        out = dict(value_schema(info["type"]), description=described(info))
        if "direction" in info:
            out["description"] = described(info, " Stricter only: {}.".format(
                {"higher": "a higher number", "true": "true",
                 "higher-version": "a higher version"}[info["direction"]]))
            if info["direction"] == "higher":
                out["minimum"] = info["baseline"]
            elif info["direction"] == "true" and info["baseline"] is True:
                out["const"] = True
        return out

    def section(props, text):
        return {"type": "object", "additionalProperties": False, "description": text,
                "properties": props}

    ex_ids = d["exceptions"]["off"] + d["exceptions"]["set"]
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$comment": "Generated by build.py --schema from build.py and baseline.json {}. "
                    "Do not edit; build.py remains the check.".format(d["baseline_version"]),
        "title": "agentic-guardrails layer (org.json, local.<host>.json)",
        "type": "object",
        "additionalProperties": False,
        "required": ["requires_baseline"],
        "properties": {
            "$schema": {"type": "string", "description": "Path to this schema, for the editor."},
            "note": {"type": ["string", "array"], "items": {"type": "string"},
                     "description": "Free text for people; build.py ignores it."},
            "layer_format": {"type": "integer", "minimum": 1, "maximum": d["layer_format"],
                             "description": "Shape of this file; 1 when missing. "
                                            "./build.py --migrate updates it."},
            "requires_baseline": {"type": "string", "default": d["requires_baseline"],
                                  "examples": [d["requires_baseline"]],
                                  "description": "Baseline versions this layer was written for, "
                                                 "e.g. >=1.0 <2."},
            "set": section({p: value_prop(i) for p, i in d["set"].items()},
                           "Values without a security direction. Only what differs from the "
                           "baseline belongs here."),
            "add": section({p: list_prop(i) for p, i in d["add"].items()},
                           "Facts added to the baseline's lists."),
            "tighten": section({p: list_prop(i) if "entry" in i else value_prop(i)
                                for p, i in d["tighten"].items()},
                               "Stricter only: extra entries, values in their stricter direction."),
            "exceptions": {
                "type": "array", "description": "Each with an id, a reason and an expiry date.",
                "items": {"type": "object", "required": ["id", "action", "reason", "expires"],
                          "properties": {
                              "id": {"type": "string", "examples": ex_ids,
                                     "description": "off: an entry id; set: a tighten value; "
                                                    "shadow: a rule id of hooks/guard.py. "
                                                    "Locked ids are refused."},
                              "action": {"enum": d["exceptions"]["actions"]},
                              "reason": {"type": "string", "minLength": 1},
                              "expires": {"type": "string",
                                          "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                                          "description": "YYYY-MM-DD; an expired exception "
                                                         "stops the build."},
                              "value": {"description": "the new value, only for action set"}}}},
        },
    }


def schema_text():
    return json.dumps(schema(), indent=2, ensure_ascii=False) + "\n"


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
    first = {"$schema": schema_ref(folder)}
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
    org, local = (dict(first, **{k: v for k, v in l.items() if k != "$schema"})
                  for l in (org, local))
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
        raise LayerError("--config: {} is not a folder.\n"
                         "  Create one:  ./build.py --init {}".format(folder, folder))
    CONFIG = folder
    POLICY = os.path.join(folder, "policy.json")
    TARGET = os.path.join(folder, "managed-settings.json")


EPILOG = """\
examples:
  ./build.py --init ~/my-guardrails             create a configuration folder
  ./build.py --config ~/my-guardrails --diff    what would change
  ./build.py --config ~/my-guardrails           write policy.json and managed-settings.json
  ./build.py --config ~/my-guardrails --ui      the optional configuration UI
  ./install.sh --config ~/my-guardrails         install (asks for sudo)

exit codes: 0 done or up to date, 1 --check, --diff or --migrate found changes, 2 error.
Must run on /usr/bin/python3 (3.9), standard library only. More: README.md, Configure."""


def parser():
    import argparse
    ap = argparse.ArgumentParser(
        prog="./build.py", allow_abbrev=False, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Builds policy.json and managed-settings.json from baseline.json and the "
                    "layers org.json and\nlocal.<host>.json of a configuration folder. Without "
                    "a command it writes both into that folder.")
    ap.add_argument("--version", action="store_true", help="show the product version and exit")
    ap.add_argument("--config", metavar="DIR",
                    help="configuration folder (default: config/ in this checkout)")
    cmds = ap.add_argument_group("commands (at most one; without one: build)")
    one = cmds.add_mutually_exclusive_group()
    one.add_argument("--check", action="store_true",
                     help="only report whether both files are up to date (for tests and CI)")
    one.add_argument("--diff", action="store_true", help="show what would change in both files")
    one.add_argument("--effective", action="store_true", help="print the merged policy")
    one.add_argument("--audit", action="store_true",
                     help="list Claude Code's own settings below managed; read only, run it in "
                          "your own terminal")
    one.add_argument("--describe", action="store_true",
                     help="print the layer rules as JSON (for an editor or a UI)")
    one.add_argument("--schema", action="store_true",
                     help="print layer.schema.json, a JSON Schema of a layer for editors")
    one.add_argument("--init", metavar="DIR",
                     help="create org.json and local.<host>.json in DIR; never overwrites")
    one.add_argument("--migrate", action="store_true",
                     help="bring the layers to the current layer_format and renamed ids; shows "
                          "a diff, writes only with --write")
    one.add_argument("--selftest", action="store_true",
                     help="check the read boundary: in your terminal lay out canary files, "
                          "run by Claude Code (sandbox) try to reach them (design notes, 12)")
    one.add_argument("--ui", action="store_true",
                     help="start the optional configuration UI on 127.0.0.1 (docs/config-ui.md)")
    opts = ap.add_argument_group("options")
    opts.add_argument("--org", metavar="FILE", help="another organisation layer (tests)")
    opts.add_argument("--local", metavar="FILE",
                      help="another machine layer than <config>/local.<host>.json")
    opts.add_argument("--write", action="store_true", help="with --migrate: write the result")
    opts.add_argument("--template", choices=TEMPLATES, help="with --init: empty (default) or "
                                                            "example (a copy of examples/)")
    opts.add_argument("--host", metavar="NAME",
                      help="with --init: short host name (default: this machine)")
    return ap


def product_version():
    tag = checkout_tag()
    if tag:
        return tag
    import subprocess
    try:
        r = subprocess.run(["git", "-C", HERE, "describe", "--tags", "--always", "--dirty"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           universal_newlines=True, timeout=10)
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def need_folder():
    """The configuration folder exists, else say how to get one."""
    if os.path.isdir(CONFIG):
        return
    raise LayerError(
        "no configuration folder: {}/ does not exist.\n"
        "  Use your own folder:  ./build.py --config DIR\n"
        "  or create one:        ./build.py --init DIR\n"
        "  All commands:         ./build.py --help".format(shown(CONFIG)))


def need_layers(org, local):
    """The layers the build will read exist, else say what to do."""
    if org is None:
        need_folder()
        if not os.path.exists(os.path.join(CONFIG, "org.json")):
            raise LayerError(
                "{} has no org.json.\n"
                "  Create the layers:  ./build.py --init {}".format(shown(CONFIG), shown(CONFIG)))
    if local is None and not os.path.exists(host_layer()):
        others = [os.path.basename(f) for f in layer_files() if not f.endswith("org.json")]
        raise LayerError(
            "no machine layer for this machine ({}): {} missing.\n"
            "  Copy {} and edit it, or create it in ./build.py --ui,\n"
            "  or name another one:  --local FILE".format(
                socket.gethostname().split(".")[0], shown(host_layer()),
                ", ".join(others) if others else "examples/local.example.json"))


def main(argv=None):
    ap = parser()
    a = ap.parse_args(argv)
    if a.write and not a.migrate:
        ap.error("--write only goes with --migrate")
    if (a.template or a.host) and not a.init:
        ap.error("--template and --host only go with --init")
    if (a.org or a.local) and (a.init or a.migrate or a.describe or a.schema or a.ui):
        ap.error("--org and --local only go with the build, --check, --diff, --effective "
                 "and --audit")
    if a.init and a.config:
        ap.error("--init DIR names the folder itself; leave out --config")
    if a.version:
        print("agentic-guardrails {} (baseline {}, layer format {})".format(
            product_version(), read_json(BASELINE)["baseline_version"], LAYER_FORMAT))
        return 0
    try:
        if a.ui:
            # optional, and loaded only here: the build never depends on ui/
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "guardrails_ui", os.path.join(HERE, "ui", "server.py"))
            ui = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ui)
            return ui.serve(sys.modules[__name__], a.config)
        if a.schema:
            sys.stdout.write(schema_text())
            return 0
        if a.describe:
            sys.stdout.write(json.dumps(describe(), indent=2, ensure_ascii=False) + "\n")
            return 0
        if a.init:
            for f in init(a.init, a.template or "empty", a.host):
                print("{} written".format(f))
            print("  edit them, then: ./build.py --config {}".format(a.init))
            print("  pin the product: put the tag you build with ({}) into product-version "
                  "there".format(checkout_tag() or "e.g. v1.2.3"))
            return 0
        if a.config:
            use_config(a.config)
        if a.migrate:
            need_folder()
            changed = migrate(a.write)
            return 1 if changed and not a.write else 0
        need_layers(a.org, a.local)
        p = effective(a.org, a.local)
    except LayerError as e:
        print("ERROR: " + str(e), file=sys.stderr)
        return 2
    if a.effective:
        sys.stdout.write(json.dumps(p, indent=2, ensure_ascii=False) + "\n")
        return 0
    if a.audit:
        return audit(p)
    if a.selftest:
        return selftest(p)
    outputs = [(POLICY, json.dumps(p, indent=2, ensure_ascii=False) + "\n"),
               (TARGET, json.dumps(build(p), indent=2, ensure_ascii=False) + "\n")]
    if a.check:
        stale = [os.path.basename(f) for f, new in outputs if read_text(f) != new]
        if not stale:
            print("policy.json and managed-settings.json are up to date")
            return 0
        print("{} {} from the layers: run ./build.py{}".format(
            " and ".join(stale), "differs" if len(stale) == 1 else "differ",
            " --config " + a.config if a.config else ""))
        return 1
    if a.diff:
        import difflib
        changed = False
        for f, new in outputs:
            d = list(difflib.unified_diff(read_text(f).splitlines(True), new.splitlines(True),
                                          os.path.basename(f) + " (now)",
                                          os.path.basename(f) + " (from the layers)"))
            sys.stdout.writelines(d)
            changed = changed or bool(d)
        if not changed:
            print("policy.json and managed-settings.json are up to date, nothing would change")
        return 1 if changed else 0
    for f, new in outputs:
        old = read_text(f)
        if old == new:
            print("{} unchanged".format(os.path.basename(f)))
            continue
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(new)
        print("{} written{}".format(os.path.basename(f), "" if old else " (new)"))
    print("  after changes, install them: ./install.sh{} (README: Install)".format(
        " --config " + a.config if a.config else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
