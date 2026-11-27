#!/usr/bin/env python3
"""PreToolUse hook for Claude Code (installed via managed settings, root-owned).

This is a guard rail, not a security boundary: it only ever sees the text of a tool
call, so a command that hides what it does (`python3 -c "os.system(...)"`) gets past it.
The boundaries are the sandbox, the network allowlist and the root-owned managed
settings; this file catches what a cooperating Claude is about to do. See
docs/design-notes.md.

Configuration lives in policy.json, which build.py generates from baseline.json and the
organisation and machine layers (config/), together with managed-settings.json: ssh
hosts, domains, working directories, data classes, package protection, logging. Only knowledge about how programs behave stays here (which commands
read, which options start a program, how a dependency shows up in a manifest). A missing
or broken policy makes the hook ask for everything.

Checked tools: Bash, Monitor, PowerShell, BashOutput (shell commands), WebFetch,
Edit/Write/MultiEdit/NotebookEdit (files), and Read/Grep/Glob/NotebookRead/LS against the
read boundary (design notes, 12). Wrappers are stripped first (timeout, nice,
sudo, command ...), as Claude Code does before matching its own rules.

Asks the user before:
  * any `git ... push`, including variants like `git -C dir push` that
    permission rules don't match
  * git fetch/pull/clone/ls-remote/submodule (they run outside the sandbox) with
    options that run a program (--upload-pack, -u, --template, risky -c keys,
    GIT_SSH_COMMAND ...), ext::/fd:: transports, local paths as remote, hosts
    other than GitHub/GitLab/Bitbucket, clone targets outside the project/temp
    folder, `submodule foreach`. Plain `git pull` / `git fetch origin` stay silent
  * a git network command whose repository is not in a working directory, `cd`
    followed (design notes, 4): those commands run outside the sandbox and execute the
    repository's own config and hooks, and in $TMPDIR Claude may write them
  * any `gh` / `glab` command that is not plainly read-only
  * WebFetch to a host that is not on the documentation/own-domain list
  * ssh with a remote command that is not plainly read-only (allowlist of read
    commands, see REMOTE_FREE and remote_issues), ssh without a readable remote
    command (interactive, stdin, `bash -c`, variable as command), and
    scp/rsync that write to a server (fetching is free, `rsync -n` is free)
  * data leaving a server, checked separately from the read/write split, because
    "read-only" is not the same as "nothing leaves" (remote_data_issue, design notes 2):
      - a network program whose argument the shell fills in ($(…), `…`, $VAR), and
        curl/openssl pointed at a host that is neither localhost nor one of the
        user's own
      - a variable assignment before the command that is not known to be harmless
        (GIT_EXTERNAL_DIFF, LESSOPEN, LD_PRELOAD, BASH_ENV, PAGER ... run programs)
      - reading a key or credential file, or a log with personal data in it; also
        printenv, bare env/set/export, `ps` with e, `docker inspect`. Everything
        read goes to the model provider, which is how it leaves the server
  * package protection:
      - installing a package that is new (npm install <name>, pip install <name>,
        npx <not installed>, uv add, pipx, go get, cargo add, gem install ...)
      - adding dependencies in a manifest via Edit/Write (package.json,
        composer.json, requirements*.txt, pyproject.toml, ...), any edit of a
        lockfile or package-manager config, and shell edits of these files
      - overriding the protection settings (release-age window, install-script
        policy, wheel-only, registry/index) by flag or environment variable
      - approving npm install scripts, global installs

  * edits of a project's .claude/settings*.json (Edit/Write or shell) that open a
    folder outside the project, see check_settings_edit
  * every Edit/Write of Claude's user settings (~/.claude, $CLAUDE_CONFIG_DIR): the
    managed lock leaves autoMode, hooks and env there in effect

At SessionStart: warns (no block) when the project's settings open such a folder,
when managed-settings.d exists, and when the user settings carry autoMode entries.

Denies (Claude must retry correctly):
  * npm/pnpm/yarn/pip/uv installs that do not run through Socket Firewall
    (`sfw npm install`, `sfw pip install ...`)

Stays silent otherwise, so the normal permission flow and the auto-mode
classifier decide. Must run on /usr/bin/python3 (3.9): stdlib only.
On any internal error it asks instead of silently allowing.

Every decision goes to the log named in policy.json (ask, deny, and silent ssh and
git network calls), with the command shortened and secrets redacted; a rule id listed
under shadow_rules only logs instead of asking. scripts/guard-log.py evaluates it.
A log that cannot be written is ignored and never changes a decision.
"""
import difflib
import fnmatch
import json
import os
import re
import shlex
import sys
from urllib.parse import urlsplit

# ------------------------------------------------------------------- policy --
# Everything about this environment (hosts, domains, folders, data classes, package
# protection) comes from policy.json; build.py generates managed-settings.json from the
# same file. What stays in this file is knowledge about how programs behave: which
# commands only read, which options start a program, how a dependency is recognised.
# Making that configurable would let a wrong entry reopen the gaps of design notes 2.
POLICY_PATHS = (
    "/Library/Application Support/ClaudeCode/policy.json",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "policy.json"),
)

# Defaults; apply_policy() fills them in. On a missing or broken policy.json the hook
# asks for everything rather than falling back to built-in values, so a deleted or
# damaged policy cannot silently weaken the check.
REQUIRE_SFW = True
SFW_WORKS_IN_SANDBOX = False
WEBFETCH_FREE = set()
WEBFETCH_FREE_SUFFIXES = ()
POLICY = {}


def load_policy(argv=()):
    """The policy file: `--policy <path>` when given, else the installed one, else the
    one in the repository. Deliberately an argument and not an environment variable:
    the hook's command line sits in the root-owned managed settings, so Claude cannot
    point the hook at a policy of its own, while a variable it could set."""
    for i, a in enumerate(argv):
        if a == "--policy" and i + 1 < len(argv):
            with open(argv[i + 1], encoding="utf-8") as f:
                return json.load(f), argv[i + 1]
    for path in POLICY_PATHS:
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f), path
    raise IOError("policy.json not found (%s)" % ", ".join(POLICY_PATHS))


def apply_policy(p):
    """Put the values from policy.json into the module's globals."""
    global REQUIRE_SFW, SFW_WORKS_IN_SANDBOX, WEBFETCH_FREE, WEBFETCH_FREE_SUFFIXES
    global REMOTE_OWN_SUFFIXES, SECRET_FILE, PERSONAL_FILE, GIT_WORK_ROOTS, POLICY
    global READ_DENY_ROOTS, READ_ALLOW, READ_ALLOW_FILE_TOOLS, START_ROOTS
    POLICY = p
    pp = p["package_protection"]
    REQUIRE_SFW = bool(pp["require_sfw"])
    SFW_WORKS_IN_SANDBOX = bool(pp["sfw_works_in_sandbox"])

    dom = p["domains"]
    WEBFETCH_FREE = set(dom["documentation"]) | set(dom["package_registries"]) \
        | set(dom["security_sources"]) | set(p["webfetch"]["extra_hosts"])
    WEBFETCH_FREE_SUFFIXES = tuple(
        "." + d["domain"] for d in dom["own"] if "webfetch" in d["purposes"])
    # a destination on one of the user's own hosts is not an outside destination
    REMOTE_OWN_SUFFIXES = tuple(
        "." + d["domain"] for d in dom["own"]
        if {"trusted", "network"} & set(d["purposes"]))

    dc = p["data_classes"]
    SECRET_FILE = compile_patterns(dc["secret_files"])
    PERSONAL_FILE = compile_patterns(dc["personal_files"])
    GIT_WORK_ROOTS = tuple(p["working_directories"]["paths"])

    # read boundary (design notes, 12); a policy without it comes with
    # blockReadsOutsideWorkingDirectories, so there is nothing to check here
    rb = p.get("read_boundary") or {}
    roots = rb.get("macos" if sys.platform == "darwin" else "linux") or []
    READ_DENY_ROOTS = tuple(r for r in (boundary_root(x) for x in roots) if r)
    READ_ALLOW = tuple(norm_path(x) for x in
                       list(p["working_directories"]["paths"])
                       + [y for y in (allow_root(x) for x in p["sandbox"]["allow_read"]) if y])
    READ_ALLOW_FILE_TOOLS = READ_ALLOW + tuple(
        norm_path(x) for x in rb.get("file_tools_extra") or [])
    START_ROOTS = tuple(norm_path(x) for x in p["working_directories"].get("roots") or [])


def compile_patterns(entry):
    """One regex from a data-class entry, or None when the class is switched off."""
    if not entry.get("ask", True) or not entry.get("patterns"):
        return None
    return re.compile("|".join("(?:%s)" % x for x in entry["patterns"]), re.I)

# ------------------------------------------------------------ read boundary --
# Design notes 12. The sandbox ends reading for shell commands (denyRead); Read, Grep and
# Glob do not run in it, so the same boundary is checked here. Seatbelt sees through
# symlinks, other case and the data-volume firmlink (tested 2026-11-25); a string
# comparison does not, so every path is resolved and folded first.
READ_DENY_ROOTS = ()
READ_ALLOW = ()
READ_ALLOW_FILE_TOOLS = ()
FIRMLINK = "/System/Volumes/Data"
FOLD = sys.platform == "darwin"  # APFS ignores case by default


def norm_path(path, base=""):
    """Absolute, symlinks and .. resolved, firmlink removed, case folded on macOS."""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(base or os.getcwd(), p)
    p = os.path.realpath(p)
    if p == FIRMLINK or p.startswith(FIRMLINK + "/"):
        p = p[len(FIRMLINK):] or "/"
    return p.casefold() if FOLD else p


# The per-user folders of all apps under /private/var/folders/<id>/; build.py carries the
# same table.
DARWIN_USER_DIRS = {
    "@darwin_user_dir": 65536,        # _CS_DARWIN_USER_DIR, .../0
    "@darwin_user_temp_dir": 65537,   # _CS_DARWIN_USER_TEMP_DIR, .../T
    "@darwin_user_cache_dir": 65538,  # _CS_DARWIN_USER_CACHE_DIR, .../C
}


def boundary_root(entry):
    if entry in DARWIN_USER_DIRS:
        if sys.platform != "darwin":
            return None
        try:
            d = os.confstr(DARWIN_USER_DIRS[entry])
        except (ValueError, OSError):
            d = None
        if not d:
            raise ValueError("per-user folder unknown: " + entry)  # fail closed
        return norm_path(d)
    if entry.startswith("@"):
        raise ValueError("unknown placeholder " + entry)
    return norm_path(entry)


def allow_root(entry):
    """An allow_read entry; a leading per-user placeholder is expanded like build.py
    does (@darwin_user_temp_dir/xcrun_db), None off macOS. Unknown: ValueError."""
    if not entry.startswith("@"):
        return entry
    name, _, rest = entry.partition("/")
    root = boundary_root(name)
    return (os.path.join(root, rest) if rest else root) if root else None


def under(p, pattern):
    """p lies in pattern; * in a pattern stands for one folder name."""
    if "*" not in pattern and "?" not in pattern and "[" not in pattern:
        return within(p, pattern)
    pp, parts = p.split("/"), pattern.split("/")
    return len(pp) >= len(parts) and all(
        fnmatch.fnmatchcase(a, b) for a, b in zip(pp, parts))


def outside_read_boundary(path, base="", allow=None):
    """The resolved path when it lies inside a boundary root and in no allowed path."""
    p = norm_path(path, base)
    if not any(within(p, r) for r in READ_DENY_ROOTS):
        return None
    if any(under(p, a) for a in (READ_ALLOW_FILE_TOOLS if allow is None else allow)):
        return None
    return p


# The start folder (design notes, 12). With working_directories.roots, build.py puts "."
# into the sandbox's allowRead, and Claude Code resolves it to the folder the session
# started in; a later cd does not move it (measured 2026-11-27). So the start folder must
# be one the boundary may open: a git checkout strictly below a root, a working
# directory, an allow_read path, or a folder outside the boundary. Elsewhere (~,
# ~/Documents, a folder of many projects) every shell command is denied.
START_ROOTS = ()


def project_slug(path):
    """The folder name Claude Code gives a project under ~/.claude/projects."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def start_folder(data):
    """The folder the session started in, or None when unknown. CLAUDE_PROJECT_DIR is
    an environment variable that settings could change, so it counts only when it names
    the project folder of the transcript, which Claude Code chooses itself."""
    d = os.environ.get("CLAUDE_PROJECT_DIR") or ""
    t = data.get("transcript_path") or ""
    if not d or not t or not os.path.isabs(d):
        return None
    slug = os.path.basename(os.path.dirname(t))
    if slug not in (project_slug(d), project_slug(os.path.realpath(d))):
        return None
    return d


def in_checkout_below_root(path):
    """path lies in a git checkout whose top folder lies strictly below a start root."""
    p = norm_path(path)
    for r in START_ROOTS:
        if p == r or not within(p, r):
            continue
        cur = p
        while cur != r:
            if os.path.exists(os.path.join(cur, ".git")):
                return True
            cur = os.path.dirname(cur)
    return False


def start_folder_ok(path):
    """'.' resolving to path opens nothing the read boundary is meant to hide."""
    p = norm_path(path)
    if not any(within(p, r) for r in READ_DENY_ROOTS):
        return True
    if any(under(p, a) for a in READ_ALLOW):
        return True
    return in_checkout_below_root(path)


def start_folder_problem(data):
    """Why the start folder may not be opened, or None when it may (or no roots are set)."""
    if not START_ROOTS or not READ_DENY_ROOTS:
        return None
    d = start_folder(data)
    if d is None:
        return ("the folder this session started in is unknown (CLAUDE_PROJECT_DIR missing "
                "or not matching the transcript)")
    if not start_folder_ok(d):
        return (f"this session started in {d}, which is neither a git checkout below "
                "working_directories.roots nor a working directory")
    return None


def apply_start_folder(data):
    """Read and Grep may read the start folder like the sandbox does."""
    global READ_ALLOW_FILE_TOOLS
    if not START_ROOTS or not READ_DENY_ROOTS:
        return
    d = start_folder(data)
    if d and in_checkout_below_root(d):
        READ_ALLOW_FILE_TOOLS = READ_ALLOW_FILE_TOOLS + (norm_path(d),)


def check_start_folder(data):
    problem = start_folder_problem(data)
    if problem:
        deny(f"Shell commands are blocked: {problem}. The sandbox opens the start folder "
             "for reading (\".\"), so here it would open more than one project. Tell the "
             "user in words; start Claude Code in a project folder, or add the folder to "
             "working_directories (design notes, 12).", "read.start-folder")


GLOB_CHARS = re.compile(r"[*?\[{]")


def glob_base(pattern, path):
    """The folder a glob pattern starts in, and whether it climbs out after a wildcard."""
    parts = pattern.split("/")
    lit = []
    for i, c in enumerate(parts):
        if GLOB_CHARS.search(c):
            return "/".join(lit) or ("/" if pattern.startswith("/") else ""), \
                ".." in parts[i:]
        lit.append(c)
    return "/".join(lit[:-1]) or ("/" if pattern.startswith("/") else ""), False


def check_file_read(tool, inp, cwd):
    """Read, Grep, Glob, NotebookRead, LS against the read boundary."""
    if not READ_DENY_ROOTS:
        return
    base = cwd or os.getcwd()
    paths = []
    if tool in ("Read", "NotebookRead"):
        paths.append(inp.get("file_path") or inp.get("notebook_path") or "")
    elif tool in ("Grep", "LS"):
        paths.append(inp.get("path") or base)
    elif tool == "Glob":
        root = inp.get("path") or base
        pattern = inp.get("pattern") or ""
        start, climbs = glob_base(os.path.expanduser(pattern), root)
        if climbs:
            deny(f"Glob pattern {pattern} climbs out with .. after a wildcard; the read "
                 "boundary cannot be checked (design notes, 12).", "read.boundary")
        paths.append(root)
        if start:
            paths.append(os.path.join(os.path.expanduser(root), start))
    for path in paths:
        if not path:
            continue
        p = outside_read_boundary(path, base)
        if p:
            deny(f"{tool} {path}: outside the read boundary (design notes, 12), neither in a "
                 "working directory nor in sandbox.allow_read. Ask the user in words; a "
                 "folder that belongs to the work goes into working_directories.",
                 "read.boundary")
            return


PATHISH = re.compile(r"^(?:[\w.-]+=)?@?(?P<p>(?:~|/|\.\.?/)\S*)$")


def outside_command_reads(segments, here, cwd, tool):
    """A command that runs outside the sandbox (git network, gh) has no read boundary of
    its own. Ask when the same command line reads through a substitution or names a path
    behind the boundary (design notes, 12)."""
    if not READ_DENY_ROOTS:
        return
    for w in segments:
        for a in w[1:]:
            a = a.split("=", 1)[1] if a.startswith("--") and "=" in a else a
            m = PATHISH.match(a)
            if not m or "://" in a:
                continue
            p = outside_read_boundary(m.group("p"), here or cwd, READ_ALLOW)
            if p:
                ask(f"{tool} runs outside the sandbox and the command names {m.group('p')}, "
                    "behind the read boundary (design notes, 12). Please check.",
                    "read.outside-sandbox")
                return


GH_READONLY = {
    ("repo", "view"), ("repo", "list"),
    ("pr", "view"), ("pr", "list"), ("pr", "diff"), ("pr", "checks"), ("pr", "status"),
    ("issue", "view"), ("issue", "list"), ("issue", "status"),
    ("run", "view"), ("run", "list"), ("release", "view"), ("release", "list"),
    ("workflow", "list"), ("workflow", "view"), ("auth", "status"),
    ("mr", "view"), ("mr", "list"), ("mr", "diff"),  # glab
}
GH_READONLY_TOP = {"search", "status", "browse", "--version", "version", "help"}
API_WRITE_FLAGS = {"-f", "-F", "--field", "--raw-field", "--input"}

SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|&\n]|\$\(|`|\(|\)")

# Wrappers that run their argument as the command. Claude Code strips the same set
# before matching Bash rules, so a rule on the inner command must see through them too.
WRAPPERS = {"sudo", "command", "builtin", "time", "nice", "nohup", "exec", "timeout",
            "stdbuf", "setsid", "ionice"}
# Options that take a value, per wrapper: `-p` is a value option for sudo (prompt) but
# a switch for command, so one shared list would swallow the command that follows.
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "--user", "--group",
             "--close-from", "--host", "--prompt", "--other-user", "--role", "--type"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "ionice": {"-c", "-n", "--class", "--classdata"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
}

# ---------------------------------------------------------------- packages --

NPM_NEW = {"add", "install", "i", "in", "ins", "inst", "insta", "instal", "isnt",
           "isnta", "isntal", "isntall"}
NPM_LOCK = {"ci", "clean-install", "ic", "install-clean", "isntall-clean",
            "update", "up", "upgrade", "udpate", "rebuild", "rb", "dedupe", "ddp",
            "install-test", "it", "install-ci-test", "cit",
            "uninstall", "remove", "rm", "r", "un", "unlink", "prune"}
NPM_FETCH_NEW = {"exec", "x", "create", "init", "innit"}  # download a package to run it
NPM_VALUE_FLAGS = {"--prefix", "-C", "-w", "--workspace", "--omit", "--include", "--tag",
                   "--loglevel", "--cache", "--install-strategy", "--save-prefix",
                   "-p", "--package", "-c", "--call"}
NPM_OVERRIDE = {"--dangerously-allow-all-scripts", "--no-strict-allow-scripts",
                "--min-release-age", "--min-release-age-exclude", "--before",
                "--allow-git", "--registry", "--allow-scripts", "--userconfig",
                "--globalconfig"}
PIP_SUBS_INSTALL = {"install", "download", "wheel"}
PIP_VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                   "-t", "--target", "--prefix", "--root", "--platform",
                   "--python-version", "--implementation", "--abi", "-d", "--dest",
                   "--src", "--progress-bar", "--log", "--cache-dir", "--report",
                   "--config-settings", "-C", "--global-option", "--upgrade-strategy",
                   "--python", "--timeout", "--retries", "--exists-action", "--proxy",
                   "--cert", "--client-cert", "--keyring-provider", "-w", "--wheel-dir"}
PIP_OVERRIDE = {"--only-binary", "--no-binary", "--uploaded-prior-to", "-i", "--index-url",
                "--extra-index-url", "--trusted-host", "-f", "--find-links", "--isolated",
                "--no-index", "--use-deprecated", "--break-system-packages"}
UV_OVERRIDE = {"--exclude-newer", "--index-url", "--extra-index-url", "--index",
               "--default-index", "--find-links", "--no-config", "--allow-insecure-host",
               "--no-binary", "--no-build-isolation"}
PROTECTED_ENV = re.compile(r"^(npm_config_|pip_|uv_|pnpm_|yarn_|corepack_|bun_|composer_)", re.I)
# composer.json "config" keys that hold protection settings (cooldown, malware/advisory blocking)
COMPOSER_PROTECTED_CONFIG = ("allow-plugins", "policy", "audit", "secure-http")

# manifests and related files
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "bun.lock", "bun.lockb", "composer.lock", "poetry.lock", "uv.lock",
             "pdm.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock"}
PM_CONFIG = {".npmrc", ".yarnrc", ".yarnrc.yml", "pnpm-workspace.yaml", ".pnpmfile.cjs",
             "pip.conf", "pip.ini", "uv.toml", "bunfig.toml", "auth.json"}
ALWAYS_ASK = {"Pipfile", "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
              "build.gradle.kts", "setup.py", "setup.cfg", "environment.yml"}
REQ_FILE = re.compile(r"^(requirements|constraints)[\w.-]*\.(txt|in)$")
MANIFEST_RE = (r"(package\.json|composer\.json|(requirements|constraints)[\w.-]*\.(txt|in)"
               r"|pyproject\.toml|Pipfile(\.lock)?|go\.(mod|sum)|Cargo\.(toml|lock)"
               r"|Gemfile(\.lock)?|pom\.xml|build\.gradle(\.kts)?|setup\.(py|cfg)"
               r"|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml"
               r"|composer\.lock|poetry\.lock|uv\.lock|\.npmrc|\.yarnrc(\.yml)?"
               r"|pnpm-workspace\.yaml|pip\.conf)")

NPM_DEP_KEYS = ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundleDependencies", "bundledDependencies",
                "overrides", "resolutions")
COMPOSER_DEP_KEYS = ("require", "require-dev")

ASKS, DENIES = [], []
# What the call touched, for the decision log: these are logged even when silent, so a
# rule can be tuned from real sessions instead of guesses.
SEEN = set()


def caller_rule():
    """Rule id from the calling function, so every ask carries one without listing it
    at each of the ~60 call sites: check_ssh -> ssh, check_npm -> npm."""
    try:
        name = sys._getframe(2).f_code.co_name
    except Exception:
        return "?"
    return re.sub(r"^(check_|ro_)", "", name) or "?"


def ask(reason, rule_id=None):
    ASKS.append((rule_id or caller_rule(), reason))


def deny(reason, rule_id=None):
    DENIES.append((rule_id or caller_rule(), reason))


def shadowed(rule_id):
    """A rule listed under shadow_rules only logs, it does not ask."""
    return rule_id in (POLICY.get("shadow_rules", {}).get("ids") or [])


def emit(tool="", cmd=""):
    asks = [(r, m) for r, m in ASKS if not shadowed(r)]
    denies = [(r, m) for r, m in DENIES if not shadowed(r)]
    shadow = [(r, m) for r, m in ASKS + DENIES if shadowed(r)]
    if denies:
        decision, chosen = "deny", denies
    elif asks:
        decision, chosen = "ask", asks
    else:
        decision, chosen = "silent", []
    seen, rules = [], []
    for r, m in chosen:
        if m not in seen:
            seen.append(m)
        if r not in rules:
            rules.append(r)
    log_decision(tool, cmd, decision, rules, seen, shadow)
    if decision == "silent":
        return
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": " | ".join(seen),
    }}))


# --------------------------------------------------------------- decision log --
# Design notes 1. Logged are ask and deny plus silent ssh and git network calls, so the
# rules can be tuned from real sessions. Never fails the decision: a log that cannot be
# written is a diagnostics problem, not a protection layer, so an error here is ignored
# while the decision still goes out.

REDACT = re.compile(r"""(?ix)
    (password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|authorization|
     client[_-]?secret|private[_-]?key)
    (\s*[=:]\s*|\s+)
    (["']?)
    ((?:bearer|basic|token)\s+)?       # auth scheme in front of the value
    ([^\s"';|&]{3,})
""")
# mysql style: -p directly followed by the password (`-pGeheim123`). At least six
# characters, so flag bundles such as `tar -pxzf` or `ps -p123` are left alone.
REDACT_SHORT_P = re.compile(r"(?<![\w-])(-p)(?=\S{6,})\S+")
REDACT_LONG = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-f]{40,})\b")


def redact(text):
    out = REDACT.sub(
        lambda m: m.group(1) + m.group(2) + m.group(3) + (m.group(4) or "") + "<redacted>",
        text)
    out = REDACT_SHORT_P.sub(r"\1<redacted>", out)
    return REDACT_LONG.sub("<redacted>", out)


def log_decision(tool, cmd, decision, rules, reasons, shadow):
    cfg = POLICY.get("logging") or {}
    if not cfg.get("enabled"):
        return
    silent_ok = set(cfg.get("log_silent_tools") or [])
    if decision == "silent" and not (SEEN & silent_ok) and not shadow:
        return
    try:
        path = os.path.expanduser(cfg["path"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rotate(path, cfg)
        limit = int(cfg.get("max_command_chars", 300))
        short = redact(cmd)[:limit]
        rec = {
            "t": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
            "tool": tool,
            "decision": decision,
            "rules": rules,
            "touched": sorted(SEEN),
            "command": short + ("…" if len(cmd) > limit else ""),
        }
        if reasons:
            rec["reasons"] = [redact(r)[:200] for r in reasons]
        if shadow:
            rec["shadow"] = [{"rule": r, "would": redact(m)[:200]} for r, m in shadow]
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass  # logging must never change or block a decision


def rotate(path, cfg):
    try:
        if os.path.getsize(path) < int(cfg.get("max_bytes", 5 * 1024 * 1024)):
            return
    except OSError:
        return
    keep = int(cfg.get("keep_files", 3))
    for i in range(keep - 1, 0, -1):
        older, newer = "%s.%d" % (path, i + 1), "%s.%d" % (path, i)
        if os.path.exists(newer):
            os.replace(newer, older)
    os.replace(path, path + ".1")


def words(segment):
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def os_base(p):
    return p.rsplit("/", 1)[-1]


def strip_prefix(w):
    """Drop env assignments and wrappers like `env`, `sudo`, `command`, `time`.

    Returns (words, sfw_used). Assignments to package-manager variables
    (npm_config_*, PIP_*, ...) are reported, since they can relax the
    protection settings.
    """
    sfw = False
    while w:
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", w[0])
        if m:
            if PROTECTED_ENV.match(m.group(1)):
                ask(f"protection setting changed by environment variable ({m.group(1)}).")
            w = w[1:]
        elif w[0] == "env":
            w = w[1:]
            while w and w[0].startswith("-"):
                if w[0] in ("-i", "-", "-u", "--ignore-environment", "--unset") \
                        or w[0].startswith(("-u", "--unset=")):
                    ask("env -i / -u: protection settings could be removed.")
                w = w[2:] if w[0] in ("-u", "--unset", "-S", "-C", "-P") else w[1:]
        elif w[0] in WRAPPERS:
            # Skip the wrapper and its own options, so `timeout 60 git push` and
            # `nice -n 5 git push` are seen as `git push`. Claude Code strips the same
            # wrappers before matching its Bash rules.
            head = w[0]
            if head == "command" and w[1:2] in (["-v"], ["-V"]):
                return [], sfw  # looks a command up, runs nothing
            w = w[1:]
            value_flags = WRAPPER_VALUE_FLAGS.get(head, ())
            while w:
                if w[0] == "--":
                    w = w[1:]
                    break
                if w[0] in value_flags:
                    w = w[2:]
                elif w[0].startswith("-") and len(w[0]) > 1:
                    w = w[1:]
                elif head == "timeout" and re.match(r"^[\d.]+[smhd]?$", w[0]):
                    w = w[1:]  # the duration
                else:
                    break
        elif os_base(w[0]) == "sfw":
            sfw = True
            w = w[1:]
        else:
            break
    return w, sfw


# ------------------------------------------------------------------- git/gh --

# These run outside the sandbox (excludedCommands in managed-settings.json): no host list,
# no read/write boundary. Options that execute a local program, local paths as remote,
# clone targets outside the project and foreign hosts ask; plain `git pull` stays silent.
GIT_NET = {"fetch", "pull", "clone", "ls-remote", "submodule"}
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
GIT_SAFE_CONFIG = re.compile(r"^(user|color|advice|log|i18n)\.|^(init\.defaultbranch|pull\.(rebase|ff)|"
                             r"fetch\.(prune|prunetags|parallel)|core\.quotepath|"
                             r"submodule\.recurse|protocol\.version)$", re.I)
GIT_DANGER_ENV = re.compile(r"\bGIT_(SSH|SSH_COMMAND|SSH_VARIANT|PROXY_COMMAND|EXEC_PATH|"
                            r"TEMPLATE_DIR|ASKPASS|CONFIG\w*|ALLOW_PROTOCOL|"
                            r"PROTOCOL_FROM_USER|DIR|WORK_TREE)=")
GIT_NET_VALUE = {"--depth", "--deepen", "--shallow-since", "--shallow-exclude", "-j", "--jobs",
                 "--negotiation-tip", "-o", "--server-option", "--refmap", "-s", "--strategy",
                 "-X", "--strategy-option", "-b", "--branch", "--origin", "--filter",
                 "--bundle-uri", "--reference", "--reference-if-able", "--separate-git-dir",
                 "--template", "-c", "--config", "--upload-pack", "--receive-pack", "--exec"}
GIT_EXEC_FLAGS = {"--upload-pack", "--receive-pack", "--exec", "--template"}
GIT_SHORT_U = {"clone", "ls-remote"}  # -u <prog> = --upload-pack; for fetch/pull -u takes no value


def git_config_issue(kv):
    key = kv.split("=", 1)[0].strip()
    if not GIT_SAFE_CONFIG.search(key):
        ask(f"git -c {key}: setting can run commands or redirect targets, "
            "git runs outside the sandbox here. Please check.")


def in_allowed_dir(path, cwd):
    """Inside the project (cwd) or Claude's temp folders; symlinks such as /tmp resolved."""
    base = cwd or os.getcwd()
    p = os.path.realpath(os.path.join(base, os.path.expanduser(path)))
    roots = [os.path.realpath(r) for r in (cwd, os.environ.get("TMPDIR", "")) if r]
    if any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots):
        return True
    return re.match(r"^/private/tmp/claude(-\d+)?(/|$)", p) is not None


# Folders where a git network command may run without a question (from policy.json):
# the project itself and the user's other working directories. Claude's temp folders are
# deliberately not among them. The sandbox protects .git/config and .git/hooks inside a
# project, but not in $TMPDIR, while git fetch/pull run outside the sandbox
# (excludedCommands) and read the repository's own config (core.sshCommand, hooks), so a
# repo prepared in $TMPDIR could run a program on the host.
GIT_WORK_ROOTS = ()


def resolve_cwd(path, here, cwd):
    """Absolute path of a `cd` target, None when it cannot be pinned down."""
    if not path or path == "-":
        return os.path.realpath(cwd) if cwd else None
    p = os.path.expanduser(path)
    if re.search(r"[*?$`]", p):
        return None
    base = here or cwd or os.getcwd()
    return os.path.realpath(os.path.join(base, p))


def git_repo_dir_ok(path, here, cwd):
    """Is the repository a git network command works on inside a working directory?"""
    p = resolve_cwd(path, here, cwd) if path else here
    if p is None:
        return False
    roots = [os.path.realpath(r) for r in ((cwd,) + GIT_WORK_ROOTS) if r]
    return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)


def git_repo_issue(repo, sub):
    """Check the repository argument of fetch/pull/clone/ls-remote/submodule add."""
    if "::" in repo:
        ask(f"git {sub}: Transport {repo.split('::')[0]}:: runs programs. Please check.")
        return
    if repo.lower().startswith("file://") or repo in (".", "..") \
            or repo.startswith(("/", "~", "./", "../")) or ("/" in repo and ":" not in repo):
        ask(f"git {sub} from a local path ({repo}): runs outside the sandbox, also beyond "
            "the read boundary. Please check.")
        return
    if ":" not in repo:
        return  # remote name such as origin
    if "://" in repo:
        host = urlsplit(repo).hostname or ""
    else:  # scp-like [user@]host:path
        host = repo.split(":", 1)[0].rsplit("@", 1)[-1].strip("[]")
    if host.lower() not in GIT_HOSTS:
        ask(f"git {sub} from {host or repo}: host not on the list (GitHub, GitLab, Bitbucket), "
            "git runs outside the sandbox. Please check.")


def check_git(w, cwd="", here=None):
    """Returns True for subcommands that run outside the sandbox (GIT_NET).

    `here` is the folder the command runs in, after any `cd` in the same shell command;
    None means it could not be determined.
    """
    # git [global options] <subcommand>; global options may take a value
    i, gconf, gdirs = 1, [], []
    while i < len(w) and w[i].startswith("-"):
        if i + 1 < len(w):
            if w[i] == "-c":
                gconf.append(w[i + 1])
            elif w[i] in ("-C", "--git-dir", "--work-tree"):
                gdirs.append(w[i] + " " + w[i + 1])
        i += 2 if w[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    sub = w[i] if i < len(w) else ""
    if sub == "push":
        ask("git push: code leaves this machine. Please check target and branch.")
    if sub not in GIT_NET:
        return False
    for kv in gconf:
        git_config_issue(kv)
    if gdirs:
        for d in gdirs:
            if not git_repo_dir_ok(d.split(" ", 1)[1], here, cwd):
                ask(f"git {d}: repository outside the working directories. git {sub} runs outside the "
                    f"sandbox and runs settings and hooks from the repository. Please check.")
    elif not git_repo_dir_ok("", here, cwd):
        where = f"in {here}" if here else "in a folder that cannot be determined"
        ask(f"git {sub} {where}: outside the working directories. git runs there outside the "
            f"sandbox and runs settings and hooks from the repository. Please check.")
    args = w[i + 1:]
    if sub == "submodule":
        pos = positionals(args, {"-b", "--branch", "--name", "--reference", "--depth", "-j",
                                 "--jobs"})
        action = pos[0] if pos else ""
        if action == "foreach":
            ask("git submodule foreach: runs a command outside the sandbox. Please check.")
        elif action == "add" and len(pos) > 1:
            git_repo_issue(pos[1], "submodule add")
        elif action == "set-url" and len(pos) > 2:
            git_repo_issue(pos[2], "submodule set-url")
        return True
    exec_flags = GIT_EXEC_FLAGS | ({"-u"} if sub in GIT_SHORT_U else set())
    value_flags = GIT_NET_VALUE | ({"-u"} if sub in GIT_SHORT_U else set())
    for a in args:
        if flag_name(a) in exec_flags or (sub in GIT_SHORT_U and re.match(r"^-u.", a)):
            ask(f"git {sub} {flag_name(a)[:13]}: option runs a local program or "
                "hook templates outside the sandbox. Please check.")
    for kv in flag_values(args, {"-c", "--config"}):
        git_config_issue(kv)
    for ref in flag_values(args, {"--reference", "--reference-if-able", "--separate-git-dir"}):
        if not in_allowed_dir(ref, cwd):
            ask(f"git {sub}: path {ref} outside the project. Please check.")
    pos = positionals(args, value_flags)
    if pos:
        git_repo_issue(pos[0], sub)
    if sub == "clone" and len(pos) > 1 and not in_allowed_dir(pos[1], cwd):
        ask(f"git clone to {pos[1]}: target outside the project and the temp folder, "
            "git writes there outside the sandbox. Please check.")
    return True


def check_gh(w):
    tool = os_base(w[0])
    clean, skip = [], False
    for a in w[1:]:
        if skip:
            skip = False
            continue
        if a in ("-R", "--repo", "--hostname"):
            skip = True
            continue
        clean.append(a)
    if not clean:
        return
    top = clean[0]
    if top in GH_READONLY_TOP:
        return
    if top == "api":
        method = "GET"
        for j, a in enumerate(clean):
            if a in ("-X", "--method") and j + 1 < len(clean):
                method = clean[j + 1].upper()
            elif a.startswith("--method="):
                method = a.split("=", 1)[1].upper()
            elif a.startswith("-X") and len(a) > 2:
                method = a[2:].upper()
        writes = any(a in API_WRITE_FLAGS or a.startswith(("--field=", "--raw-field=", "--input="))
                     for a in clean)
        graphql_mutation = "graphql" in clean and any("mutation" in a for a in clean)
        if not (method == "GET" and not writes and not graphql_mutation):
            ask(f"{tool} api writes ({method}): please check.")
        return
    if len(clean) >= 2 and (top, clean[1]) in GH_READONLY:
        return
    ask(f"{tool} {' '.join(clean[:2])}: not a read-only command, please check.")


# ----------------------------------------------------------------- packages --

def flag_name(a):
    return a.split("=", 1)[0]


def positionals(args, value_flags):
    """Positional arguments, skipping the values of flags that take one."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in value_flags:
                skip = True
            continue
        out.append(a)
    return out


def flag_values(args, names):
    vals = []
    for j, a in enumerate(args):
        if a in names and j + 1 < len(args):
            vals.append(args[j + 1])
        elif flag_name(a) in names and "=" in a:
            vals.append(a.split("=", 1)[1])
    return vals


def need_sfw(sfw, cmd):
    if REQUIRE_SFW and not SFW_WORKS_IN_SANDBOX:
        deny("Package protection: installs only run through Socket Firewall, and sfw does not work "
             "in the sandbox yet. Do not retry: give the user the command to run in their own "
             "terminal (there npm, pnpm, yarn, pip, pip3 and uv run through sfw "
             "automatically; write `python -m pip` as `pip` there).")
    elif REQUIRE_SFW and not sfw:
        deny(f"Package protection: installs only through Socket Firewall, so `sfw {cmd} …`. "
             f"Please run again with `sfw` in front.")


def pkg_name(spec):
    """npm spec -> package name (`@a/b@1` -> `@a/b`, `vite@5` -> `vite`)."""
    if spec.startswith("@"):
        parts = spec.split("@")
        return "@" + parts[1] if len(parts) > 1 else spec
    return spec.split("@", 1)[0]


def locally_installed(cwd, name, as_bin):
    d = cwd or os.getcwd()
    for _ in range(40):
        if as_bin and os.path.exists(os.path.join(d, "node_modules", ".bin", name)):
            return True
        if os.path.exists(os.path.join(d, "node_modules", name, "package.json")):
            return True
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return False


def npm_overrides(tool, args):
    for j, a in enumerate(args):
        n = flag_name(a)
        if n in NPM_OVERRIDE:
            ask(f"{tool} {n}: lifts a protection setting, please check.")
        if n == "--strict-allow-scripts":
            val = a.split("=", 1)[1] if "=" in a else (args[j + 1] if j + 1 < len(args) else "")
            if val.lower() in ("false", "0", "no"):
                ask(f"{tool} --strict-allow-scripts=false: lifts the script policy.")


def check_npx(tool, args, sfw, cwd):
    """npx / pnpx / bunx / npm exec / pnpm dlx / yarn dlx: may download a package."""
    if any(a in ("--no", "--no-install") for a in args):
        return
    pkgs = flag_values(args, {"-p", "--package"})
    pos = positionals(args, NPM_VALUE_FLAGS)
    if pkgs:
        missing = [p for p in pkgs if not locally_installed(cwd, pkg_name(p), False)]
    elif pos:
        missing = [] if locally_installed(cwd, pkg_name(pos[0]), True) else [pos[0]]
    else:
        return
    if missing:
        need_sfw(sfw, tool)
        ask(f"Package protection: {tool} fetches a package that is not installed ({', '.join(missing)}). "
            f"New packages only after /dep-check and your decision.")


def check_npm(w, sfw, cwd):
    tool = os_base(w[0])
    args = w[1:]
    if tool in ("npx", "pnpx", "bunx"):
        npm_overrides(tool, args)
        check_npx(tool, args, sfw, cwd)
        return
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in NPM_VALUE_FLAGS else 1
    sub = args[i] if i < len(args) else ("install" if tool == "yarn" else "")
    rest = args[i + 1:]
    npm_overrides(tool, args)
    if sub == "config" and rest[:1] and rest[0] in ("set", "delete", "edit", "fix"):
        ask(f"{tool} config {rest[0]}: changes the package configuration.")
    if sub in ("approve-scripts",) or (sub == "install-scripts" and rest[:1] == ["approve"]):
        ask("npm: approving install scripts. Please check package and script.")
        return
    if sub == "pkg" and rest[:1] and rest[0] in ("set", "delete", "fix"):
        ask(f"{tool} pkg {rest[0]}: changes package.json, please check the dependencies.")
        return
    if sub == "audit" and "fix" in rest:
        need_sfw(sfw, tool)
        return
    if any(a in ("-g", "--global") or a == "--location=global" for a in args):
        ask(f"{tool}: global install, please check.")
    # dlx / exec / create download a package to run it
    if (tool == "npm" and sub in NPM_FETCH_NEW) or (tool in ("pnpm", "yarn", "bun")
                                                   and sub in ("dlx", "create", "x")):
        if sub in ("init", "innit") and not positionals(rest, NPM_VALUE_FLAGS):
            return  # plain `npm init` writes a package.json, downloads nothing
        if sub in ("create", "init", "innit"):
            need_sfw(sfw, tool)
            ask(f"Package protection: {tool} {sub} fetches a starter package. Please check.")
            return
        check_npx(f"{tool} {sub}", rest, sfw, cwd)
        return
    if tool == "bun":
        if sub in ("add", "install", "i") and positionals(rest, NPM_VALUE_FLAGS):
            ask("Package protection: bun is not covered by sfw/release age, please check the new package.")
        return
    if sub in NPM_NEW:
        need_sfw(sfw, tool)
        new = positionals(rest, NPM_VALUE_FLAGS)
        if new or sub == "add":
            ask(f"Package protection: new package ({', '.join(new) or '?'}). "
                f"New packages only after /dep-check and your decision.")
    elif sub in NPM_LOCK:
        need_sfw(sfw, tool)


def check_pip(tool, args, sfw):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in PIP_VALUE_FLAGS else 1
    sub = args[i] if i < len(args) else ""
    rest = args[i + 1:]
    for a in args:
        if flag_name(a) in PIP_OVERRIDE:
            ask(f"{tool} {flag_name(a)}: lifts a protection setting, please check.")
    if sub == "config" and rest[:1] and rest[0] in ("set", "unset", "edit"):
        ask(f"{tool} config {rest[0]}: changes the pip configuration.")
    if sub not in PIP_SUBS_INSTALL:
        return
    need_sfw(sfw, "pip")
    new = [p for p in positionals(rest, PIP_VALUE_FLAGS)
           if not (p in (".", "..") or p.startswith(("./", "../", "/", "~")))]
    if new:
        ask(f"Package protection: new Python package ({', '.join(new)}). "
            f"New packages only after /dep-check and your decision.")


def check_uv(w, sfw):
    tool = os_base(w[0])
    args = w[1:]
    for a in args:
        if flag_name(a) in UV_OVERRIDE:
            ask(f"{tool} {flag_name(a)}: lifts a protection setting, please check.")
    if tool == "uvx":
        need_sfw(sfw, "uvx")
        ask("Package protection: uvx fetches a package, please check.")
        return
    pos = positionals(args, {"--directory", "--project", "-p", "--python", "--with",
                             "--group", "--extra", "--package"})
    if not pos:
        return
    sub, more = pos[0], pos[1:]
    if sub == "pip" and more[:1] and more[0] in ("install", "sync", "compile"):
        need_sfw(sfw, "uv")
        if more[0] == "install" and [p for p in more[1:] if not p.startswith((".", "/"))]:
            ask("Package protection: new Python package (uv pip install). Please check.")
    elif sub == "add" or (sub == "tool" and more[:1] in (["install"], ["run"], ["upgrade"])):
        need_sfw(sfw, "uv")
        ask(f"Package protection: uv {sub} adds a package. Please check.")
    elif sub in ("sync", "lock"):
        need_sfw(sfw, "uv")


def check_other_pm(w):
    tool = os_base(w[0])
    args = w[1:]
    sub = args[0] if args else ""
    if tool == "pipx" and sub in ("install", "run", "inject", "upgrade"):
        ask("Package protection: pipx is not covered by sfw/release age, please check the package.")
    elif tool == "go" and (sub == "get" or (sub == "install" and any("@" in a for a in args))):
        ask("Package protection: go fetches a module, please check.")
    elif tool == "cargo" and sub in ("add", "install"):
        ask("Package protection: new Rust package, please check.")
    elif tool == "gem" and sub in ("install", "update"):
        ask("Package protection: new Ruby package, please check.")


def pip_tool(w):
    """`pip3 install`, `python3 -m pip install`, `.venv/bin/pip` -> ('pip', args)."""
    name = os_base(w[0])
    if re.match(r"^pip(\d+(\.\d+)?)?$", name):
        return name, w[1:]
    if re.match(r"^python(\d+(\.\d+)?)?$", name):
        for j in range(1, len(w) - 1):
            if w[j] == "-m" and w[j + 1] == "pip":
                return "pip", w[j + 2:]
            if w[j] == "-m":
                break
    return None, None


def check_pkg(w, sfw, cwd):
    name = os_base(w[0])
    if name in ("npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx"):
        check_npm(w, sfw, cwd)
        return
    if name in ("uv", "uvx"):
        check_uv(w, sfw)
        return
    if name in ("pipx", "go", "cargo", "gem"):
        check_other_pm(w)
        return
    tool, args = pip_tool(w)
    if tool:
        check_pip(tool, args, sfw)


def shell_writes(cmd, m):
    """Does the shell command write to a file whose name matches the regex m?"""
    patterns = [
        rf"(>>?|\btee\b(\s+-a)?)\s*['\"]?[^\s;&|'\"]*{m}",
        rf"\b(sed|gsed|perl)\b[^;&|\n]*\s-[a-zA-Z]*i[^;&|\n]*{m}",
        rf"\b(mv|cp|ln|rsync)\b[^;&|\n]*{m}['\"]?\s*($|[;&|)])",
        rf"\s-o\s*['\"]?[^\s;&|]*{m}",
        rf"(writeFile|write_text|write_bytes|open\([^)]*['\"][wa]|json\.dump|truncate)[^\n]*{m}",
        rf"{m}[^\n]*(writeFile|write_text|write_bytes|open\([^)]*['\"][wa]|json\.dump)",
        rf"open\([^)]*{m}[^)]*['\"][wax+]",
    ]
    return any(re.search(p, cmd) for p in patterns)


def check_bash_manifest_edit(cmd):
    """Shell edits of manifests, lockfiles and package-manager configs."""
    if shell_writes(cmd, MANIFEST_RE):
        ask("Package protection: shell command changes a manifest, lockfile or "
            "package configuration. Please check the dependencies.")
    if shell_writes(cmd, SETTINGS_RE):
        ask("Shell command changes a project's Claude settings (.claude/settings*.json). "
            "Please check which folders it opens.")


def check_env_commands(cmd):
    if re.search(r"\b(export|unset|declare|typeset|set)\b[^;&|\n]*\b(npm_config_|pip_|uv_|pnpm_|"
                 r"yarn_|corepack_|composer_)", cmd, re.I):
        ask("Protection setting changed by export/unset, please check.")


# --------------------------------------------------------------------- ssh --
# Design notes 3: reading on own servers is free, every
# change asks with host and command. Allowlist: a remote command runs free only if
# every part of it is a known read command; anything unknown asks.

REMOTE_TOOLS = re.compile(r"\b(ssh|scp|rsync|sftp)\b")
# read-only whatever the arguments (output redirection is checked separately)
REMOTE_FREE = {
    "cat", "zcat", "bzcat", "xzcat", "head", "tail", "less", "more", "grep", "egrep",
    "fgrep", "zgrep", "wc", "cut", "tr", "diff", "cmp", "comm", "md5sum", "sha1sum",
    "sha256sum", "sha512sum", "stat", "file", "readlink", "realpath", "basename",
    "dirname", "ls", "tree", "du", "df", "free", "uptime", "uname", "id", "whoami",
    "groups", "w", "who", "last", "lastlog", "ps", "pgrep", "pstree", "ss", "netstat",
    "lsof", "printenv", "echo", "printf", "true", "false", "test", "[", "[[", "which",
    "type", "whereis", "getent", "nproc", "lscpu", "lsblk", "lsmod", "lspci", "findmnt",
    "ldd", "lsb_release", "nl", "column", "strings", "od", "hexdump", "jq", "sleep",
    "cd", "pwd", "pushd", "popd", "exit", "read", "dpkg-query", "a2query", "zipinfo",
    "dig", "host", "nslookup", "ping", "traceroute", "vmstat", "iostat", "getconf",
    "locale", "ulimit", "umask", "export", "unset", "local", "shopt", "set", "seq",
}
# tools whose arguments decide (REMOTE_CHECKED below and remote_segment_issue)
SHELL_KEYWORDS = {"do", "then", "else", "elif", "if", "while", "until", "!", "{", "time"}
SHELL_ENDS = {"done", "fi", "}", "esac"}

# --- data leaving the server (design notes, 2) --------------------------------
# "Read-only" is not the same as "nothing leaves". Two channels are checked on top of
# the read/write split: programs on the server that send data out, and reads of files
# that hold secrets or personal data (they end up at the model provider).

# Programs that can carry arbitrary data to a destination. Most of them are not on the
# read-only list anyway and ask for that reason; the check matters for the few that are
# (`curl`, `openssl s_client`).
REMOTE_EGRESS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp",
                 "sftp", "scp", "rsync", "links", "lynx", "w3m", "fetch", "mail", "mailx",
                 "sendmail", "smtp", "swaks", "openssl"}
# Programs whose positional argument is a URL, never a local file.
URL_TOOLS = {"curl", "wget", "links", "lynx", "w3m", "fetch"}
URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
HOST_PORT = re.compile(r"^\[?([A-Za-z0-9._-]+|[0-9a-f:]+)\]?:(\d{1,5})$", re.I)
HOST_LIKE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
                       r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+\.?$")
# Programs whose destination is only a name, so a fixed target carries nothing. They ask
# only when an argument is built by the shell (substitution or variable).
REMOTE_LOOKUP = {"dig", "host", "nslookup", "ping", "ping6", "traceroute", "tracepath",
                 "mtr", "whois", "getent"}
LOCAL_HOST = re.compile(r"^(localhost\d?|ip6-localhost|127(\.\d+){1,3}|\[?::1\]?|0\.0\.0\.0"
                        r"|10(\.\d+){3}|192\.168(\.\d+){2}|172\.(1[6-9]|2\d|3[01])(\.\d+){2})$", re.I)
# The user's own hosts (from policy.json); a destination there is not an outside one.
REMOTE_OWN_SUFFIXES = ()
# A word the shell fills in: $(…), `…`, $VAR, ${VAR}. Such an argument can carry any
# file content to the destination, so it is never free on a network program.
SHELL_FILLED = re.compile(r"\$\(|`|\$\{?[A-Za-z_?*@#!$]")

# Data classes from policy.json (decision 2026-11-20): secret_files holds real key and
# credential files (a certificate is public, so cert.pem and fullchain.pem stay free),
# personal_files the logs with personal data in them. None means the class is off.
SECRET_FILE = None
PERSONAL_FILE = None
# Commands that print the environment, which can hold credentials.
SECRET_COMMAND = {"printenv"}
# The same, but only without arguments: `set -e` and `export PATH=…` print nothing,
# bare `set`, `export` and `env` print every variable.
SECRET_COMMAND_BARE = {"env", "set", "export", "declare", "typeset"}
# Commands that print login records (personal data).
PERSONAL_COMMAND = {"last", "lastlog", "lastb"}

# Variable assignments before a remote command. Only these are harmless; every other
# one can redirect the command (GIT_*, LESSOPEN, LD_PRELOAD, BASH_ENV, PAGER …).
SAFE_REMOTE_ENV = re.compile(r"^(LANG|LANGUAGE|LC_[A-Z_]+|TZ|TERM|COLUMNS|LINES|NO_COLOR"
                             r"|DEBIAN_FRONTEND|DEBCONF_NONINTERACTIVE_SEEN|SYSTEMD_COLORS"
                             r"|SYSTEMD_PAGER|GIT_PAGER|PAGER)=(|cat|less|more|none|noninteractive"
                             r"|true|0|1|xterm[\w-]*|dumb|[\w.@-]+\.(UTF-8|utf8)|C|POSIX"
                             r"|de_DE[\w.@-]*|en_US[\w.@-]*|Europe/[\w/+-]+|UTC)$", re.I)


def remote_destination(arg, tool=""):
    """Host a network-program argument points at, '' if the argument names none.

    Deliberately narrow: a local file name such as `cert.pem` or `nginx.conf` looks
    like a host name, so a bare word counts as a destination only for tools whose
    positional argument is always a URL.
    """
    if arg.startswith("-") or arg.startswith("/"):
        return ""
    if URL_SCHEME.match(arg):
        return (urlsplit(arg).hostname or "").lower()
    m = HOST_PORT.match(arg)                      # host:443, openssl -connect
    if m:
        return m.group(1).strip("[]").lower()
    if ":" in arg:                                # [user@]host:path (scp style)
        head = arg.split(":", 1)[0].rsplit("@", 1)[-1].strip("[]")
        return head.lower() if head and "/" not in head else ""
    if tool in URL_TOOLS and HOST_LIKE.match(arg):
        return arg.rstrip(".").lower()
    return ""


def outside_destination(host):
    return bool(host) and not LOCAL_HOST.match(host) \
        and not host.endswith(REMOTE_OWN_SUFFIXES) and host not in ("", "-")


# Reasons from remote_data_issue carry this prefix, so check_ssh can tell a data
# question ("this leaves the server") from a change question ("this writes there").
DATA_MARK = "Daten: "


def remote_data_issue(name, args):
    """Data leaving the server: network programs and reads of sensitive files."""
    def mark(msg):
        return DATA_MARK + msg

    if name in REMOTE_EGRESS or name in REMOTE_LOOKUP:
        for a in args:
            if SHELL_FILLED.search(a):
                return mark(f"{name} with an argument the shell fills in ($(…), variable): "
                            f"file contents can leave the server this way")
    if name in REMOTE_EGRESS:
        for a in args:
            host = remote_destination(a, name)
            if outside_destination(host):
                return mark(f"{name} to {host} (not localhost, not an own host)")
    if name in SECRET_COMMAND or (name in SECRET_COMMAND_BARE and not args):
        return mark(f"{name} shows all environment variables, which can hold credentials")
    if name in PERSONAL_COMMAND:
        return mark(f"{name} shows login data of people")
    if name == "ps" and any(re.match(r"^-?[a-dfghj-z]*e", a) for a in args):
        return mark("ps with e shows the environment variables of processes")
    if name == "docker" and "inspect" in args:
        return mark("docker inspect shows the environment variables of containers")
    for a in args:
        if a.startswith("-"):
            continue
        if SECRET_FILE is not None and SECRET_FILE.search(a):
            return mark(f"reads {a} (credentials)")
        if PERSONAL_FILE is not None and PERSONAL_FILE.search(a):
            return mark(f"reads {a} (personal data)")
    return None


def sh_tokens(s):
    # a newline separates commands like `;` (shlex would treat it as a blank)
    lex = shlex.shlex(s, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    return list(lex)


def is_op(t):
    return bool(t) and all(c in "();<>|&\n" for c in t)


def short_letters(a):
    """`-avz` -> 'avz'; long options and plain words -> ''."""
    return a[1:] if a.startswith("-") and not a.startswith("--") and len(a) > 1 else ""


def flag_value(args, j, letter_or_name):
    """Value of a flag at args[j]: attached (`-ofile`, `--x=y`) or the next word."""
    a = args[j]
    if a.startswith("--"):
        return a.split("=", 1)[1] if "=" in a else (args[j + 1] if j + 1 < len(args) else "")
    rest = a[a.index(letter_or_name) + 1:]
    return rest or (args[j + 1] if j + 1 < len(args) else "")


def substitutions(word):
    """Inner commands of `$(...)` inside a word (quoted forms stay in one word)."""
    out, i = [], word.find("$(")
    while i >= 0:
        depth, j = 1, i + 2
        while j < len(word) and depth:
            depth += {"(": 1, ")": -1}.get(word[j], 0)
            j += 1
        out.append(word[i + 2:j - 1])
        i = word.find("$(", j)
    return out


def backtick_commands(s):
    """Inner commands of backticks the shell would run: outside single quotes (inside
    double quotes they run too), backslash-escaped backticks skipped. An unclosed
    backtick counts up to the end, so it stays suspicious."""
    out, i, n, dq = [], 0, len(s), False
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'" and not dq:
            j = s.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            dq = not dq
        elif c == "`":
            j = i + 1
            while j < n and s[j] != "`":
                j += 2 if s[j] == "\\" else 1
            out.append(s[i + 1:j])
            i = j
        i += 1
    return out


OP_PARTS = re.compile(r"&>>|&>|>>|>&|<&|>\||<<<|<<-|<<|<>|&&|\|\||;;|\|&|[;&|()<>\n]")


def split_segments(tokens, issues=None):
    """Simple commands of a token list. `$(…)`, `<(…)` and `( … )` become commands of
    their own; the outer command keeps a placeholder. Redirects are checked when
    `issues` is given."""
    segs, cur, stack, i = [], [], [], 0

    def note(msg):
        if issues is not None:
            issues.append(msg)

    while i < len(tokens):
        t = tokens[i]
        i += 1
        if not is_op(t):
            cur.append(t)
            continue
        parts = OP_PARTS.findall(t)
        k = 0
        while k < len(parts):
            p = parts[k]
            nxt = parts[k + 1] if k + 1 < len(parts) else None
            if p == "(":
                if cur and cur[-1].endswith("$"):  # command substitution
                    cur[-1] = cur[-1][:-1] + "$(…)"
                    stack.append(cur)
                else:  # subshell
                    stack.append(None)
                    segs.append(cur)
                cur = []
            elif p == ")":
                segs.append(cur)
                cur = []
                if stack:
                    outer = stack.pop()
                    cur = outer if outer is not None else []
            elif p in ("<", ">") and nxt == "(":  # process substitution
                if p == ">":
                    note("process substitution >(…)")
                stack.append(cur + [p + "(…)"])
                cur = []
                k += 1
            elif p in (";", "&", "&&", "||", "|", "|&", ";;", "\n"):
                if p == ";;":
                    note("case statement")
                segs.append(cur)
                cur = []
            else:  # redirect: the next word is its target
                target = ""
                if nxt is None and i < len(tokens) and not is_op(tokens[i]):
                    target = tokens[i]
                    i += 1
                if cur and cur[-1].isdigit():
                    cur.pop()  # fd number of `2>…`
                if p in (">&", "<&") and (target.isdigit() or target == "-"):
                    pass
                elif p in (">", ">>", ">|", "&>", "&>>", ">&") and target == "/dev/null":
                    pass
                elif p == "<":
                    pass
                elif ">" in p:
                    note(f"output to file ({p} {target})")
                else:
                    note(f"redirection {p} (heredoc or similar)")
            k += 1
    segs.append(cur)
    segs.extend(s for s in stack if s)
    return [s for s in segs if s]


def strip_remote_prefix(w, issues=None):
    """Drop keywords, assignments and wrappers (sudo, nice, timeout, env, nohup, exec).

    A variable assignment before the command is only dropped when it is known to be
    harmless (SAFE_REMOTE_ENV). Every other one is reported, because it can redirect
    the command that follows: GIT_EXTERNAL_DIFF, LESSOPEN, LD_PRELOAD, BASH_ENV,
    PAGER and others make a read command run a program of its own.
    """
    while w:
        h = w[0]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", h)
        if m:
            if not SAFE_REMOTE_ENV.match(h) and issues is not None:
                issues.append(f"Variable {m.group(1)} before the command: can run another "
                              f"command or redirect the output")
            w = w[1:]
        elif h in SHELL_KEYWORDS:
            w = w[1:]
        elif h == "sudo":
            w = w[1:]
            while w and w[0].startswith("-"):
                if w[0] == "--":
                    w = w[1:]
                    break
                w = w[2:] if w[0] in ("-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t") else w[1:]
        elif h == "nice":
            w = w[1:]
            if w and w[0] == "-n":
                w = w[2:]
            elif w and re.match(r"^-n?\d+$", w[0]):
                w = w[1:]
        elif h == "timeout":
            w = w[1:]
            while w and w[0].startswith("-"):
                w = w[2:] if w[0] in ("-s", "--signal", "-k", "--kill-after") else w[1:]
            w = w[1:]  # duration
        elif h in ("nohup", "exec"):
            w = w[1:]
        elif h == "env" and len(w) > 1 and not w[1].startswith("-"):
            w = w[1:]
        elif h == "command" and len(w) > 1 and w[1] not in ("-v", "-V"):
            w = w[1:]
        else:
            break
    return w


def positional_words(args, value_flags=()):
    return positionals(args, set(value_flags))


def ro_date(a):
    if any(flag_name(x) in ("-s", "--set") or "s" in short_letters(x) for x in a):
        return "date -s"
    if [x for x in a if not x.startswith(("-", "+"))]:
        return "date with a time argument"


def ro_hostname(a):
    if any(not x.startswith("-") for x in a) or any(flag_name(x) in ("-F", "--file", "-b", "--boot")
                                                     for x in a):
        return "hostname set"


def ro_find(a):
    bad = [x for x in a if x in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint",
                                 "-fprint0", "-fprintf", "-fls")]
    if bad:
        return f"find {bad[0]}"


SED_WRITE = re.compile(r"(^|[;}\n!$0-9]|/[gpIiMm0-9]*)\s*[wWe](\s|$)|s(.).*\3.*\3[gpIiMm0-9]*[we]")


def ro_sed(a):
    scripts, j, given = [], 0, False
    while j < len(a):
        x = a[j]
        n = flag_name(x)
        if n in ("--in-place", "-f", "--file") or (short_letters(x) and
                                                   ("i" in short_letters(x).split("e")[0].split("f")[0])):
            return "sed -i / -f"
        if n in ("-e", "--expression"):
            scripts.append(flag_value(a, j, "e"))
            given = True
            j += 1 if "=" in x else 2
            continue
        if short_letters(x) and "e" in short_letters(x):
            scripts.append(flag_value(a, j, "e"))
            given = True
            j += 2 if x.endswith("e") else 1
            continue
        if not x.startswith("-") and not given:
            scripts.append(x)
            given = True
        j += 1
    if any(SED_WRITE.search(s) for s in scripts):
        return "sed writes (w/e command)"


def ro_awk(a):
    prog, j = None, 0
    while j < len(a):
        x = a[j]
        if flag_name(x) in ("-f", "--file", "-i", "--include", "-l", "--load", "-E", "--exec") \
                or x.startswith(("-f", "-i")) and not x.startswith("--"):
            return "awk with program file/extension"
        if x in ("-v", "-F", "--assign", "--field-separator"):
            j += 2
            continue
        if not x.startswith("-") and prog is None:
            prog = x
        j += 1
    if prog is None or re.search(r"system|[>|]", prog):
        return "awk writes or starts commands (>, |, system)"


def ro_sort(a):
    for x in a:
        if flag_name(x) == "--compress-program":
            return "sort --compress-program (runs a program)"
        if flag_name(x) == "--output" or "o" in short_letters(x).split("k")[0].split("t")[0] \
                .split("S")[0].split("T")[0]:
            return "sort -o"


def ro_uniq(a):
    if len(positional_words(a, ("-f", "-s", "-w"))) >= 2:
        return "uniq writes to a file"


def ro_crontab(a):
    rest = positional_words(a, ("-u",))
    if rest or "-l" not in a:
        return "crontab change"


def ro_dpkg(a):
    ro = {"-l", "--list", "-s", "--status", "-L", "--listfiles", "-S", "--search",
          "--get-selections", "-p", "--print-avail", "--version", "--print-architecture",
          "-V", "--verify", "--audit", "-C"}
    flags = [flag_name(x) for x in a if x.startswith("-")]
    if not flags or any(f not in ro for f in flags):
        return "dpkg changes packages"


def ro_apt(a, tool):
    ok = {"apt": {"list", "show", "policy", "search", "depends", "rdepends", "madison"},
          "apt-cache": {"policy", "show", "search", "depends", "rdepends", "madison", "showpkg",
                        "stats", "pkgnames", "showsrc"}}[tool]
    pos = positional_words(a, ("-o", "-c", "-t"))
    if not pos or pos[0] not in ok:
        return f"{tool} {pos[0] if pos else ''}".strip()


def ro_systemctl(a):
    ok = {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files",
          "list-timers", "list-sockets", "list-dependencies", "show", "cat", "list-jobs",
          "is-system-running", "get-default"}
    pos = positional_words(a, ("-t", "--type", "-p", "--property", "-H", "--host", "-M",
                               "--machine", "--state", "-n", "--lines", "-o", "--output"))
    if pos and pos[0] not in ok:
        return f"systemctl {pos[0]}"


def ro_service(a):
    if a == ["--status-all"] or (len(a) == 2 and a[1] == "status"):
        return None
    return f"service {' '.join(a[:2])}"


def ro_journalctl(a):
    bad = [x for x in a if flag_name(x).startswith(("--vacuum", "--rotate", "--flush", "--sync",
                                                    "--relinquish", "--smart-relinquish",
                                                    "--setup-keys", "--update-catalog"))]
    if bad:
        return f"journalctl {flag_name(bad[0])}"


def ro_apache(a, tool):
    action, j = False, 0
    while j < len(a):
        x = a[j]
        if x in ("-k", "-T", "-X") or x.startswith("-k"):
            return f"{tool} {x} (starts/controls the server)"
        if x in ("-D", "-f", "-d", "-C", "-c", "-E"):
            if x == "-D" and j + 1 < len(a) and a[j + 1].startswith("DUMP_"):
                action = True
            j += 2
            continue
        if x in ("-v", "-V", "-M", "-S", "-l", "-L", "-t", "-h") or x.startswith("-t"):
            action = True
        elif not x.startswith("-"):
            if x not in ("configtest", "status", "fullstatus", "-t"):
                return f"{tool} {x}"
            action = True
        else:
            return f"{tool} {x}"
        j += 1
    if not action:
        return f"{tool} without a check option starts the server"


def ro_nginx(a):
    action, j = False, 0
    while j < len(a):
        x = a[j]
        if x in ("-c", "-p", "-e"):
            j += 2
            continue
        if x in ("-v", "-V", "-t", "-T", "-h", "-?"):
            action = True
        elif x != "-q":
            return f"nginx {x}"
        j += 1
    if not action:
        return "nginx without -t/-T/-v starts the server"


def ro_php(a, tool):
    ok = {"-v", "--version", "-m", "--modules", "-i", "--info", "--ini", "-l", "--syntax-check",
          "-t", "--test"}
    flags = [x for x in a if x.startswith("-")]
    pos = [x for x in a if not x.startswith("-")]
    if not flags or any(f not in ok for f in flags) or (pos and not ({"-l", "--syntax-check"}
                                                                     & set(flags))):
        return f"{tool} runs code"


def ro_openssl(a):
    ok = {"x509", "s_client", "version", "verify", "ciphers", "crl", "list", "asn1parse"}
    if not a or a[0] not in ok:
        return f"openssl {a[0] if a else ''}".strip()
    bad = [x for x in a if flag_name(x).startswith(("-out", "-keyout", "-writerand", "-sess_out",
                                                    "-signkey", "-CA", "-req", "-new"))]
    if bad:
        return f"openssl {bad[0]}"


CURL_VAL = set("AbcCdDeEFHKmoPQrTtuUwxXyYz")
CURL_BAD_LONG = ("--output", "--remote-name", "--output-dir", "--data", "--json", "--form",
                 "--upload-file", "--config", "--cookie-jar", "--quote", "--ftp-create-dirs",
                 "--trace", "--stderr", "--libcurl", "--etag-save", "--hsts", "--alt-svc",
                 "--create-dirs")


def ro_curl(a):
    for j, x in enumerate(a):
        n = flag_name(x)
        if n in ("-o", "--output") and flag_value(a, j, "o") == "/dev/null":
            continue  # `curl -o /dev/null -w …`: a health check, writes nothing
        if n.startswith(CURL_BAD_LONG):
            return f"curl {n}"
        if n == "--request" and flag_value(a, j, "").upper() not in ("GET", "HEAD"):
            return f"curl {n}"
        if n == "--dump-header" and flag_value(a, j, "") != "-":
            return f"curl {n}"
        for k, c in enumerate(short_letters(x)):
            if c == "O" or c in "cdFKoQT":
                return f"curl -{c}"
            if c == "X" and flag_value(a, j, "X").upper() not in ("GET", "HEAD"):
                return "curl -X"
            if c == "D" and flag_value(a, j, "D") != "-":
                return "curl -D"
            if c in CURL_VAL:
                break


def ro_git(a):
    j = 0
    while j < len(a) and a[j].startswith("-"):
        if a[j] == "-c" or a[j].startswith("--exec-path"):
            return "git -c"
        j += 2 if a[j] in ("-C", "--git-dir", "--work-tree", "--namespace") else 1
    if j >= len(a):
        return None if a else "git"
    sub, rest = a[j], a[j + 1:]
    if any(flag_name(x) in ("--output", "-O", "--open-files-in-pager") for x in rest):
        return f"git {sub} --output"
    if sub in ("status", "log", "diff", "show", "rev-parse", "ls-files", "ls-tree", "describe",
               "blame", "shortlog", "cat-file", "rev-list", "grep", "whatchanged",
               "count-objects", "version", "help", "ls-remote", "show-ref", "for-each-ref"):
        return None
    pos = [x for x in rest if not x.startswith("-")]
    if sub in ("branch", "tag") and (not pos or {"-l", "--list"} & set(rest)) \
            and not {"-d", "-D", "-m", "-M", "-c", "-C", "--delete", "-f", "--force"} & set(rest):
        return None
    if sub == "remote" and (not pos or pos[0] in ("show", "get-url")):
        return None
    if sub == "stash" and pos[:1] in (["list"], ["show"]):
        return None
    if sub == "config" and {"--get", "--get-all", "--get-regexp", "--list", "-l"} & set(rest):
        return None
    if sub == "reflog" and (not pos or pos[0] == "show"):
        return None
    return f"git {sub}"


def ro_docker(a):
    pos = positional_words(a, ("-H", "--host", "--context", "-c", "-f", "--file", "-p",
                               "--project-name", "--format", "-n", "--tail", "--since"))
    if pos[:1] == ["compose"]:
        pos = pos[1:]
        ok = {"ps", "logs", "config", "ls", "images", "version", "top"}
    else:
        ok = {"ps", "images", "inspect", "logs", "version", "info", "top", "stats", "port"}
    if pos[:1] == ["container"] or pos[:1] == ["image"]:
        pos = pos[1:]
        ok = {"ls", "list", "inspect", "logs", "top", "port", "stats", "history"}
    if not pos or pos[0] not in ok:
        return f"docker {pos[0] if pos else ''}".strip()
    if pos[0] == "stats" and "--no-stream" not in a:
        return "docker stats without --no-stream"


def ro_ip(a):
    bad = {"add", "del", "delete", "change", "replace", "set", "flush", "append", "prepend",
           "exec", "save", "restore", "attach", "detach", "update"}
    hit = [x for x in a if x in bad]
    if hit:
        return f"ip {hit[0]}"


def ro_sysctl(a):
    if any(flag_name(x) in ("-w", "--write", "-p", "--load", "--system") or "=" in x for x in a):
        return "sysctl sets values"


def ro_firewall(a, tool):
    if tool == "ufw":
        if a[:1] in (["status"], ["show"]) or a[:2] in (["app", "list"], ["app", "info"]):
            return None
        return f"ufw {' '.join(a[:1])}"
    if tool == "nft":
        return None if a[:1] == ["list"] or a == ["--version"] else "nft changes rules"
    listing = {"-L", "--list", "-S", "--list-rules"}
    changes = {"-A", "-I", "-D", "-R", "-F", "-X", "-N", "-P", "-Z", "-E", "--append", "--insert",
               "--delete", "--replace", "--flush", "--delete-chain", "--new-chain", "--policy",
               "--zero", "--rename-chain"}
    if not listing & set(a) or changes & set(a):
        return f"{tool} changes rules"


def ro_ctl(a, tool):
    pos = positional_words(a)
    if pos and pos[0] not in ("status", "show", "list", "list-timezones", "list-sessions",
                              "list-users", "list-locales", "list-keymaps", "show-session"):
        return f"{tool} {pos[0]}"


def ro_tar(a):
    first = a[0] if a else ""
    letters = first.lstrip("-") if first and not first.startswith("--") else ""
    if "--list" in a or ("t" in letters and not set("cxruA") & set(letters)):
        if not [x for x in a if flag_name(x) in ("--delete", "--to-command", "--use-compress-program",
                                                 "-I", "--checkpoint-action")]:
            return None
    return "tar packs/unpacks"


def ro_misc(name, a):
    if name == "unzip":
        return None if {"-l", "-v", "-Z", "-t"} & set(a) and "-d" not in a else "unzip entpackt"
    if name == "certbot":
        return None if a[:1] == ["certificates"] else f"certbot {' '.join(a[:1])}"
    if name == "dmesg":
        bad = [x for x in a if flag_name(x) in ("-c", "-C", "--clear", "--read-clear", "-n",
                                                "--console-level", "-D", "-E", "--console-off",
                                                "--console-on")]
        return f"dmesg {bad[0]}" if bad else None
    if name == "top":
        return None if any("b" in short_letters(x) for x in a) else "top without -b"
    if name == "mount":
        return None if not a or a == ["-l"] else "mount"
    if name == "env":
        return None if not a else "env with options"
    if name == "command":
        return None if a[:1] in (["-v"], ["-V"]) else "command"
    return "?"


REMOTE_CHECKED = {
    "date": ro_date, "hostname": ro_hostname, "find": ro_find, "sed": ro_sed, "awk": ro_awk,
    "gawk": ro_awk, "mawk": ro_awk, "nawk": ro_awk, "sort": ro_sort, "uniq": ro_uniq,
    "crontab": ro_crontab, "dpkg": ro_dpkg, "systemctl": ro_systemctl, "service": ro_service,
    "journalctl": ro_journalctl, "nginx": ro_nginx, "openssl": ro_openssl, "curl": ro_curl,
    "git": ro_git, "docker": ro_docker, "ip": ro_ip, "sysctl": ro_sysctl, "tar": ro_tar,
}


def remote_segment_issue(w):
    env_issues = []
    w = strip_remote_prefix(w, env_issues)
    if env_issues:
        return env_issues[0]
    if not w or (len(w) == 1 and w[0] in SHELL_ENDS):
        return None
    head = w[0]
    if head in ("for", "select"):
        return None  # loop words; substitutions in them are checked separately
    if "$" in head or "`" in head:
        return f"variable as command ({head})"
    name, args = os_base(head), w[1:]
    # data leaving the server is checked for every command, read-only or not
    leak = remote_data_issue(name, args)
    if leak:
        return leak
    if args in (["--version"], ["--help"]) and name not in ("bash", "sh", "zsh", "dash"):
        return None
    if name in REMOTE_CHECKED:
        return REMOTE_CHECKED[name](args)
    if name in REMOTE_FREE:
        return None
    if name in ("apt", "apt-cache"):
        return ro_apt(args, name)
    if name in ("apache2", "apache2ctl", "apachectl", "httpd"):
        return ro_apache(args, name)
    if re.match(r"^php(-fpm)?[\d.]*$", name):
        return ro_php(args, name)
    if name in ("ufw", "iptables", "ip6tables", "nft"):
        return ro_firewall(args, name)
    if name in ("timedatectl", "hostnamectl", "localectl", "loginctl"):
        return ro_ctl(args, name)
    if name in ("unzip", "certbot", "dmesg", "top", "mount", "env", "command"):
        issue = ro_misc(name, args)
        return None if issue is None else (issue if issue != "?" else name)
    return name


def remote_issues(remote, depth=0):
    """Reasons why a remote shell command is not plainly read-only (empty: read-only)."""
    if depth > 3:
        return ["nested too deeply"]
    try:
        tokens = sh_tokens(remote)
    except ValueError:
        return ["command not readable (quotes)"]
    issues = []
    if backtick_commands(remote):
        issues.append("Backticks")
    for t in tokens:
        for inner in substitutions(t):
            issues.extend(remote_issues(inner, depth + 1))
    for seg in split_segments(tokens, issues):
        issue = remote_segment_issue(seg)
        if issue:
            issues.append(issue)
    return issues


SSH_VAL = set("BbcDEeFIiJLlmOoPpQRSWw")
FORWARD_REASON = ("Agent forwarding (-A / ForwardAgent): the server could use your ssh agent "
                  "to log in to further servers. Please check.")


def forward_agent_value(v):
    """-o value enables agent forwarding: ForwardAgent=yes, a socket path, $VAR, not `no`."""
    m = re.match(r"(?i)^\s*forwardagent\s*(?:=|\s)\s*(\S*)", v)
    return bool(m) and m.group(1).strip("'\"").lower() != "no"


def ssh_opts_forward(args):
    """-A or -o ForwardAgent=… among ssh-style options (ssh command line, rsync -e value)."""
    j = 0
    while j < len(args):
        letters = short_letters(args[j])
        for k, c in enumerate(letters):
            if c == "A":
                return True
            if c in SSH_VAL:
                val = letters[k + 1:] or (args[j + 1] if j + 1 < len(args) else "")
                if c == "o" and forward_agent_value(val):
                    return True
                if not letters[k + 1:]:
                    j += 1
                break
        j += 1
    return False


def check_ssh(w):
    args, j, host, opts = w[1:], 0, "", []
    while j < len(args):
        a = args[j]
        if a == "--":
            j += 1
            break
        if not a.startswith("-") or a == "-":
            break
        letters = a[1:]
        for k, c in enumerate(letters):
            opts.append(c)
            if c == "A":
                ask(f"ssh -A: {FORWARD_REASON}")
            if c in SSH_VAL:
                val = letters[k + 1:] or (args[j + 1] if j + 1 < len(args) else "")
                if c == "o" and re.match(r"(?i)^\s*remotecommand", val):
                    ask("ssh -o RemoteCommand: command on the server cannot be checked, please check.")
                if c == "o" and forward_agent_value(val):
                    ask(f"ssh: {FORWARD_REASON}")
                if not letters[k + 1:]:
                    j += 1
                break
        j += 1
    if j < len(args):
        host, rest = args[j], args[j + 1:]
    else:
        rest = []
    if set(opts) & {"G", "V", "Q"} and not rest:
        return  # prints config/version, no connection
    if "s" in opts:
        ask(f"ssh -s {host}: subsystem (e.g. sftp), please check.")
        return
    if not rest:
        ask(f"ssh {host or '?'} without a command (interactive or command via stdin): content cannot "
            f"be checked. Please check host and command.")
        return
    issues = remote_issues(" ".join(rest))
    if issues:
        seen = []
        for i in issues:
            if i not in seen:
                seen.append(i)
        data = [i[len(DATA_MARK):] for i in seen if i.startswith(DATA_MARK)]
        other = [i for i in seen if not i.startswith(DATA_MARK)]
        if data and not other:
            ask(f"ssh {host}: the command passes data on from the server ({'; '.join(data[:4])}). "
                f"Credentials and personal data must not leave the servers, and everything "
                f"read goes to the model provider. Please check.", "ssh.data")
        elif data:
            ask(f"ssh {host}: command is not read-only ({'; '.join(other[:3])}) and passes data on "
                f"weiter ({'; '.join(data[:2])}). Please check host, change and data.",
                "ssh.write+data")
        else:
            ask(f"ssh {host}: command is not read-only ({'; '.join(other[:4])}). Changes on "
                f"servers only after asking: please check host and change.", "ssh.write")


def rsh_forward(rsh):
    try:
        parts = shlex.split(rsh)
    except ValueError:
        ask("rsync -e: value cannot be split, please check.")
        return
    if ssh_opts_forward(parts[1:]):
        ask(f"rsync -e: {FORWARD_REASON}")


REMOTE_PATH = re.compile(r"^(scp://|rsync://|([^/:@\s]+@)?(\[[^\]]+\]|[^/:\s]+):)")


def check_copy(w):
    """scp/rsync: writing to a server asks, fetching is free."""
    tool = os_base(w[0])
    args = w[1:]
    if tool == "scp":
        val_short, val_long = set("cDFiJlOoPSX"), set()
    else:
        val_short = set("efTMB")
        val_long = {"--rsh", "--exclude", "--include", "--filter", "--files-from",
                    "--exclude-from", "--include-from", "--rsync-path", "--chmod", "--log-file",
                    "--temp-dir", "--partial-dir", "--backup-dir", "--suffix", "--port",
                    "--timeout", "--bwlimit", "--compare-dest", "--copy-dest", "--link-dest",
                    "--max-size", "--min-size", "--out-format", "--password-file", "--chown",
                    "--usermap", "--groupmap", "--info", "--debug", "--contimeout"}
    pos, j, dry = [], 0, False
    while j < len(args):
        a = args[j]
        if a.startswith("--"):
            if a in ("--dry-run",):
                dry = True
            if tool == "rsync" and (a == "--rsh" or a.startswith("--rsh=")):
                rsh = a[len("--rsh="):] if "=" in a else (args[j + 1] if j + 1 < len(args) else "")
                rsh_forward(rsh)
            if a in val_long:
                j += 1
        elif a.startswith("-") and len(a) > 1:
            for k, c in enumerate(a[1:]):
                if c == "n" and tool == "rsync":
                    dry = True
                if tool == "scp" and c == "A":
                    ask(f"scp -A: {FORWARD_REASON}")
                if c in val_short:
                    val = a[k + 2:] or (args[j + 1] if j + 1 < len(args) else "")
                    if tool == "scp" and c == "o" and forward_agent_value(val):
                        ask(f"scp: {FORWARD_REASON}")
                    if tool == "rsync" and c == "e":
                        rsh_forward(val)
                    if not a[k + 2:]:
                        j += 1
                    break
        else:
            pos.append(a)
        j += 1
    if len(pos) < 2 or dry:
        return
    dst, srcs = pos[-1], pos[:-1]
    if REMOTE_PATH.match(dst):
        ask(f"{tool}: writes to the server ({dst}). Please check host and target.")
    elif tool == "rsync" and "--remove-source-files" in args and any(REMOTE_PATH.match(s)
                                                                    for s in srcs):
        ask("rsync --remove-source-files: deletes on the server. Please check.")


LOCAL_WRAPPERS = {"sudo", "command", "time", "nice", "nohup", "exec", "env", "timeout"}
NESTING = {"sh", "bash", "zsh", "dash", "eval", "xargs", "parallel", "watch", "flock",
           "script", "source", "."}


def check_remote(cmd, depth=0):
    """Find ssh/scp/rsync/sftp in a local command, quotes respected."""
    if not REMOTE_TOOLS.search(cmd):
        return
    if depth > 3:
        ask("ssh in a deeply nested command: please check.")
        return
    try:
        tokens = sh_tokens(cmd)
    except ValueError:
        ask("ssh/scp/rsync in a command that cannot be split: please check.")
        return
    for t in tokens:
        for inner in substitutions(t):
            check_remote(inner, depth + 1)
    if any(REMOTE_TOOLS.search(inner) for inner in backtick_commands(cmd)):
        ask("ssh/scp/rsync in backticks: please check.")
    for w in split_segments(tokens):
        while w and (w[0] in SHELL_KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0])):
            w = w[1:]
        while w and os_base(w[0]) in LOCAL_WRAPPERS:
            if w[0] == "command" and w[1:2] in (["-v"], ["-V"]):
                w = []
                break
            w = w[1:]
            while w and (w[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0])
                         or re.match(r"^\d+[smhd]?$", w[0])):
                w = w[2:] if w[0] in ("-u", "-n", "-s", "-k", "-g") else w[1:]
        if not w:
            continue
        name = os_base(w[0])
        if name == "ssh":
            SEEN.add("ssh")
            check_ssh(w)
        elif name in ("scp", "rsync"):
            SEEN.add("ssh")
            check_copy(w)
        elif name == "sftp":
            ask("sftp: file access on the server cannot be checked, please check.")
        elif name in NESTING and REMOTE_TOOLS.search(" ".join(w[1:])):
            ask(f"ssh/scp/rsync in a nested command ({name}): please check.")


# `<<WORD`, `<<-WORD`, `<<'WORD'`, `<<"WORD"`, `<<\WORD`; not the here-string `<<<`
HEREDOC_START = re.compile(r"(?<!<)<<(?!<)(-?)\s*(?:\\|(['\"]))?([A-Za-z_][\w.-]*)\2?")
# A heredoc fed to one of these is a command, not text.
HEREDOC_RUNS = re.compile(r"(^|[\s;&|(`])(ssh|sh|bash|zsh|dash|ksh|eval|source|\.|python\d*"
                          r"|perl|ruby|node|php|xargs|env|sudo)(\s|$)")


def strip_heredocs(cmd):
    """The command without the body of heredocs that are only text.

    `git commit -F - <<'EOF' … EOF` passes a message; reading that message as commands
    made a commit about these rules look like a package install and get denied (section
    20.7). A heredoc stays when the line that opens it runs a shell, ssh or an
    interpreter (then the body is a command), so in doubt the body is kept and checked.
    Writes into files are judged on the full text elsewhere (check_bash_manifest_edit).
    """
    if "<<" not in cmd:
        return cmd
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        tags = [(m.group(1) == "-", m.group(3)) for m in HEREDOC_START.finditer(line)]
        keep = bool(HEREDOC_RUNS.search(line))
        for dash, tag in tags:
            while i < len(lines):
                body = lines[i]
                i += 1
                if (body.lstrip("\t") if dash else body) == tag:
                    out.append(body)
                    break
                if keep:
                    out.append(body)
    return "\n".join(out)


# Programs that run text given to them as an argument. For a shell the text is a shell
# command; for an interpreter it is code, in which a shell command may sit as a string
# (os.system("npm install x")). The same list decides for heredocs (HEREDOC_RUNS).
TEXT_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "eval", "su", "source", ".",
               "xargs", "watch", "parallel", "script", "flock", "runuser", "doas",
               "chroot", "find", "osascript", "expect"}
TEXT_INTERPRETERS = re.compile(r"^(python[\d.]*|perl|ruby|node|nodejs|php|deno|bun|lua"
                               r"|tclsh|Rscript|awk|gawk|mawk|nawk)$")
MAX_TEXT_DEPTH = 4


def coarse_segments(text):
    """The old split: separators count even inside quotes. Only for text that cannot be
    parsed, where checking too much is better than too little."""
    return [w for w in (words(s.strip()) for s in SEGMENT_SPLIT.split(text)) if w]


def bash_segments(text, depth=0, code=False):
    """The simple commands in a local shell command, quotes respected (design notes, 5).

    A separator inside quotes is text, so `git commit -m "fix; npm install x"` is one
    commit and not an install. Quoted text is read as a command only where it runs:
    command substitutions and backticks, the arguments of a shell (`bash -c "…"`,
    `xargs sh -c "…"`, `eval "…"`), and the code of an interpreter (`python3 -c "…"`),
    where every string is searched as well (code=True). Text that cannot be parsed and
    nesting deeper than MAX_TEXT_DEPTH fall back to the old split, so in doubt more is
    checked, not less."""
    if depth > MAX_TEXT_DEPTH:
        return coarse_segments(text)
    try:
        tokens = sh_tokens(text)
    except ValueError:
        return coarse_segments(text)
    out = []
    for seg in split_segments(tokens):
        out.append(seg)
        inner_code = code
        if not code:
            w, _ = strip_prefix_quiet(seg)
            name = os_base(w[0]) if w else ""
            if name in TEXT_SHELLS:
                inner_code = False
            elif TEXT_INTERPRETERS.match(name):
                inner_code = True
            else:
                continue
        for word in seg[1:] if not code else seg:
            if re.search(r"\s", word):
                out.extend(bash_segments(word, depth + 1, inner_code))
    for t in tokens:
        for inner in substitutions(t):
            out.extend(bash_segments(inner, depth + 1))
    for inner in backtick_commands(text):
        out.extend(bash_segments(inner, depth + 1))
    return out


def strip_prefix_quiet(w):
    """strip_prefix without its questions, only to find the program a segment runs."""
    n_ask, n_deny = len(ASKS), len(DENIES)
    try:
        return strip_prefix(list(w))
    finally:
        del ASKS[n_ask:], DENIES[n_deny:]


def check_bash(cmd, cwd):
    check_remote(cmd)
    git_net = False
    outside = []  # tools on this line that run outside the sandbox
    seen_words = []
    here = os.path.realpath(cwd) if cwd else None
    full, cmd = cmd, strip_heredocs(cmd)
    for seg in bash_segments(cmd):
        w, sfw = strip_prefix(seg)
        if not w:
            continue
        seen_words.append(w)
        name = os_base(w[0])
        if name == "cd":
            # follow the working directory, so `cd <repo> && git pull` is judged there
            targets = positionals(w[1:], set())
            here = resolve_cwd(targets[0] if targets else "", here, cwd)
            continue
        if name == "git":
            if check_git(w, cwd, here):
                git_net = True
                SEEN.add("git-network")
                outside.append("git")
        elif name in ("gh", "glab"):
            check_gh(w)
            outside.append(name)
        else:
            check_pkg(w, sfw, cwd)
    # fallback for nested forms the parser misses, e.g. `bash -c "git push"`
    if re.search(r"\b(sh|bash|zsh|eval|xargs|env)\b", cmd) and \
            re.search(r"\bgit\b[^\n;&|]*\bpush\b", cmd):
        ask("git push (in a nested command): please check.")
    if git_net and GIT_DANGER_ENV.search(cmd):
        ask("git environment variable (GIT_SSH_COMMAND, GIT_CONFIG_* …) with git outside the sandbox: "
            "can run commands. Please check.")
    if outside:
        if READ_DENY_ROOTS and re.search(r"\$\(|`|<\(", cmd):
            ask(f"{outside[0]} runs outside the sandbox, and the command line fills in text "
                "through $(…), `…` or <(…), which would then read without the read boundary "
                "(design notes, 12). Please check.", "read.outside-sandbox")
        outside_command_reads(seen_words, here, cwd, outside[0])
    check_bash_manifest_edit(full)  # a heredoc written into package.json counts
    check_env_commands(cmd)


# ---------------------------------------------------------- file edits ------

def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def new_content(tool, inp, old):
    if tool == "Write":
        return inp.get("content", "")
    edits = inp.get("edits") if tool == "MultiEdit" else [inp]
    s = old
    for e in edits or []:
        o, n = e.get("old_string", ""), e.get("new_string", "")
        if not o:
            s = n if not s else s
        elif e.get("replace_all"):
            s = s.replace(o, n)
        else:
            s = s.replace(o, n, 1)
    return s


def plain_spec(spec):
    """A registry version range (`^1.2.3`, `~5`, `>=2 <3`, `latest`), no URL/git/file/alias."""
    return isinstance(spec, str) and not re.search(r"[:/#\\@]", spec)


def flat(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                for item in flat(v, prefix + k + ">"):
                    yield item
            else:
                yield prefix + k, v
    elif isinstance(obj, list):
        for v in obj:
            yield prefix + str(v), True


def json_dep_changes(old, new, keys, extra_keys):
    try:
        o = json.loads(old) if old.strip() else {}
        n = json.loads(new)
    except ValueError:
        return ["file is not valid JSON"]
    if not isinstance(o, dict) or not isinstance(n, dict):
        return ["unerwartete Struktur"]
    found = []
    for k in keys:
        od, nd = dict(flat(o.get(k))), dict(flat(n.get(k)))
        for name, spec in nd.items():
            if name not in od:
                found.append(f"new: {name}")
            elif spec != od[name] and not plain_spec(spec):
                found.append(f"{name} -> {spec}")
    for k in extra_keys:
        if o.get(k) != n.get(k):
            found.append(f"{k} changed")
    return found


def req_entries(text):
    out = {}
    for line in text.splitlines():
        s = line.split(" #", 1)[0].strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("-"):
            out[s] = s
            continue
        m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", s)
        key = re.sub(r"[-_.]+", "-", m.group(0)).lower() if m else s
        out[key] = s
    return out


def req_changes(old, new):
    o, n = req_entries(old), req_entries(new)
    found = []
    for k, line in n.items():
        if k not in o:
            found.append(f"new: {line}")
        elif line != o[k] and re.search(r"(://|@|git\+|--)", line):
            found.append(f"changed: {line}")
    return found


def pyproject_dep_lines(text):
    lines, section, depth = set(), "", 0
    arr = re.compile(r'^[A-Za-z0-9_."-]*(dependencies|requires|requirements|dev)'
                     r'[A-Za-z0-9_."-]*\s*=\s*\[')
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if depth == 0 and s.startswith("["):
            section = s.strip("[]").strip()
            continue
        dep_section = any(x in section for x in ("dependencies", "dependency-groups",
                                                 "build-system", "requires")) \
            or section.startswith(("tool.uv", "tool.poetry.source", "tool.pdm"))
        if depth == 0 and arr.match(s):
            depth = s.count("[") - s.count("]")
            lines.add((section, s))
            continue
        if depth > 0:
            depth += s.count("[") - s.count("]")
            lines.add((section, s))
            continue
        if dep_section:
            lines.add((section, s))
    return lines


def check_file_edit(tool, inp):
    path = inp.get("file_path") or inp.get("notebook_path") or ""
    base = os.path.basename(path)
    if not base:
        return
    if base in LOCKFILES:
        ask(f"Package protection: edit {base} directly? Change lockfiles only through the package manager.")
        return
    if base in PM_CONFIG:
        ask(f"Package protection: {base} is a package configuration (registry, scripts, release age). "
            f"Please check.")
        return
    if base in ALWAYS_ASK:
        ask(f"Package protection: {base} pins dependencies. Please check.")
        return
    if base not in ("package.json", "composer.json", "pyproject.toml") \
            and not REQ_FILE.match(base):
        return
    old = read_text(path)
    new = new_content(tool, inp, old)
    if base == "package.json":
        found = json_dep_changes(old, new, NPM_DEP_KEYS,
                                 ("allowScripts", "packageManager", "devEngines"))
    elif base == "composer.json":
        found = json_dep_changes(old, new, COMPOSER_DEP_KEYS,
                                 ("repositories", "minimum-stability"))
        try:
            o = (json.loads(old) if old.strip() else {}).get("config", {}) or {}
            n = json.loads(new).get("config", {}) or {}
            for key in COMPOSER_PROTECTED_CONFIG:
                if o.get(key) != n.get(key):
                    found.append(f"config.{key} changed")
        except (ValueError, AttributeError):
            pass
    elif base == "pyproject.toml":
        added = pyproject_dep_lines(new) - pyproject_dep_lines(old)
        found = [f"{sec or '?'}: {line}" for sec, line in sorted(added)]
    else:
        found = req_changes(old, new)
    if found:
        shown = "; ".join(found[:5]) + (" …" if len(found) > 5 else "")
        ask(f"Package protection: dependencies in {base} changed ({shown}). "
            f"New packages only after /dep-check and your decision.")


# --------------------------------------------------------- project settings --
# Folders outside the project are opened centrally in ~/.claude/settings.json
# (additionalDirectories). A project's own .claude/settings*.json that opens a folder outside
# the project (additionalDirectories, sandbox allowRead / allowWrite) triggers a question on
# edit and a warning at session start. Claude Code ignores such entries from settings.json
# under blockReadsOutsideWorkingDirectories, but honors them from an untracked
# settings.local.json for the file tools.
SETTINGS_FILES = ("settings.json", "settings.local.json")
SETTINGS_RE = r"\.claude/settings(\.local)?\.json"


def is_settings_file(path):
    return os.path.basename(path) in SETTINGS_FILES \
        and os.path.basename(os.path.dirname(path)) == ".claude"


def within(p, base):
    return p == base or p.startswith(base.rstrip("/") + "/")


def opened_dirs(obj):
    """Directory entries in a settings object that widen the read/write boundary."""
    out = []
    if not isinstance(obj, dict):
        return out
    perm = obj.get("permissions") if isinstance(obj.get("permissions"), dict) else {}
    sandbox = obj.get("sandbox") if isinstance(obj.get("sandbox"), dict) else {}
    fs = sandbox.get("filesystem") if isinstance(sandbox.get("filesystem"), dict) else {}
    for v in (perm.get("additionalDirectories"), fs.get("allowRead"), fs.get("allowWrite")):
        if isinstance(v, list):
            out.extend(v)
        elif v is not None:
            out.append(v)
    return out


def resolve_dir(entry, root):
    """Absolute real path of a settings entry, None if it cannot be pinned down."""
    if not isinstance(entry, str) or not entry.strip():
        return None
    p = entry.strip()
    if p.startswith("//"):
        p = p[1:]
    p = re.sub(r"(/\*\*?)+/?$", "", p) or "/"
    if re.search(r"[*?\[\]{}$`]", p):
        return None
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(root, p)
    return os.path.realpath(p)


def outside_dirs(obj, root):
    """Entries that open something outside the own project (root holds .claude/)."""
    root_r = os.path.realpath(root)
    bad = []
    for e in opened_dirs(obj):
        r = resolve_dir(e, root_r)
        if r is None or not within(r, root_r):
            bad.append(str(e))
    return bad


# Claude's own user settings. allowManagedPermissionRulesOnly drops permission rules from
# them, but not the rest: autoMode (an allow entry there can lift a managed soft_deny in
# the classifier), hooks, env, apiKeyHelper. The sandbox keeps shell writes out; for the
# file tools this hook is the only check, so every change asks, whatever it contains.
def user_config_dirs():
    dirs = [os.path.expanduser("~/.claude")]
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        dirs.append(os.path.expanduser(os.environ["CLAUDE_CONFIG_DIR"]))
    return {os.path.realpath(d) for d in dirs}


def user_settings_files():
    return [os.path.join(d, n) for d in sorted(user_config_dirs()) for n in SETTINGS_FILES]


def is_user_settings(path):
    """True for ~/.claude/settings(.local).json, also via a symlinked file or folder."""
    if not path:
        return False
    p = os.path.abspath(os.path.expanduser(path))
    dirs = user_config_dirs()
    for q in (p, os.path.realpath(p)):
        if os.path.basename(q) in SETTINGS_FILES \
                and os.path.realpath(os.path.dirname(q)) in dirs:
            return True
    return False


def check_settings_edit(tool, inp):
    path = inp.get("file_path") or ""
    if is_user_settings(path):
        ask(f"Claude Code user settings ({path}): they apply to every session, and the "
            "managed lock covers only permission rules, not autoMode, hooks or env. "
            "Please check the change.", "user-settings")
        return
    if not is_settings_file(path):
        return
    root = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    old = read_text(path)
    new = new_content(tool, inp, old)
    try:
        o = json.loads(old) if old.strip() else {}
    except ValueError:
        o = {}
    try:
        n = json.loads(new) if new.strip() else {}
    except ValueError:
        ask(f"{path}: not valid JSON after the change, opened folders cannot be checked.")
        return
    before = set(outside_dirs(o, root))
    added = [e for e in outside_dirs(n, root) if e not in before]
    if added:
        ask(f"Project setting opens folders outside the project: "
            f"{', '.join(added[:5])}. Please check.")


# Claude Code merges every *.json in this directory into the managed settings, with the
# later file winning for single values and without the checks build.py makes (section
# 21.7). The installer refuses to run while it exists; this catches one added later.
MANAGED_DROPIN_DIR = "/Library/Application Support/ClaudeCode/managed-settings.d"


def session_start(data):
    """Warn when managed-settings.d exists, and when project settings (cwd and its
    parents, up to but not including ~) open outside folders."""
    msgs = []
    if os.path.exists(MANAGED_DROPIN_DIR):
        msgs.append(f"{MANAGED_DROPIN_DIR} exists. Claude Code merges the files in it into "
                    "the managed settings, bypassing policy.json and build.py; single values "
                    "can loosen the locks. Please check and remove it (docs/design-notes.md, 9).")
    home = os.path.realpath(os.path.expanduser("~"))
    d = os.path.realpath(data.get("cwd") or os.getcwd())
    found = []
    while d != home and d != "/":
        for name in SETTINGS_FILES:
            p = os.path.join(d, ".claude", name)
            if not os.path.isfile(p):
                continue
            try:
                obj = json.loads(read_text(p) or "{}")
            except ValueError:
                found.append(f"{p} (not valid JSON, cannot be checked)")
                continue
            bad = outside_dirs(obj, d)
            if bad:
                found.append(f"{p}: {', '.join(bad[:5])}")
        d = os.path.dirname(d)
    if found:
        msgs.append("Project settings open folders outside the project: "
                    + " | ".join(found))
    problem = start_folder_problem(data)
    if problem:
        msgs.append(f"Shell commands are blocked in this session: {problem}. Start Claude "
                    "Code in a project folder, or add this folder to working_directories "
                    "(docs/design-notes.md, 12).")
    auto = user_auto_mode_entries()
    if auto:
        msgs.append("User settings add their own auto-mode rules: " + " | ".join(auto)
                    + ". The managed lock does not cover them; an allow entry can lift a "
                    "managed soft_deny. Please check they are yours (docs/design-notes.md, 11).")
    if msgs:
        session_warn(" ".join(msgs))


def user_auto_mode_entries():
    """Per user settings file, the autoMode keys with entries of their own ("$defaults"
    alone does not count): e.g. '~/.claude/settings.json: allow 1, soft_deny 2'."""
    out = []
    for p in user_settings_files():
        if not os.path.isfile(p):
            continue
        try:
            obj = json.loads(read_text(p) or "{}")
        except ValueError:
            out.append(f"{p} (not valid JSON, cannot be checked)")
            continue
        am = obj.get("autoMode") if isinstance(obj, dict) else None
        if am is None:
            continue
        if not isinstance(am, dict):
            out.append(f"{p}: autoMode ({type(am).__name__})")
            continue
        parts = []
        for k, v in sorted(am.items()):
            if isinstance(v, list):
                n = len([e for e in v if e != "$defaults"])
                if n or "$defaults" not in v:
                    parts.append(f"{k} {n}")
            else:
                parts.append(f"{k}={json.dumps(v)}")
        if parts:
            out.append(f"{p}: {', '.join(parts)}")
    return out


def session_warn(msg):
    print(json.dumps({
        "systemMessage": "Security hook: " + msg,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "Security hook: " + msg + " Point this out to the user at the start "
                                 "and rely on the settings named here only after they confirm.",
        },
    }))


# ----------------------------------------------------------------- webfetch --

def check_webfetch(url):
    host = (urlsplit(url).hostname or "").lower()
    if host in WEBFETCH_FREE or host.endswith(WEBFETCH_FREE_SUFFIXES) \
            or "." + host in WEBFETCH_FREE_SUFFIXES:
        return
    ask(f"WebFetch to {host or url}: not on the documentation list.")


EVENT = ["PreToolUse"]

# Tools that run shell commands. Monitor waits for a condition and runs a command to do
# so, so it needs the same check as Bash; PowerShell is listed in case it is ever enabled.
SHELL_TOOLS = ("Bash", "Monitor", "PowerShell", "BashOutput")


def shell_command(inp):
    """The shell command in a tool input. Monitor carries more than one field (command
    and the condition it waits on), and the field names are not fixed, so every string
    in the input is checked. An extra field can only cause a question, never silence."""
    if "command" in inp and isinstance(inp["command"], str) and len(inp) == 1:
        return inp["command"]
    parts = [v for k, v in sorted(inp.items())
             if isinstance(v, str) and k not in ("description", "label", "reason", "title")]
    return "\n".join(parts)


def main():
    data = json.load(sys.stdin)
    apply_policy(load_policy(sys.argv[1:])[0])
    if data.get("hook_event_name") == "SessionStart":
        EVENT[0] = "SessionStart"
        session_start(data)
        return
    apply_start_folder(data)
    tool = data.get("tool_name")
    inp = data.get("tool_input") or {}
    logged = ""
    if tool in SHELL_TOOLS:
        logged = shell_command(inp)
        check_start_folder(data)
        check_bash(logged, data.get("cwd") or "")
    elif tool == "WebFetch":
        logged = inp.get("url", "")
        check_webfetch(logged)
    elif tool in ("Read", "Grep", "Glob", "NotebookRead", "LS"):
        logged = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
        if tool == "Glob":
            logged = (inp.get("path") or "") + " " + (inp.get("pattern") or "")
        check_file_read(tool, inp, data.get("cwd") or "")
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        logged = inp.get("file_path") or inp.get("notebook_path") or ""
        check_file_edit(tool, inp)
        check_settings_edit(tool, inp)
    emit(tool, logged)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # fail closed: ask rather than allow
        if EVENT[0] == "SessionStart":
            session_warn(f"Project settings cannot be checked ({type(e).__name__}).")
            sys.exit(0)
        ASKS[:] = [("hook-fehler",
                    f"Security hook could not check the call ({type(e).__name__}).")]
        DENIES[:] = []
        emit("?", "")
