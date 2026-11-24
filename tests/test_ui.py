"""Tests for the optional configuration UI server (ui/server.py, docs/config-ui.md): who may
call it, what it serves, and that it writes only the two layer files, through build.py.

Run: /usr/bin/python3 -I tests/test_ui.py
"""
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build = load("build", os.path.join(ROOT, "build.py"))
ui = load("guardrails_ui", os.path.join(ROOT, "ui", "server.py"))

verbose = "-v" in sys.argv
fails = total = 0


def check(label, ok, detail=""):
    global fails, total
    total += 1
    fails += not ok
    if verbose or not ok:
        print(f"{'ok  ' if ok else 'FAIL'} {label}" + (f"\n     {detail}" if not ok and detail else ""))


TMP = tempfile.mkdtemp(prefix="uitest-")
CONF = os.path.join(TMP, "conf")
# build.py builds with the layer of this machine, so the folder uses its host name
MACHINE = socket.gethostname().split(".")[0]
build.init(CONF, "example", host=MACHINE)
ORG_PATH = os.path.join(CONF, "org.json")
LOCAL_NAME = "local.{}.json".format(MACHINE)
LOCAL_PATH = os.path.join(CONF, LOCAL_NAME)

httpd, app = ui.make_server(build, CONF, quiet=True)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
PORT = app.port
HOST = "127.0.0.1:{}".format(PORT)


def call(method, path, body=None, token=True, headers=None, raw=None):
    """(status, headers, parsed JSON or bytes)."""
    h = {"Host": HOST}
    if token:
        h[ui.TOKEN_HEADER] = app.token if token is True else token
    data = raw
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in h.items():
        c.putheader(k, v)
    if data is not None:
        c.putheader("Content-Length", str(len(data)))
    c.endheaders()
    if data is not None:
        c.send(data)
    r = c.getresponse()
    payload = r.read()
    out = payload
    if r.getheader("Content-Type", "").startswith("application/json"):
        out = json.loads(payload.decode("utf-8"))
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, hdrs, out


def snapshot():
    return {n: open(os.path.join(CONF, n), "rb").read() for n in sorted(os.listdir(CONF))
            if os.path.isfile(os.path.join(CONF, n))}


# --- binding --------------------------------------------------------------------
check("bound to 127.0.0.1 only", httpd.server_address[0] == "127.0.0.1")
check("random port", PORT > 1024)
check("token is long and random", len(app.token) >= 40)

# --- token ----------------------------------------------------------------------
s, _, b = call("GET", "/api/state")
check("with token: state answers", s == 200 and b["folder"] == os.path.abspath(CONF), str(b))
s, _, _ = call("GET", "/api/state", token=False)
check("without token: 403", s == 403)
s, _, _ = call("GET", "/api/state", token="x" * len(app.token))
check("wrong token: 403", s == 403)
s, _, _ = call("GET", "/api/state?token=" + app.token, token=False)
check("token in the query string does not count", s == 403)
s, _, _ = call("GET", "/index.html", token=False)
check("static files need no token (they are product code, not data)", s == 200)

# --- Host and Origin --------------------------------------------------------------
for host in ("evil.example:{}".format(PORT), "127.0.0.1", "127.0.0.1:1", "localhost.evil:{}".format(PORT), ""):
    s, _, _ = call("GET", "/api/state", headers={"Host": host})
    check("Host {!r} refused (DNS rebinding)".format(host), s == 403)
    s, _, _ = call("GET", "/index.html", token=False, headers={"Host": host})
    check("Host {!r} refused for static files too".format(host), s == 403)
s, _, _ = call("GET", "/api/state", headers={"Host": "localhost:{}".format(PORT)})
check("Host localhost:<port> accepted", s == 200)
for origin in ("http://evil.example", "http://127.0.0.1:1", "null", "https://127.0.0.1:{}".format(PORT)):
    s, _, _ = call("POST", "/api/check", {}, headers={"Origin": origin})
    check("Origin {!r} refused".format(origin), s == 403)
s, _, _ = call("GET", "/api/state", headers={"Origin": "http://127.0.0.1:{}".format(PORT)})
check("own Origin accepted", s == 200)
for site in ("cross-site", "same-site"):
    s, _, _ = call("GET", "/api/state", headers={"Sec-Fetch-Site": site})
    check("Sec-Fetch-Site {} refused".format(site), s == 403)
s, _, _ = call("POST", "/api/check", raw=b"{}", headers={"Content-Type": "text/plain"})
check("POST without application/json refused (no form posts)", s == 415)
s, _, _ = call("POST", "/api/check", headers={"Content-Type": "application/json",
                                             "Content-Length": str(ui.MAX_BODY + 1)})
check("oversized body refused before it is read", s == 413)

# --- headers ----------------------------------------------------------------------
EXPECT_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
              "connect-src 'self'; frame-ancestors 'none'")
for path, tok in (("/", False), ("/app.js", False), ("/api/state", True), ("/nope", False)):
    s, hd, _ = call("GET", path, token=tok)
    csp = hd.get("content-security-policy", "")
    check("CSP on {} ({})".format(path, s), csp.startswith(EXPECT_CSP), csp)
    check("no unsafe-eval or unsafe-inline on {}".format(path), "unsafe" not in csp)
    check("nosniff, no-store, DENY on {}".format(path), hd.get("x-content-type-options") == "nosniff"
          and hd.get("cache-control") == "no-store" and hd.get("x-frame-options") == "DENY")
s, hd, _ = call("GET", "/")
check("server header does not name the Python version", "Python" not in hd.get("server", ""))

# --- static files: only ui/, nothing else -----------------------------------------
s, hd, body = call("GET", "/", token=False)
check("/ serves index.html", s == 200 and b"app.js" in body and hd["content-type"].startswith("text/html"))
check("no inline script in index.html", not re.search(rb"<script(?![^>]*\bsrc=)[^>]*>", body))
check("no external resource in index.html", not re.search(rb"(src|href)=\"(https?:)?//", body))
for path in ("/server.py", "/../build.py", "/%2e%2e/build.py", "/..%2fbuild.py", "/vendor/../../build.py",
             "//etc/passwd", "/vendor/VENDOR.md", "/vendor/vue.LICENSE", "/../baseline.json",
             "/ui/app.js", "/.DS_Store", "/__pycache__/server.cpython-39.pyc"):
    s, _, body = call("GET", path, token=False)
    check("not served: {}".format(path), s == 404, str(s))
s, _, body = call("GET", "/vendor/vue.runtime.global.prod.js", token=False)
check("vendored Vue served", s == 200 and body.startswith(b"/**\n* vue v3."))
for name in ("app.js", "style.css", "index.html"):
    text = open(os.path.join(ROOT, "ui", name), encoding="utf-8").read()
    check("{} loads nothing from outside".format(name),
          not re.search(r"https?://(?!127\.0\.0\.1[:/])", text), name)

# --- vendor hash ------------------------------------------------------------------
vendor = open(os.path.join(ROOT, "ui", "vendor", "VENDOR.md"), encoding="utf-8").read()
m = re.search(r"SHA-256: ([0-9a-f]{64})", vendor)
vue = open(os.path.join(ROOT, "ui", "vendor", "vue.runtime.global.prod.js"), "rb").read()
check("vendored Vue matches the SHA-256 in VENDOR.md",
      m is not None and hashlib.sha256(vue).hexdigest() == m.group(1))
check("vendored Vue is the runtime build (no eval, no new Function)",
      b"eval(" not in vue and b"new Function" not in vue)
check("app.js uses no templates (render functions only)",
      not re.search(r"\btemplate\s*:\s*[\"'`#]", open(os.path.join(ROOT, "ui", "app.js"), encoding="utf-8").read()))

# --- describe, layers, check: build.py's own answers ------------------------------
s, _, d = call("GET", "/api/describe")
check("describe is build.py --describe", s == 200 and d == json.loads(json.dumps(build.describe())))
s, _, ls = call("GET", "/api/layers")
files = ls["files"]
check("layers lists org.json and the machine layer",
      sorted(files) == [LOCAL_NAME, "org.json"])
check("layers carry the text and its hash",
      files["org.json"]["text"] == open(ORG_PATH, encoding="utf-8").read()
      and files["org.json"]["sha256"] == hashlib.sha256(open(ORG_PATH, "rb").read()).hexdigest())
ORG = files["org.json"]["layer"]
LOCAL = files[LOCAL_NAME]["layer"]
s, _, c = call("POST", "/api/check", {"org": ORG, "local": LOCAL, "local_name": LOCAL_NAME})
check("check: example layers build", s == 200 and c["ok"] and c["policy"]["organization"]["name"]
      == ORG["set"]["organization.name"], str(c.get("error")))
bad = json.loads(json.dumps(ORG))
bad["set"]["logging.max_bytes"] = "big"
s, _, c = call("POST", "/api/check", {"org": bad, "local": LOCAL, "local_name": LOCAL_NAME})
check("check: build.py's message, unchanged, with file and path", s == 200 and not c["ok"]
      and c["error"].startswith("org.json: set logging.max_bytes:") and c["file"] == "org.json"
      and c["paths"] == ["logging.max_bytes"], str(c))
check("check: no temporary folder in the message", TMP not in c["error"] and "guardrails-ui-" not in c["error"])
s, _, c = call("POST", "/api/check", {"org": ORG, "local": LOCAL, "local_name": "../x.json"})
check("check: machine layer name must be local.<host>.json", s == 400)

# --- writes: only the two layer files, only after a check -------------------------
before = snapshot()
for name in ("baseline.json", "policy.json", "managed-settings.json", "product-version", "../org.json",
             "..%2forg.json", "local.json", "local.a.b.json", "org.json.bak", "test_x.py"):
    s, _, _ = call("PUT", "/api/layers/" + name, {"layer": ORG, "sha256": None})
    check("PUT {} refused".format(name), s in (403, 404), str(s))
check("refused PUTs wrote nothing", snapshot() == before)
check("nothing outside the folder appeared", sorted(os.listdir(TMP)) == ["conf"])
s, _, _ = call("POST", "/api/layers/org.json", {"layer": ORG})
check("POST to a layer is not a write", s == 404 and snapshot() == before)

sha_org = files["org.json"]["sha256"]
s, _, r = call("PUT", "/api/layers/org.json", {"layer": ORG, "sha256": sha_org})
check("round trip without changes: nothing written", s == 200 and r["written"] is False)
check("round trip is byte-identical", snapshot() == before)

# a file written by hand with another indent stays untouched when nothing changed
hand = json.dumps(LOCAL, indent=4) + "\n"
with open(LOCAL_PATH, "w", encoding="utf-8") as f:
    f.write(hand)
s, _, ls = call("GET", "/api/layers")
s, _, r = call("PUT", "/api/layers/" + LOCAL_NAME,
               {"layer": ls["files"][LOCAL_NAME]["layer"],
                "sha256": ls["files"][LOCAL_NAME]["sha256"]})
check("unchanged hand-formatted layer is not rewritten",
      s == 200 and not r["written"] and open(LOCAL_PATH, encoding="utf-8").read() == hand)
sha_local = ls["files"][LOCAL_NAME]["sha256"]

s, _, r = call("PUT", "/api/layers/org.json", {"layer": bad, "sha256": sha_org})
check("a layer build.py refuses is not written", s == 422 and r["check"]["paths"] == ["logging.max_bytes"]
      and open(ORG_PATH, "rb").read() == before["org.json"], str(r))

changed = json.loads(json.dumps(ORG))
changed["set"]["organization.description"] = "changed by the test"
s, _, r = call("PUT", "/api/layers/org.json", {"layer": changed, "sha256": "0" * 64})
check("stale hash: 409, nothing written", s == 409 and open(ORG_PATH, "rb").read() == before["org.json"])
s, _, r = call("PUT", "/api/layers/org.json", {"layer": changed, "sha256": sha_org})
text = open(ORG_PATH, encoding="utf-8").read()
check("a valid change is written in build.py's layer format",
      s == 200 and r["written"] and text == build.layer_text(changed), str(r))
check("key order kept", list(json.loads(text)) == list(ORG) and list(json.loads(text)["set"]) == list(ORG["set"]))
check("returned hash is the file's", r.get("sha256") == hashlib.sha256(text.encode("utf-8")).hexdigest())
check("no temporary file left", not [n for n in os.listdir(CONF) if n.endswith(".tmp")])

# org.json is checked against the machine layers on disk
ex = {"id": "personal.app-audit", "action": "off", "reason": "t", "expires": "2099-01-01"}
local2 = json.loads(json.dumps(LOCAL))
local2["exceptions"] = local2.get("exceptions", []) + [ex]
s, _, r = call("PUT", "/api/layers/" + LOCAL_NAME, {"layer": local2, "sha256": sha_local})
check("machine layer that refers to an org pattern is accepted", s == 200 and r["written"], str(r))
no_pattern = json.loads(text)
no_pattern.pop("tighten")
s, _, r = call("PUT", "/api/layers/org.json", {"layer": no_pattern, "sha256": hashlib.sha256(text.encode()).hexdigest()})
check("org.json that would break a machine layer on disk is refused",
      s == 422 and "personal.app-audit" in r["error"], str(r))

# a new machine layer may be created, an existing one not overwritten blindly
new = {"layer_format": 1, "requires_baseline": d["requires_baseline"]}
s, _, r = call("PUT", "/api/layers/local.other.json", {"layer": new, "sha256": None})
check("new machine layer created", s == 200 and r["written"] and os.path.exists(os.path.join(CONF, "local.other.json")))
s, _, r = call("PUT", "/api/layers/local.other.json", {"layer": new, "sha256": None})
check("existing file without its hash: 409", s == 409)

# a symbolic link in the folder is never written through
target = os.path.join(TMP, "outside.json")
with open(target, "w") as f:
    f.write("{}")
os.symlink(target, os.path.join(CONF, "local.link.json"))
s, _, r = call("PUT", "/api/layers/local.link.json", {"layer": new, "sha256": hashlib.sha256(b"{}").hexdigest()})
check("symbolic link not written through", s == 403 and open(target).read() == "{}")
os.remove(os.path.join(CONF, "local.link.json"))
os.remove(target)

# --- folder: fixed by --config ------------------------------------------------------
s, _, r = call("POST", "/api/folder", {"path": TMP})
check("folder fixed by --config cannot be changed", s == 409)
s, _, r = call("POST", "/api/init", {"path": os.path.join(TMP, "x"), "template": "empty"})
check("init elsewhere refused when fixed", s == 409 and not os.path.exists(os.path.join(TMP, "x")))
s, _, r = call("POST", "/api/init", {"template": "empty", "host": MACHINE})
check("init into the folder refuses to overwrite", s == 422 and "already present" in r["error"])

# --- migrate and build run build.py ------------------------------------------------
s, _, r = call("GET", "/api/migrate")
check("migrate dry run: current", s == 200 and r["code"] == 0 and "is current" in r["output"], str(r))
s, _, r = call("POST", "/api/migrate", {})
check("migrate --write needs confirm", s == 400)
before = snapshot()
s, _, r = call("POST", "/api/build", {"write": False})
check("diff first, writes nothing", s == 200 and r["code"] == 1 and "+++ policy.json" in r["output"]
      and snapshot() == before, str(r)[:300])
s, _, r = call("POST", "/api/build", {"write": True})
check("build writes the generated files", s == 200 and r["code"] == 0
      and os.path.exists(os.path.join(CONF, "managed-settings.json")), str(r)[:300])
check("after the build: the install command to copy, not run",
      r.get("install", "").endswith("./install.sh --config " + os.path.abspath(CONF)))
s, _, r = call("POST", "/api/build", {"write": False})
check("diff after the build is empty", r["code"] == 0)

# --- a layer the product cannot read is shown with build.py's message only ----------
with open(os.path.join(CONF, "local.future.json"), "w", encoding="utf-8") as f:
    f.write(build.layer_text({"layer_format": build.LAYER_FORMAT + 1, "requires_baseline": ">=1.0 <2"}))
with open(os.path.join(CONF, "local.old.json"), "w", encoding="utf-8") as f:
    f.write(build.layer_text({"requires_baseline": ">=0.1 <1"}))
s, _, ls = call("GET", "/api/layers")
fut, old = ls["files"]["local.future.json"], ls["files"]["local.old.json"]
check("newer layer_format: build.py's message, no layer", fut["layer"] is None
      and "newer than this product" in fut["error"])
check("outside requires_baseline: build.py's message, no layer", old["layer"] is None
      and "requires baseline" in old["error"])

# --- an unfixed server: choose the folder, init a new one ---------------------------
httpd.shutdown()
httpd.server_close()
httpd, app = ui.make_server(build, None, quiet=True)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
PORT, HOST = app.port, "127.0.0.1:{}".format(app.port)
s, _, r = call("GET", "/api/layers")
check("no folder yet: 409", s == 409)
s, _, r = call("POST", "/api/folder", {"path": os.path.join(TMP, "missing")})
check("missing folder refused", s == 404)
NEW = os.path.join(TMP, "fresh")
s, _, r = call("POST", "/api/init", {"path": NEW, "template": "empty", "host": "box"})
check("init writes org.json and local.box.json", s == 200 and r["folder"] == NEW
      and sorted(os.listdir(NEW)) == ["local.box.json", "org.json"], str(r))
s, _, r = call("POST", "/api/init", {"path": NEW, "template": "fancy"})
check("init with an unknown template: build.py's message", s == 422 and "unknown" in r["error"])
s, _, r = call("POST", "/api/folder", {"path": CONF})
check("another folder can be opened", s == 200 and r["folder"] == os.path.abspath(CONF))

httpd.shutdown()
httpd.server_close()
shutil.rmtree(TMP)
print(f"{total} UI checks, FAILURES: {fails}")
sys.exit(1 if fails else 0)
