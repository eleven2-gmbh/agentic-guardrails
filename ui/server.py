"""The optional configuration UI (docs/config-ui.md), started by ./build.py --ui.

Everything it does is a build.py call that also works in the terminal: the forms come
from describe(), every change is checked by effective(), and --diff, the build and
--migrate run build.py itself, so the UI shows build.py's messages as they are. It never
runs install.sh or sudo, and writes only org.json and local.<host>.json.

Security: bound to 127.0.0.1 on a random port; a random token in the start URL's
fragment (never sent in a request line, so never in a log) that the page sends as a
header on every API call; Host, Origin and Sec-Fetch-Site checked against DNS rebinding
and cross-site requests; a strict Content-Security-Policy; only the files in ui/ that
were there at start are served.

Standard library only, /usr/bin/python3 (3.9).
"""
import contextlib
import copy
import datetime
import hashlib
import hmac
import http.server
import io
import json
import os
import re
import secrets
import shlex
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import traceback
import urllib.parse

UI = os.path.dirname(os.path.abspath(__file__))
TOKEN_HEADER = "X-Guardrails-Token"
MAX_BODY = 1 << 20
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
# The two files the UI may write; the same names build.py's layer_files() reads.
LAYER_NAME = re.compile(r"^(org|local\.[A-Za-z0-9-]+)\.json$")


class UIError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status


def sha256(text):
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def static_files():
    """URL path -> file for every servable file in ui/ at start. A fixed map, so no
    request path can reach anything else (no traversal, no server.py)."""
    out = {}
    for d, dirs, files in os.walk(UI):
        dirs[:] = [x for x in dirs if not x.startswith(".") and x != "__pycache__"]
        for f in files:
            if f.startswith(".") or os.path.splitext(f)[1] not in STATIC_TYPES:
                continue
            full = os.path.join(d, f)
            if os.path.islink(full):
                continue
            out["/" + os.path.relpath(full, UI).replace(os.sep, "/")] = full
    out["/"] = out.get("/index.html")
    return out


class App:
    def __init__(self, build, folder=None):
        self.build = build
        self.fixed = folder is not None
        self.folder = os.path.abspath(os.path.expanduser(folder)) if folder else None
        if self.folder and not os.path.isdir(self.folder):
            raise build.LayerError("--config: {} is not a folder".format(self.folder))
        self.token = secrets.token_urlsafe(32)
        self.host = socket.gethostname().split(".")[0]
        self.port = None
        self.static = static_files()
        self.lock = threading.Lock()  # build.py keeps module state; one API call at a time

    # ------------------------------------------------------------ helpers --
    def need_folder(self):
        if not self.folder:
            raise UIError(409, "No configuration folder chosen yet")
        return self.folder

    def layer_names(self):
        return sorted(n for n in os.listdir(self.need_folder()) if LAYER_NAME.match(n))

    def run_build(self, args):
        """build.py itself, so the output is exactly what the terminal shows."""
        cmd = [sys.executable, "-I", os.path.join(self.build.HERE, "build.py"),
               "--config", self.need_folder()] + args
        r = subprocess.run(cmd, cwd=self.build.HERE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
        return {"code": r.returncode, "output": r.stdout + r.stderr,
                "command": "./build.py " + " ".join(shlex.quote(a) for a in cmd[3:])}

    def git(self, *args):
        try:
            r = subprocess.run(["git", "-C", self.build.HERE] + list(args),
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        return r.stdout.strip() if r.returncode == 0 else None

    def install_command(self):
        return "cd {} && ./install.sh --config {}".format(
            shlex.quote(self.build.HERE), shlex.quote(self.need_folder()))

    def known_paths(self):
        d = self.build.describe()
        return set(d["set"]) | set(d["add"]) | set(d["tighten"]) | \
            set(d["exceptions"]["off"]) | set(d["exceptions"]["set"])

    def where(self, message):
        """The file and the layer paths or ids a build.py message names, so the page can
        show it next to the field. The message itself stays as build.py wrote it."""
        m = re.match(r"^(org\.json|local\.[A-Za-z0-9-]+\.json):", message)
        paths = [p for p in self.known_paths()
                 if re.search(r"(?<![\w.:~/*-])" + re.escape(p) + r"(?![\w.-])", message)]
        return (m.group(1) if m else None), sorted(paths, key=len, reverse=True)

    def merge(self, org, local, local_name):
        """effective() over two layers in a temporary folder: (policy, None, notes) or
        (None, error, notes)."""
        if not LAYER_NAME.match(local_name or "") or not local_name.startswith("local."):
            raise UIError(400, "machine layer name must be local.<host>.json")
        with tempfile.TemporaryDirectory(prefix="guardrails-ui-") as d:
            paths = []
            for name, layer in (("org.json", org), (local_name, local)):
                p = os.path.join(d, name)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(self.build.layer_text(layer))
                paths.append(p)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    policy = self.build.effective(paths[0], paths[1])
                error = None
            except self.build.LayerError as e:
                policy, error = None, str(e)
            prefix = d + os.sep
            notes = [x.replace(prefix, "") for x in err.getvalue().splitlines() if x]
            return policy, error and error.replace(prefix, ""), notes

    def check_result(self, org, local, local_name):
        policy, error, notes = self.merge(org, local, local_name)
        out = {"ok": error is None, "error": error, "notes": notes, "file": None, "paths": []}
        if error:
            out["file"], out["paths"] = self.where(error)
        else:
            out["policy"] = policy
        return out

    def blocking(self, name, text):
        """build.py's message when a layer cannot be edited here at all: not JSON, a newer
        layer_format, or a baseline outside its requires_baseline."""
        b = self.build
        try:
            layer = json.loads(text)
        except ValueError as e:
            return "{}: not valid JSON ({})".format(name, e)
        try:
            base, policy = b.load_baseline()
            layer, _ = b.migrate_layer(layer, *b.renames(base), name=name)
            b.apply_layer(copy.deepcopy(policy), {"requires_baseline":
                                                  layer.get("requires_baseline")},
                          name, set(), datetime.date.today(), [])
        except b.LayerError as e:
            return str(e)
        return None

    # --------------------------------------------------------------- calls --
    def state(self):
        out = {"product": self.build.HERE, "folder": self.folder, "fixed": self.fixed,
               "host": self.host, "machine": "local.{}.json".format(self.host),
               "layers": [], "product_version": None, "install": None}
        tags = self.git("tag", "--points-at", "HEAD")
        status = self.git("status", "--porcelain")
        out["checkout"] = None if tags is None else {
            "describe": self.git("describe", "--tags", "--always"),
            "tags": tags.split(), "clean": status == ""}
        if self.folder:
            out["layers"] = self.layer_names()
            pin = read_text(os.path.join(self.folder, "product-version"))
            out["product_version"] = pin.strip() if pin is not None else None
            out["install"] = self.install_command()
        c, pin = out["checkout"], out["product_version"]
        out["matches"] = None if not pin or not c else (pin in c["tags"] and c["clean"])
        return out

    def set_folder(self, body):
        path = body.get("path") if isinstance(body, dict) else None
        if not isinstance(path, str) or not path.strip():
            raise UIError(400, "path missing")
        path = os.path.abspath(os.path.expanduser(path.strip()))
        if self.fixed and path != self.folder:
            raise UIError(409, "Started with --config {}; restart ./build.py --ui to use "
                               "another folder".format(self.folder))
        if not os.path.isdir(path):
            raise UIError(404, "{} is not a folder".format(path))
        self.folder = path
        return self.state()

    def init(self, body):
        body = body if isinstance(body, dict) else {}
        path = body.get("path") or self.folder
        if not isinstance(path, str) or not path.strip():
            raise UIError(400, "path missing")
        path = os.path.abspath(os.path.expanduser(path.strip()))
        if self.fixed and path != self.folder:
            raise UIError(409, "Started with --config {}".format(self.folder))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            written = self.build.init(path, body.get("template") or "empty",
                                      body.get("host") or None)
        self.folder = path
        out = self.state()
        out["written"] = written
        return out

    def layers(self):
        folder = self.need_folder()
        files = {}
        for name in self.layer_names():
            text = read_text(os.path.join(folder, name))
            error = self.blocking(name, text)
            files[name] = {"text": text, "sha256": sha256(text), "error": error,
                           "layer": None if error else json.loads(text)}
        return {"folder": folder, "files": files}

    def check(self, body):
        if not isinstance(body, dict):
            raise UIError(400, "expected {org, local, local_name}")
        return self.check_result(body.get("org"), body.get("local"), body.get("local_name"))

    def put_layer(self, name, body):
        folder = self.need_folder()
        if not LAYER_NAME.match(name):
            raise UIError(403, "The UI writes only org.json and local.<host>.json")
        if not isinstance(body, dict) or not isinstance(body.get("layer"), dict):
            raise UIError(400, "expected {layer, sha256}")
        layer, path = body["layer"], os.path.join(folder, name)
        if os.path.islink(path):
            raise UIError(403, "{} is a symbolic link; edit it in the terminal".format(name))
        current = read_text(path)
        if body.get("sha256") != sha256(current):
            raise UIError(409, "{} changed on disk since it was read. Reload, then make "
                               "the change again".format(name))
        if current is not None:
            try:
                if json.loads(current) == layer:
                    return {"written": False, "sha256": sha256(current)}
            except ValueError:
                pass
        # Check against what is on disk next to it, so the folder always builds.
        if name == "org.json":
            machines = [n for n in self.layer_names() if n != "org.json"] or \
                ["local.{}.json".format(self.host)]
            pairs = [(layer, self.disk_layer(m, {"requires_baseline": self.build.describe()
                                                 ["requires_baseline"]}), m)
                     for m in machines]
        else:
            pairs = [(self.disk_layer("org.json"), layer, name)]
        for org, local, local_name in pairs:
            res = self.check_result(org, local, local_name)
            if not res["ok"]:
                raise CheckFailed(res)
        text = self.build.layer_text(layer)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            mode = os.stat(path).st_mode & 0o777 if current is not None else 0o644
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return {"written": True, "sha256": sha256(text)}

    def disk_layer(self, name, default=None):
        text = read_text(os.path.join(self.need_folder(), name))
        if text is None:
            if default is not None:
                return default
            raise UIError(409, "{} is missing in the folder; save it first".format(name))
        try:
            return json.loads(text)
        except ValueError as e:
            raise UIError(409, "{}: not valid JSON ({})".format(name, e))

    def migrate(self, write, body=None):
        if write and not (isinstance(body, dict) and body.get("confirm") is True):
            raise UIError(400, "writing the migration needs {\"confirm\": true}")
        return self.run_build(["--migrate"] + (["--write"] if write else []))

    def build_folder(self, body):
        write = isinstance(body, dict) and body.get("write") is True
        out = self.run_build([] if write else ["--diff"])
        if write and out["code"] == 0:
            out["install"] = self.install_command()
        return out

    def api(self, method, path, body):
        routes = {
            ("GET", "/api/state"): lambda: self.state(),
            ("POST", "/api/folder"): lambda: self.set_folder(body),
            ("POST", "/api/init"): lambda: self.init(body),
            ("GET", "/api/describe"): lambda: self.build.describe(),
            ("GET", "/api/layers"): lambda: self.layers(),
            ("POST", "/api/check"): lambda: self.check(body),
            ("GET", "/api/migrate"): lambda: self.migrate(False),
            ("POST", "/api/migrate"): lambda: self.migrate(True, body),
            ("POST", "/api/build"): lambda: self.build_folder(body),
        }
        with self.lock:
            if (method, path) in routes:
                return 200, routes[(method, path)]()
            if method == "PUT" and path.startswith("/api/layers/"):
                return 200, self.put_layer(urllib.parse.unquote(path[len("/api/layers/"):]),
                                           body)
        raise UIError(404, "no such call: {} {}".format(method, path))


class CheckFailed(Exception):
    def __init__(self, result):
        Exception.__init__(self, result["error"])
        self.result = result


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "guardrails-ui"
    sys_version = ""
    app = None  # set by serve()

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")

    def handle_any(self, method):
        try:
            self.guard()
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/api/"):
                if not hmac.compare_digest(self.headers.get(TOKEN_HEADER, ""), self.app.token):
                    raise UIError(403, "missing or wrong token: open the address build.py "
                                       "--ui printed")
                body = self.read_body() if method in ("POST", "PUT") else None
                status, obj = self.app.api(method, path, body)
                self.send(status, obj)
            elif method == "GET":
                self.send_static(path)
            else:
                raise UIError(405, "method not allowed")
        except UIError as e:
            self.send(e.status, {"error": str(e)})
        except CheckFailed as e:
            self.send(422, {"error": str(e), "check": e.result})
        except self.app.build.LayerError as e:
            self.send(422, {"error": str(e)})
        except Exception:
            traceback.print_exc()
            self.send(500, {"error": "internal error, see the terminal running build.py --ui"})

    def guard(self):
        """Only this page, on this machine, under the address it was started with."""
        port = self.app.port
        hosts = {"127.0.0.1:{}".format(port), "localhost:{}".format(port)}
        if self.headers.get("Host", "") not in hosts:
            raise UIError(403, "Host not allowed")
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {"http://" + h for h in hosts}:
            raise UIError(403, "cross-origin request refused")
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            raise UIError(403, "cross-site request refused")

    def read_body(self):
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise UIError(415, "expected Content-Type: application/json")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise UIError(411, "Content-Length missing")
        if length < 0 or length > MAX_BODY:
            raise UIError(413, "request too large")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise UIError(400, "body is not JSON")

    def send(self, status, obj):
        self.respond(status, "application/json; charset=utf-8",
                     json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def send_static(self, path):
        f = self.app.static.get(path)
        if not f:
            raise UIError(404, "not found")
        with open(f, "rb") as fh:
            data = fh.read()
        self.respond(200, STATIC_TYPES[os.path.splitext(f)[1]], data)

    def respond(self, status, ctype, data):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # the token travels in a header and in the URL fragment, never in the request line
        sys.stderr.write("ui: " + (fmt % args) + "\n")


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # skip HTTPServer's getfqdn(), which can take seconds on macOS
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def make_server(build, folder=None, quiet=False):
    """(server, app) bound to 127.0.0.1 on a free port; tests use it without serve()."""
    app = App(build, folder)
    handler = type("BoundHandler", (Handler,), {"app": app})
    if quiet:
        handler.log_message = lambda self, *a: None
    httpd = Server(("127.0.0.1", 0), handler)
    app.port = httpd.server_address[1]
    return httpd, app


def serve(build, folder=None):
    httpd, app = make_server(build, folder)
    print("Configuration UI (optional; every step is also a build.py command):\n\n"
          "  http://127.0.0.1:{}/#token={}\n\n"
          "Open this address in your browser. Only this machine can reach it, and only with "
          "the key in it.\nIt writes only org.json and local.<host>.json; install.sh stays "
          "in your terminal. Ctrl+C stops it.".format(app.port, app.token), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
