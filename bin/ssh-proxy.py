#!/usr/bin/env python3
"""ssh ProxyCommand for the Claude Code sandbox: tunnels host:port through the
sandbox's authenticated HTTP proxy (from $HTTPS_PROXY) using CONNECT.
Usage: ssh -o ProxyCommand='python3 ssh-proxy.py %h %p' host
       python3 ssh-proxy.py --probe host port   (prints the first line)"""
import base64, json, os, select, socket, sys
from urllib.parse import urlsplit

# The same policy the hook reads: the installed one, else the one next to this checkout.
POLICY_PATHS = (
    "/Library/Application Support/ClaudeCode/policy.json",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "policy.json"),
)


def search_domain():
    """ssh.search_domain from the policy: short names like "web01" resolve to
    web01.<search domain>. Without a readable policy short names stay as they are and
    fail to resolve, rather than going to a guessed domain."""
    for path in POLICY_PATHS:
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)["ssh"].get("search_domain") or ""
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return ""


def tunnel(host, port):
    if "." not in host and host != "localhost":
        domain = search_domain()
        if domain:
            host = f"{host}.{domain}"
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy:  # not inside the sandbox: connect directly
        return socket.create_connection((host, port), timeout=20), b""
    p = urlsplit(proxy)
    s = socket.create_connection((p.hostname, p.port), timeout=20)
    auth = base64.b64encode(f"{p.username}:{p.password}".encode()).decode()
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
              f"Proxy-Authorization: Basic {auth}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200" not in status:
        sys.exit(f"proxy refused {host}:{port}: {status}")
    return s, head.split(b"\r\n\r\n", 1)[1]


def main():
    if sys.argv[1] == "--probe":
        s, rest = tunnel(sys.argv[2], int(sys.argv[3]))
        data = rest or s.recv(256)
        print("OK", data.split(b"\n", 1)[0].decode(errors="replace").strip())
        return
    s, rest = tunnel(sys.argv[1], int(sys.argv[2]))
    s.settimeout(None)
    out, inp = sys.stdout.buffer, sys.stdin.buffer
    if rest:
        out.write(rest); out.flush()
    watch = [s, inp]
    while True:
        r, _, _ = select.select(watch, [], [])
        if s in r:
            d = s.recv(65536)
            if not d:
                break
            out.write(d); out.flush()
        if inp in r:
            d = os.read(inp.fileno(), 65536)
            if not d:
                s.shutdown(socket.SHUT_WR)
                watch = [s]
                continue
            s.sendall(d)


if __name__ == "__main__":
    main()
