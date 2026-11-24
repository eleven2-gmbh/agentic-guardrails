# Configuration UI

Status: built (`ui/`, `tests/test_ui.py`). It rests on `build.py --describe`, `--init`,
`--migrate` and `layer_format`; see README, *Configure*, and design notes, 8.

```
./build.py --ui [--config DIR]   prints http://127.0.0.1:<port>/#token=... ; Ctrl+C stops it
```

Open the printed address yourself; the UI does not start a browser, so the token never
appears in another process's command line.

## Files

| Path | Content |
|---|---|
| `ui/server.py` | the server and its JSON API; loaded by `build.py --ui` only, the build never imports it |
| `ui/index.html`, `ui/app.js`, `ui/style.css` | the page; components are render functions (`h()`) |
| `ui/vendor/vue.runtime.global.prod.js` | Vue 3.5.45, runtime-only build; `VENDOR.md` records source, integrity and SHA-256 |
| `tests/test_ui.py` | the server tests below |

## Principles

- **Optional.** The product works without the UI, always. Everything the UI does is a
  `build.py` command that also works in the terminal. `install.sh` never needs it.
- **No second copy of the rules.** The UI builds its forms from `build.py --describe` and
  lets `build.py` check every change (merge, `--diff`, `--check`). It shows `build.py`'s
  error messages as they are. No validation logic in JavaScript beyond input hints.
- **No root.** The UI never runs `install.sh` or `sudo`. It shows the command to copy
  into the user's own terminal.
- **Nothing leaves the machine.** No CDN, no web fonts, no external request of any kind.

## Stack

| Part | Choice | Why |
|---|---|---|
| Server | Python standard library (`http.server`), started by `./build.py --ui [--config DIR]`, on `/usr/bin/python3` | the product's own runtime, no dependency |
| Frontend | Vue 3 as one vendored file (`ui/vendor/vue.runtime.global.prod.js`, the runtime-only build), plain HTML and JavaScript, no build step | reactive forms without npm; one file to review and replace |
| CSS | own stylesheet, system fonts, CSS variables, light and dark via `prefers-color-scheme` | no third-party CSS |
| Icons | a few inline SVGs | no icon font |

Considered and rejected: Electron (the stack of a sibling project; hundreds of npm
packages and a bundled Chromium in a supply-chain product), Tauri (Rust crates plus an
npm frontend), native SwiftUI (new language, signing), a Vite/TypeScript build with a
checked-in bundle (an unreadable blob in the repository).

Vendoring Vue: vetted with `/dep-check` (2026-11-24); exact version 3.5.45; version,
source URL, registry integrity, SHA-256 and licence (MIT) in `ui/vendor/VENDOR.md`; a
test checks the hash.

## Server security

- Bind to `127.0.0.1` only, on a random free port.
- A random token (`secrets.token_urlsafe`) in the start URL's fragment (`#token=`), so it
  never travels in a request line or a log; the page keeps it in `sessionStorage`, drops
  it from the address bar and sends it as `X-Guardrails-Token` on every API call;
  requests without it get 403. The static files of the page need no token.
- `POST` and `PUT` need `Content-Type: application/json` (no plain form posts) and at
  most 1 MiB.
- Check the `Host` header (`127.0.0.1:<port>` or `localhost:<port>`) against DNS
  rebinding; reject cross-origin requests (`Origin`, `Sec-Fetch-Site`).
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`, plus
  `base-uri 'none'; form-action 'none'`. Templates compiled at runtime would need
  `'unsafe-eval'`; the components are render functions (`h()`) on the runtime-only
  build, which has no compiler and no `eval` at all. No inline script, no inline style.
- Serve only files from `ui/` (a fixed list made at start: `.html`, `.js`, `.css`, `.svg`,
  no symbolic links); JSON API only for the configuration folder given at start. Without
  `--config` the Folder screen chooses it.
- Writes go to `org.json` and `local.<host>.json` only, through the same text format
  `build.py` writes (`layer_text`: 2-space indent, key order kept, trailing newline).
  `baseline.json`, `policy.json` and `managed-settings.json` are never written by the UI;
  the generated files come from `build.py`. A layer that did not change is not written
  at all, so even a hand-formatted file stays byte-identical. Each write sends the
  SHA-256 of the text it was based on and is refused (409) if the file changed since;
  it is written to a temporary file and renamed, never through a symbolic link.
- A write is checked against what is on disk next to it: `org.json` with every machine
  layer in the folder, a machine layer with `org.json`. So the folder always builds.

## Screens

1. **Folder.** Enter the path of a configuration folder (no native folder dialog in a
   browser). Existing folder: read it. New folder: `--init` with template `empty` or
   `example` and a host name. Show `product-version` and whether the checkout matches.
2. **Update.** If `--migrate` finds changes, show its diff and notes; write only after
   confirmation (`--write`). A layer with a newer `layer_format` or outside
   `requires_baseline` shows `build.py`'s message and nothing else.
3. **Organisation** (`org.json`) and **Machine** (`local.<host>.json`), each with tabs:
   - *Set*: one field per settable path, typed from `--describe`, baseline value shown.
   - *Add*: lists of facts; own domains with purposes and wildcard, ssh hosts with role.
   - *Tighten*: extra patterns and list entries; values with their stricter direction.
   - *Exceptions*: id picked from `exceptions.off` / `exceptions.set`, action, reason,
     expiry date; locked ids are not offered.
4. **Check.** Run the merge on every change and show errors next to the field when the
   message names a path. `--diff` of `policy.json` and `managed-settings.json` before
   building; then build. Afterwards show the `install.sh` command to copy.

## Server API

| Call | Does |
|---|---|
| `GET /api/describe` | `describe()` |
| `GET /api/layers` | the layer files of the folder, as JSON |
| `GET /api/state` | folder, host, `product-version`, checkout (tag, clean), install command |
| `POST /api/folder` | choose the folder (only without `--config`) |
| `POST /api/check` | layers from the body, merged with `effective()` in a temp folder; errors (with the file and the paths they name) or the merged policy |
| `GET /api/migrate` / `POST /api/migrate` | `build.py --migrate` / `--migrate --write`, the latter only with `{"confirm": true}` |
| `POST /api/init` | `init()` |
| `PUT /api/layers/<file>` | write one layer after a successful check |
| `POST /api/build` | `build.py --diff`, or with `{"write": true}` the build; then the `install.sh` command |

`--diff`, the build and `--migrate` run `build.py` itself (`/usr/bin/python3 -I`), so the
page shows the same output as the terminal. Note that `build.py` builds with
`local.<this machine>.json`; the page says so when another machine layer is open.

## Tests

`tests/test_ui.py` on `/usr/bin/python3 -I`: token, Host and Origin checks, CSP header,
path traversal, writes limited to the two layer files, round trip of a layer without
changes is byte-identical, vendor hash.
