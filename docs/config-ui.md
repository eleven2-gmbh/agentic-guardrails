# Configuration UI (planned)

Status: planned, not built. The foundation in `build.py` (`--describe`, `--init`,
`--migrate`, `layer_format`) is in place; see README, *Configure*, and design notes, 8.

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
| Frontend | Vue 3 as one vendored file (`ui/vendor/vue.global.prod.js`), plain HTML and JavaScript, no build step | reactive forms without npm; one file to review and replace |
| CSS | own stylesheet, system fonts, CSS variables, light and dark via `prefers-color-scheme` | no third-party CSS |
| Icons | a few inline SVGs | no icon font |

Considered and rejected: Electron (the stack of a sibling project; hundreds of npm
packages and a bundled Chromium in a supply-chain product), Tauri (Rust crates plus an
npm frontend), native SwiftUI (new language, signing), a Vite/TypeScript build with a
checked-in bundle (an unreadable blob in the repository).

Vendoring Vue: vet it with `/dep-check` first; pin an exact version; record version,
source URL, SHA-256 and licence (MIT) in `ui/vendor/VENDOR.md`; a test checks the hash.

## Server security

- Bind to `127.0.0.1` only, on a random free port.
- A random token (`secrets.token_urlsafe`) in the start URL; the page keeps it and sends
  it as a header on every API call; requests without it get 403.
- Check the `Host` header (`127.0.0.1:<port>` or `localhost:<port>`) against DNS
  rebinding; reject cross-origin requests (`Origin`, `Sec-Fetch-Site`).
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`. With
  `vue.global.prod.js` templates must be compiled at runtime, which needs
  `'unsafe-eval'`; avoid it by writing components as render functions (`h()`), or accept
  it knowingly and note why.
- Serve only files from `ui/`; JSON API only for the configuration folder given at start.
- Writes go to `org.json` and `local.<host>.json` only, through the same text format
  `build.py` writes (`layer_text`: 2-space indent, key order kept, trailing newline).
  `baseline.json`, `policy.json` and `managed-settings.json` are never written by the UI;
  the generated files come from `build.py`.

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

## Server API (sketch)

| Call | Does |
|---|---|
| `GET /api/describe` | `describe()` |
| `GET /api/layers` | the layer files of the folder, as JSON |
| `POST /api/check` | layers from the body, merged with `effective()` in a temp folder; errors or the merged policy |
| `GET /api/migrate` / `POST /api/migrate` | diff and notes / write |
| `POST /api/init` | `init()` |
| `PUT /api/layers/<file>` | write one layer after a successful check |
| `POST /api/build` | `build.py` output for the folder (`--diff`, then write) |

## Tests

`tests/test_ui.py` on `/usr/bin/python3 -I`: token, Host and Origin checks, CSP header,
path traversal, writes limited to the two layer files, round trip of a layer without
changes is byte-identical, vendor hash.
