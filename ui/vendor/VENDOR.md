# Vendored files

Checked with `/dep-check` on 2026-11-24: vuejs/core, MIT, two npm maintainers, OpenSSF
scorecard 6.3, no install scripts, no known vulnerabilities (OSV) in this version. 3.5.46
was 4 days old and so too young (7-day window).

| File | Package | Version | Licence |
|---|---|---|---|
| `vue.runtime.global.prod.js` | vue | 3.5.45 | MIT (`vue.LICENSE`) |

- Source: https://registry.npmjs.org/vue/-/vue-3.5.45.tgz, file `package/dist/vue.runtime.global.prod.js`
- Tarball integrity (npm registry): `sha512-3cvsib8m9c0vB24+MDKsgcW4+Da4xaBl9Z/5Tbm2pmSIsRPxcil4cdXjXlVsmJ2g64XJo5h+IRd7rsdGT9pZaw==`
- SHA-256: 3decf87d416625675c52bd38e928521ba192277a26c5172ab4545a4e98ffddc3

The runtime-only build has no template compiler, so it contains no `eval` or
`new Function`, and the page runs under a Content-Security-Policy without
`'unsafe-eval'`. The components in `ui/app.js` are render functions (`h()`).

To update: run `/dep-check` again, take the newest version that is at least 7 days old,
check the tarball against the registry's `integrity`, replace the file and the licence,
and update the version, URL, integrity and SHA-256 above. `tests/test_ui.py` checks the
SHA-256.
