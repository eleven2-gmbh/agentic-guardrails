/* agentic-guardrails configuration UI (docs/config-ui.md).
 *
 * The forms come from build.py --describe; build.py checks every change. This file holds
 * no rules of its own: it turns form input into layer JSON and shows build.py's messages
 * as they are. Components are render functions (h()), so the page runs on Vue's runtime
 * build under a Content-Security-Policy without 'unsafe-eval'.
 */
"use strict";
(function () {
  const { createApp, h, reactive, watch, onMounted } = window.Vue;

  // ------------------------------------------------------------- token ----
  // build.py --ui prints http://127.0.0.1:<port>/#token=...; the fragment never reaches
  // the server or its log. Keep it for this tab only and drop it from the address bar.
  const KEY = "guardrails-ui-token";
  let token = "";
  const m = /^#token=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (m) {
    token = m[1];
    try { sessionStorage.setItem(KEY, token); } catch (e) { /* private window */ }
    history.replaceState(null, "", location.pathname);
  } else {
    try { token = sessionStorage.getItem(KEY) || ""; } catch (e) { token = ""; }
  }

  async function api(method, path, body) {
    const opt = { method, headers: { "X-Guardrails-Token": token }, cache: "no-store" };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    let r;
    try {
      r = await fetch(path, opt);
    } catch (e) {
      return { status: 0, ok: false, data: { error: "The UI server does not answer. Is ./build.py --ui still running?" } };
    }
    let data;
    try { data = await r.json(); } catch (e) { data = { error: "no JSON answer (HTTP " + r.status + ")" }; }
    return { status: r.status, ok: r.ok, data };
  }

  // ------------------------------------------------------------- state ----
  const S = reactive({
    fatal: "",
    state: null,
    describe: null,
    files: {},
    blocked: [],
    org: null, local: null, localName: "", localNew: false,
    orig: { org: null, local: null },
    saved: { org: "", local: "" },
    sha: { org: null, local: null },
    check: null,
    migrate: null, migrateConfirm: false,
    screen: "folder",
    tab: { org: "set", local: "add" },
    folderInput: "", initTemplate: "empty", initHost: "",
    busy: false, note: "", error: "", saveError: { org: null, local: null },
    diff: null, built: null, copied: false,
  });

  const clone = (o) => (o === undefined ? undefined : JSON.parse(JSON.stringify(o)));
  const hasOwn = (o, k) => !!o && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
  const fileName = (which) => (which === "org" ? "org.json" : S.localName);
  const dirty = (which) => S[which] !== null && JSON.stringify(S[which]) !== S.saved[which];
  const anyDirty = () => dirty("org") || dirty("local");
  const in90 = () => new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);

  function show(v) {
    if (Array.isArray(v)) return v.length ? v.map(show).join(", ") : "(empty list)";
    if (v === "") return "(empty)";
    if (v && typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  // A layer section is created when first needed and removed again only if the file
  // did not have it, so an unchanged layer round-trips to the same text.
  function setIn(which, op, path, value) {
    const layer = S[which];
    if (!layer[op] || typeof layer[op] !== "object" || Array.isArray(layer[op])) layer[op] = {};
    layer[op][path] = value;
  }
  function unsetIn(which, op, path) {
    const layer = S[which];
    if (!hasOwn(layer, op)) return;
    delete layer[op][path];
    if (!Object.keys(layer[op]).length && !hasOwn(S.orig[which], op)) delete layer[op];
  }
  function setList(which, op, path, list) {
    if (!list.length && !(hasOwn(S.orig[which], op) && hasOwn(S.orig[which][op], path))) {
      unsetIn(which, op, path);
    } else {
      setIn(which, op, path, list);
    }
  }

  // ------------------------------------------------------------- loading --
  async function start() {
    if (!token) {
      S.fatal = "No key. Open the address that ./build.py --ui printed in your terminal.";
      return;
    }
    const [st, d] = await Promise.all([api("GET", "/api/state"), api("GET", "/api/describe")]);
    if (!st.ok || !d.ok) {
      S.fatal = (st.ok ? d : st).data.error;
      return;
    }
    S.state = st.data;
    S.describe = d.data;
    S.initHost = st.data.host;
    S.folderInput = st.data.folder || "";
    if (st.data.folder) await loadFolder();
  }

  async function refreshState() {
    const st = await api("GET", "/api/state");
    if (st.ok) S.state = st.data;
  }

  function newMachineLayer() {
    return { layer_format: S.describe.layer_format, requires_baseline: S.describe.requires_baseline };
  }

  function useLayer(which, name) {
    const f = S.files[name];
    if (which === "local") {
      S.localName = name;
      S.localNew = !f;
    }
    S[which] = f && f.layer ? clone(f.layer) : which === "local" ? newMachineLayer() : null;
    S.orig[which] = f && f.layer ? clone(f.layer) : null;
    S.saved[which] = f && f.layer ? JSON.stringify(f.layer) : "";
    S.sha[which] = f ? f.sha256 : null;
    S.saveError[which] = null;
  }

  async function loadFolder() {
    S.busy = true;
    S.error = "";
    S.diff = S.built = null;
    const [ls, mg] = await Promise.all([api("GET", "/api/layers"), api("GET", "/api/migrate")]);
    S.busy = false;
    if (!ls.ok) { S.error = ls.data.error; return; }
    S.files = ls.data.files;
    S.blocked = Object.keys(S.files).filter((n) => S.files[n].error).map((n) => S.files[n].error);
    S.migrate = mg.ok ? mg.data : { code: 2, output: mg.data.error };
    S.migrateConfirm = false;
    useLayer("org", "org.json");
    const machines = Object.keys(S.files).filter((n) => n !== "org.json");
    const mine = S.state.machine;
    useLayer("local", S.files[mine] || !machines.length ? mine : machines[0]);
    await refreshState();
    if (S.blocked.length || (S.migrate && S.migrate.code !== 0)) S.screen = "update";
    else if (!S.org) S.screen = "folder";
    else if (S.screen === "folder" || S.screen === "update") S.screen = "org";
    runCheck();
  }

  // ------------------------------------------------------------- checking --
  let checkSeq = 0;
  let checkTimer = null;
  async function runCheck() {
    if (!S.org || !S.local || S.blocked.length) { S.check = null; return; }
    const seq = ++checkSeq;
    const r = await api("POST", "/api/check", { org: S.org, local: S.local, local_name: S.localName });
    if (seq !== checkSeq) return;
    S.check = r.ok ? r.data : { ok: false, error: r.data.error, paths: [], notes: [] };
  }
  watch(() => JSON.stringify([S.org, S.local, S.localName]), () => {
    clearTimeout(checkTimer);
    checkTimer = setTimeout(runCheck, 300);
  });

  function errorFor(which, path) {
    const c = S.check;
    if (!c || c.ok || !c.error || c.file !== fileName(which)) return null;
    return c.paths.indexOf(path) >= 0 ? c.error : null;
  }

  // ------------------------------------------------------------- actions --
  async function openFolder() {
    S.error = S.note = "";
    const r = await api("POST", "/api/folder", { path: S.folderInput });
    if (!r.ok) { S.error = r.data.error; return; }
    S.state = r.data;
    await loadFolder();
  }

  async function initFolder() {
    S.error = S.note = "";
    const r = await api("POST", "/api/init", {
      path: S.state.folder || S.folderInput, template: S.initTemplate, host: S.initHost || null,
    });
    if (!r.ok) { S.error = r.data.error; return; }
    S.state = r.data;
    S.folderInput = r.data.folder;
    S.note = r.data.written.join(" and ") + " written";
    await loadFolder();
  }

  async function writeMigration() {
    S.busy = true;
    const r = await api("POST", "/api/migrate", { confirm: true });
    S.busy = false;
    S.note = r.ok ? r.data.output : "";
    S.error = r.ok ? "" : r.data.error;
    await loadFolder();
  }

  async function save(which) {
    const name = fileName(which);
    S.saveError[which] = null;
    S.note = "";
    const r = await api("PUT", "/api/layers/" + encodeURIComponent(name), { layer: S[which], sha256: S.sha[which] });
    if (!r.ok) {
      S.saveError[which] = r.data.error;
      if (r.data.check) S.check = r.data.check;
      return;
    }
    S.sha[which] = r.data.sha256;
    S.saved[which] = JSON.stringify(S[which]);
    S.orig[which] = clone(S[which]);
    S.files[name] = { text: null, sha256: r.data.sha256, error: null, layer: clone(S[which]) };
    if (which === "local") S.localNew = false;
    S.note = name + (r.data.written ? " written" : " unchanged, nothing written");
    S.diff = S.built = null;
    await refreshState();
  }

  function discard(which) {
    useLayer(which, fileName(which));
  }

  async function runBuild(write) {
    S.busy = true;
    S.error = "";
    const r = await api("POST", "/api/build", { write });
    S.busy = false;
    if (!r.ok) { S.error = r.data.error; return; }
    if (write) { S.built = r.data; S.diff = null; } else { S.diff = r.data; S.built = null; }
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      S.copied = true;
      setTimeout(() => { S.copied = false; }, 1500);
    } catch (e) {
      S.copied = false;
    }
  }

  // ------------------------------------------------------------- pieces ---
  const ICONS = { ok: "M3 8.5l3 3 7-7", bad: "M4 4l8 8M12 4l-8 8", warn: "M8 2.5v7M8 12.5v.5" };
  function icon(kind) {
    return h("svg", { width: 16, height: 16, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor",
      "stroke-width": 2, "stroke-linecap": "round", "aria-hidden": "true" }, [h("path", { d: ICONS[kind] })]);
  }
  function msg(kind, text) {
    return h("div", { class: "msg " + kind, role: kind === "bad" ? "alert" : "status" }, [icon(kind), h("span", text)]);
  }
  function button(label, onClick, opts) {
    opts = opts || {};
    return h("button", { class: "act" + (opts.kind ? " " + opts.kind : ""), type: "button",
      disabled: !!opts.disabled, onClick }, label);
  }
  function out(text) {
    const lines = (text || "").split("\n");
    return h("pre", { class: "out" }, lines.map((l) => h("span", {
      class: /^\+(?!\+\+)/.test(l) ? "add" : /^-(?!--)/.test(l) ? "del" : null,
    }, l + "\n")));
  }
  function copyBox(text) {
    return h("div", { class: "copy" }, [h("code", text), button(S.copied ? "Copied" : "Copy", () => copy(text))]);
  }

  // Form input -> JSON value. Input that does not fit the type is passed on as text, so
  // build.py reports the type error in its own words.
  function parseTyped(type, raw) {
    const s = raw.trim();
    if (type === "integer" && /^-?\d+$/.test(s)) return parseInt(s, 10);
    if (type === "number" && /^-?\d+(\.\d+)?$/.test(s)) return parseFloat(s);
    return raw;
  }
  function lines(text) {
    return text.split("\n").map((x) => x.trim()).filter((x) => x);
  }

  function valueInput(type, value, disabled, onSet, label) {
    if (type === "boolean") {
      return h("select", { value: String(value), disabled, "aria-label": label,
        onChange: (e) => onSet(e.target.value === "true") },
      [h("option", { value: "true" }, "true"), h("option", { value: "false" }, "false")]);
    }
    if (type === "list of text") {
      return h("textarea", { value: Array.isArray(value) ? value.join("\n") : String(value), disabled,
        "aria-label": label, placeholder: "one entry per line", onChange: (e) => onSet(lines(e.target.value)) });
    }
    return h("input", { type: "text", value: String(value), disabled, "aria-label": label,
      inputmode: type === "integer" || type === "number" ? "decimal" : null,
      onInput: (e) => onSet(type === "text" ? e.target.value : parseTyped(type, e.target.value)) });
  }

  const DIRECTIONS = { higher: "stricter means higher", "true": "stricter means true",
    "higher-version": "stricter means a higher version" };

  // One settable value: `set` paths, and `tighten` values with their direction.
  function valueRow(which, op, path, info) {
    const layer = S[which];
    const has = hasOwn(layer[op], path);
    const value = has ? layer[op][path] : info.baseline;
    const err = errorFor(which, path);
    const id = "f-" + which + "-" + op + "-" + path;
    return h("div", { class: "row", key: path }, [
      h("div", { class: "label" }, [
        h("label", [
          h("input", { type: "checkbox", checked: has, onChange: (e) => (e.target.checked
            ? setIn(which, op, path, clone(info.baseline)) : unsetIn(which, op, path)) }),
          h("span", { id }, path),
        ]),
      ]),
      h("div", { class: "field" }, [
        valueInput(info.type, value, !has, (v) => setIn(which, op, path, v), path),
        h("div", { class: "base" }, "baseline: " + show(info.baseline) +
          (info.direction ? " · " + (DIRECTIONS[info.direction] || info.direction) : "") +
          (has ? "" : " · tick the box to set it in this layer")),
        err ? msg("bad", err) : null,
      ]),
    ]);
  }

  function entryLabel(e) {
    if (typeof e === "string") return e;
    if (e && e.domain) return e.domain + (e.wildcard ? " (+ subdomains)" : "") + " [" + (e.purposes || []).join(", ") + "]";
    if (e && e.host) return e.host + (e.role ? " (" + e.role + ")" : "");
    if (e && e.id) return e.id + (e.pattern ? ": " + e.pattern : "");
    return JSON.stringify(e);
  }

  function setOptional(e, k, v) {
    if (v === "") delete e[k]; else e[k] = v;
  }

  function entryEditor(which, op, path, kind, list) {
    const update = (l) => setList(which, op, path, l);
    const remove = (i) => { const l = list.slice(); l.splice(i, 1); update(l); };
    const add = (e) => update(list.concat([e]));
    const del = (i) => button("Remove", () => remove(i), { kind: "danger" });
    if (kind === "text") {
      return h("textarea", { value: list.join("\n"), placeholder: "one entry per line", "aria-label": path,
        onChange: (e) => update(lines(e.target.value)) });
    }
    let rows;
    let blank;
    if (kind === "domain") {
      const purposes = S.describe.purposes;
      rows = list.map((e, i) => h("div", { class: "entry", key: i }, [
        h("input", { type: "text", value: e.domain || "", placeholder: "example.com", "aria-label": "domain",
          onInput: (ev) => { e.domain = ev.target.value; } }),
        h("span", { class: "checks" }, purposes.map((p) => h("label", [
          h("input", { type: "checkbox", checked: (e.purposes || []).indexOf(p) >= 0, onChange: (ev) => {
            const have = new Set(e.purposes || []);
            if (ev.target.checked) have.add(p); else have.delete(p);
            e.purposes = purposes.filter((x) => have.has(x)).concat((e.purposes || []).filter((x) => purposes.indexOf(x) < 0));
          } }), p,
        ])).concat([h("label", [
          h("input", { type: "checkbox", checked: !!e.wildcard, onChange: (ev) => { e.wildcard = ev.target.checked; } }),
          "subdomains",
        ])])),
        del(i),
      ]));
      blank = () => ({ domain: "", purposes: ["network"] });
    } else if (kind === "host") {
      rows = list.map((e, i) => h("div", { class: "entry", key: i }, [
        h("input", { type: "text", value: e.host || "", placeholder: "host or host.domain", "aria-label": "host",
          onInput: (ev) => { e.host = ev.target.value; } }),
        h("input", { type: "text", value: e.role || "", placeholder: "role", "aria-label": "role",
          onInput: (ev) => setOptional(e, "role", ev.target.value) }),
        h("input", { type: "text", value: e.note || "", placeholder: "note", "aria-label": "note",
          onInput: (ev) => setOptional(e, "note", ev.target.value) }),
        del(i),
      ]));
      blank = () => ({ host: "", role: "" });
    } else {
      rows = list.map((e, i) => h("div", { class: "entry", key: i }, typeof e === "string" ? [
        h("input", { type: "text", value: e, placeholder: "regular expression", "aria-label": "pattern",
          onInput: (ev) => { list[i] = ev.target.value; } }),
        del(i),
      ] : [
        h("input", { type: "text", value: e.id || "", placeholder: "id, e.g. personal.app-audit", "aria-label": "id",
          onInput: (ev) => { e.id = ev.target.value; } }),
        h("input", { type: "text", value: e.pattern || "", placeholder: "regular expression", "aria-label": "pattern",
          onInput: (ev) => { e.pattern = ev.target.value; } }),
        del(i),
      ]));
      blank = () => ({ id: "", pattern: "" });
    }
    return h("div", { class: "entries" }, rows.concat([
      h("div", [button("Add", () => add(blank()))]),
    ]));
  }

  // One list: `add` lists of facts and `tighten` lists.
  function listRow(which, op, path, info) {
    const layer = S[which];
    const list = hasOwn(layer[op], path) && Array.isArray(layer[op][path]) ? layer[op][path] : [];
    const err = errorFor(which, path);
    const base = info.baseline || [];
    return h("div", { class: "row", key: path }, [
      h("div", { class: "label" }, [h("span", path), h("div", { class: "base" }, info.entry + " entries")]),
      h("div", { class: "field" }, [
        entryEditor(which, op, path, info.entry, list),
        h("details", { class: "baseline" }, [
          h("summary", "baseline: " + base.length + " entries"),
          base.length ? h("ul", base.map((e) => h("li", entryLabel(e)))) : null,
        ]),
        err ? msg("bad", err) : null,
      ]),
    ]);
  }

  function exceptionsTab(which) {
    const layer = S[which];
    const D = S.describe;
    const list = Array.isArray(layer.exceptions) ? layer.exceptions : [];
    const remove = (i) => {
      list.splice(i, 1);
      if (!list.length && !hasOwn(S.orig[which], "exceptions")) delete layer.exceptions;
    };
    const add = () => {
      if (!Array.isArray(layer.exceptions)) layer.exceptions = [];
      layer.exceptions.push({ id: "", action: "off", reason: "", expires: in90() });
    };
    const rows = list.map((ex, i) => {
      const err = S.check && !S.check.ok && S.check.file === fileName(which) && ex.id &&
        S.check.error.indexOf(ex.id) >= 0 ? S.check.error : null;
      const setType = (D.tighten[ex.id] || {}).type || "text";
      return h("div", { class: "entry", key: i }, [
        h("select", { value: ex.action, "aria-label": "action", onChange: (e) => {
          ex.action = e.target.value;
          if (ex.action !== "set") delete ex.value;
          else if (!hasOwn(ex, "value")) ex.value = D.tighten[ex.id] ? clone(D.tighten[ex.id].baseline) : "";
        } }, D.exceptions.actions.map((a) => h("option", { value: a }, a))),
        h("input", { type: "text", value: ex.id || "", "aria-label": "id",
          list: ex.action === "off" ? "dl-off" : ex.action === "set" ? "dl-set" : null,
          placeholder: ex.action === "shadow" ? "rule id of hooks/guard.py" : "id from the baseline",
          onInput: (e) => { ex.id = e.target.value; } }),
        h("input", { type: "text", value: ex.reason || "", placeholder: "reason", "aria-label": "reason",
          onInput: (e) => { ex.reason = e.target.value; } }),
        h("input", { type: "date", value: ex.expires || "", "aria-label": "expires",
          onInput: (e) => { ex.expires = e.target.value; } }),
        ex.action === "set" ? valueInput(setType, hasOwn(ex, "value") ? ex.value : "", false,
          (v) => { ex.value = v; }, "value") : null,
        button("Remove", () => remove(i), { kind: "danger" }),
        err ? h("div", { class: "field" }, [msg("bad", err)]) : null,
      ]);
    });
    return [
      h("p", { class: "hint" }, "Every exception needs an id, a reason and an expiry date. off removes a " +
        "list entry, set changes a value in any direction, shadow only logs a hook rule. Locked ids are not " +
        "offered (" + D.locked.length + " locked)."),
      h("div", { class: "entries" }, rows.concat([h("div", [button("Add exception", add)])])),
    ];
  }

  const TABS = [["set", "Set"], ["add", "Add"], ["tighten", "Tighten"], ["exceptions", "Exceptions"], ["json", "JSON"]];
  const TAB_HINTS = {
    set: "Values without a security direction: names, descriptions, paths. Ticked values are set in this layer.",
    add: "Facts: your own domains, hosts, folders. Entries are added to the baseline's lists.",
    tighten: "Stricter only: more patterns and list entries, values in their stricter direction.",
    json: "The layer as it will be written (2-space indent, key order kept).",
  };

  function layerEditor(which) {
    const D = S.describe;
    const layer = S[which];
    const name = fileName(which);
    if (!layer) {
      return [h("section", { class: "panel" }, [
        h("h2", name),
        msg("warn", name + " is missing. Create the layers on the Folder screen."),
      ])];
    }
    const tab = S.tab[which];
    let body;
    if (tab === "set") {
      body = Object.keys(D.set).map((p) => valueRow(which, "set", p, D.set[p]));
    } else if (tab === "add") {
      body = Object.keys(D.add).map((p) => listRow(which, "add", p, D.add[p]));
    } else if (tab === "tighten") {
      const keys = Object.keys(D.tighten);
      body = keys.filter((p) => D.tighten[p].entry).map((p) => listRow(which, "tighten", p, D.tighten[p]))
        .concat(keys.filter((p) => !D.tighten[p].entry).map((p) => valueRow(which, "tighten", p, D.tighten[p])));
    } else if (tab === "exceptions") {
      body = exceptionsTab(which);
    } else {
      body = [h("pre", { class: "out" }, JSON.stringify(layer, null, 2) + "\n")];
    }
    const picker = which === "local" ? machinePicker() : null;
    return [h("section", { class: "panel" }, [
      h("h2", [which === "org" ? "Organisation · " : "Machine · ", h("span", { class: "mono" }, name),
        dirty(which) ? h("span", { class: "dirty" }, " · unsaved") : null]),
      picker,
      h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, label]) => h("button", {
        type: "button", role: "tab", class: tab === k ? "on" : null, "aria-selected": String(tab === k),
        onClick: () => { S.tab[which] = k; },
      }, label))),
      TAB_HINTS[tab] ? h("p", { class: "hint" }, TAB_HINTS[tab]) : null,
      h("div", body),
      h("div", { class: "actions" }, [
        button("Save " + name, () => save(which), { kind: "primary", disabled: !dirty(which) }),
        button("Discard changes", () => discard(which), { disabled: !dirty(which) || (which === "local" && S.localNew) }),
        h("span", { class: "muted" }, which === "org"
          ? "Saved only if build.py accepts it together with every machine layer in the folder."
          : "Saved only if build.py accepts it together with org.json as saved."),
      ]),
      S.saveError[which] ? msg("bad", S.saveError[which]) : null,
    ])];
  }

  function machinePicker() {
    const names = Object.keys(S.files).filter((n) => n !== "org.json");
    if (names.indexOf(S.state.machine) < 0) names.push(S.state.machine);
    if (names.indexOf(S.localName) < 0) names.push(S.localName);
    return h("p", { class: "hint" }, [
      "Machine layer: ",
      h("select", { value: S.localName, disabled: dirty("local") && !S.localNew, "aria-label": "machine layer",
        onChange: (e) => useLayer("local", e.target.value) },
      names.map((n) => h("option", { value: n }, n + (S.files[n] ? "" : " (new)") +
        (n === S.state.machine ? " · this machine" : "")))),
      dirty("local") && !S.localNew ? " (save or discard first to switch)" : null,
      S.localNew ? " · not on disk yet; Save creates it" : null,
    ]);
  }

  // ------------------------------------------------------------- screens --
  function folderScreen() {
    const st = S.state;
    const c = st.checkout;
    const facts = [
      ["Product checkout", st.product],
      ["Checkout at", c ? (c.describe || "?") + (c.clean ? ", clean" : ", uncommitted changes") : "not a git checkout"],
      ["Configuration folder", st.folder || "none chosen"],
      ["product-version", st.folder ? st.product_version || "not pinned (install.sh installs this checkout as it is)" : "-"],
      ["Layers", st.layers.length ? st.layers.join(", ") : "-"],
    ];
    const panels = [h("section", { class: "panel" }, [
      h("h2", "Configuration folder"),
      h("p", { class: "hint" }, "Keep it outside the product checkout; it holds your organisation's facts. " +
        "A browser has no folder dialog: enter the path."),
      h("div", { class: "copy" }, [
        h("input", { type: "text", value: S.folderInput, disabled: st.fixed, placeholder: "~/my-guardrails",
          "aria-label": "configuration folder", onInput: (e) => { S.folderInput = e.target.value; },
          onKeydown: (e) => { if (e.key === "Enter" && !st.fixed) openFolder(); } }),
        button("Open", openFolder, { kind: "primary", disabled: st.fixed || !S.folderInput.trim() }),
      ]),
      st.fixed ? h("p", { class: "hint" }, "Fixed by --config at start.") : null,
      h("h3", "State"),
      h("dl", { class: "facts" }, facts.flatMap(([k, v]) => [h("dt", k), h("dd", v)])),
      st.product_version && st.matches === false ? msg("warn",
        "The configuration pins " + st.product_version + ", the checkout is at " + (c ? c.describe : "?") +
        (c && !c.clean ? " with uncommitted changes" : "") + ". install.sh will refuse. In your terminal: git -C " +
        st.product + " checkout " + st.product_version) : null,
      st.product_version && st.matches ? msg("ok", "The checkout matches product-version " + st.product_version + ".") : null,
    ])];
    if (!st.folder || !S.files["org.json"]) {
      panels.push(h("section", { class: "panel" }, [
        h("h2", "Create the layers"),
        h("p", { class: "hint" }, "./build.py --init: writes org.json and local.<host>.json into " +
          (st.folder || "the folder above") + " (created if missing) and never overwrites a file."),
        h("div", { class: "row" }, [h("div", { class: "label" }, "template"), h("div", { class: "field" }, [
          h("select", { value: S.initTemplate, "aria-label": "template", onChange: (e) => { S.initTemplate = e.target.value; } }, [
            h("option", { value: "empty" }, "empty: blank organisation and machine layer"),
            h("option", { value: "example" }, "example: a copy of examples/"),
          ]),
        ])]),
        h("div", { class: "row" }, [h("div", { class: "label" }, "host name"), h("div", { class: "field" }, [
          h("input", { type: "text", value: S.initHost, "aria-label": "host name", onInput: (e) => { S.initHost = e.target.value; } }),
          h("div", { class: "base" }, "short host name of the machine; this one is " + st.host),
        ])]),
        h("div", { class: "actions" }, [button("Create", initFolder, { kind: "primary",
          disabled: !(st.folder || S.folderInput.trim()) })]),
      ]));
    }
    return panels;
  }

  function updateScreen() {
    const mg = S.migrate;
    if (S.blocked.length) {
      return [h("section", { class: "panel" }, [h("h2", "Cannot edit these layers here")]
        .concat(S.blocked.map((e) => msg("bad", e))))];
    }
    if (!mg) return [];
    if (mg.code === 2) {
      return [h("section", { class: "panel" }, [h("h2", "Update"), msg("bad", mg.output.trim())])];
    }
    return [h("section", { class: "panel" }, [
      h("h2", "Update the layers"),
      mg.code === 0 ? msg("ok", "The layers are in the current layer format and use current ids.")
        : h("p", { class: "hint" }, "The baseline renamed ids or paths, or the layer format changed. build.py " +
          "--migrate would make these changes. Nothing is written until you confirm."),
      out(mg.output),
      mg.code === 1 ? h("div", { class: "actions" }, S.migrateConfirm ? [
        h("span", "Write the migrated layers now?"),
        button("Yes, write", writeMigration, { kind: "primary", disabled: S.busy }),
        button("Cancel", () => { S.migrateConfirm = false; }),
      ] : [button("Write migration", () => { S.migrateConfirm = true; }, { kind: "primary" })]) : null,
      mg.code === 1 ? h("p", { class: "hint" }, "Same as: " + mg.command + " --write") : null,
    ])];
  }

  function checkScreen() {
    const c = S.check;
    const panels = [h("section", { class: "panel" }, [
      h("h2", "Check"),
      c ? (c.ok ? msg("ok", "build.py accepts org.json and " + S.localName + " as they are in the forms.")
        : msg("bad", c.error)) : msg("warn", "No check yet."),
      c && c.notes && c.notes.length ? h("div", c.notes.map((n) => msg("warn", n))) : null,
      S.localName !== S.state.machine ? msg("warn", "You are editing " + S.localName + ". build.py " +
        "builds for this machine, with org.json and " + S.state.machine + ".") : null,
      anyDirty() ? msg("warn", "Unsaved changes. build.py builds from the files: save " +
        [dirty("org") ? "org.json" : null, dirty("local") ? S.localName : null].filter((x) => x).join(" and ") + " first.") : null,
    ])];
    const d = S.diff;
    const b = S.built;
    panels.push(h("section", { class: "panel" }, [
      h("h2", "Build"),
      h("p", { class: "hint" }, "First the difference that ./build.py --diff shows for policy.json and " +
        "managed-settings.json, then the build. Both are written into the configuration folder."),
      h("div", { class: "actions" }, [
        button("Show diff", () => runBuild(false), { disabled: S.busy || anyDirty() }),
        button("Build", () => runBuild(true), { kind: "primary",
          disabled: S.busy || anyDirty() || !d || d.code !== 1 }),
      ]),
      d ? h("div", [
        h("p", { class: "hint" }, d.command),
        d.code === 0 ? msg("ok", "No difference: policy.json and managed-settings.json are up to date.")
          : d.code === 1 ? out(d.output) : msg("bad", d.output.trim()),
      ]) : null,
      b ? h("div", [
        h("p", { class: "hint" }, b.command),
        b.code === 0 ? out(b.output) : msg("bad", b.output.trim()),
      ]) : null,
      (b && b.code === 0) || (d && d.code === 0) ? h("div", [
        h("h3", "Install"),
        h("p", { class: "hint" }, "The UI never runs install.sh or sudo. Copy this into your own terminal; " +
          "it checks the build and the tests, then asks for your password."),
        copyBox(S.state.install),
      ]) : null,
    ]));
    return panels;
  }

  function nav() {
    const ready = !!S.state && !!S.state.folder && !S.blocked.length;
    const migrateOpen = S.blocked.length || (S.migrate && S.migrate.code !== 0);
    const items = [
      ["folder", "Folder", true],
      ["update", "Update" + (migrateOpen ? " •" : ""), !!S.state && !!S.state.folder],
      ["org", "Organisation" + (dirty("org") ? " •" : ""), ready && !!S.org],
      ["local", "Machine" + (dirty("local") ? " •" : ""), ready && !!S.org],
      ["check", "Check & build", ready && !!S.org],
    ];
    return h("nav", { class: "screens" }, items.map(([k, label, on]) => h("button", {
      type: "button", class: S.screen === k ? "on" : null, disabled: !on,
      "aria-current": S.screen === k ? "page" : null, onClick: () => { S.screen = k; },
    }, label)));
  }

  function statusBar() {
    if (S.screen !== "org" && S.screen !== "local") return null;
    const c = S.check;
    return h("div", { class: "status" }, [h("div", { class: "inner" }, [
      c ? (c.ok ? msg("ok", "build.py accepts both layers.") : msg("bad", c.error)) : null,
    ])]);
  }

  function datalists() {
    if (!S.describe) return null;
    const E = S.describe.exceptions;
    return h("div", [
      h("datalist", { id: "dl-off" }, E.off.map((i) => h("option", { value: i }))),
      h("datalist", { id: "dl-set" }, E.set.map((i) => h("option", { value: i }))),
    ]);
  }

  const App = {
    setup() {
      onMounted(start);
      return () => {
        if (S.fatal) return h("main", [msg("bad", S.fatal)]);
        if (!S.state || !S.describe) return h("p", { class: "boot" }, "Loading…");
        let screen;
        if (S.screen === "folder") screen = folderScreen();
        else if (S.screen === "update") screen = updateScreen();
        else if (S.screen === "org") screen = layerEditor("org");
        else if (S.screen === "local") screen = layerEditor("local");
        else screen = checkScreen();
        return h("div", [
          h("header", { class: "top" }, [
            h("h1", "agentic-guardrails · configuration"),
            h("span", { class: "folder" }, S.state.folder || "no folder"),
            h("span", { class: "muted" }, "baseline " + S.describe.baseline_version + " · layer format " + S.describe.layer_format),
          ]),
          nav(),
          h("main", [
            S.error ? msg("bad", S.error) : null,
            S.note ? msg("ok", S.note) : null,
          ].concat(screen)),
          statusBar(),
          datalists(),
        ]);
      };
    },
  };

  createApp(App).mount("#app");
})();
