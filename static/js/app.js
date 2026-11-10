/* SinkronKhanza — UI. Vanilla JS, tanpa dependensi, tanpa innerHTML dari data (anti-XSS), CSP script-src 'self'. */
(() => {
"use strict";

/* ============================ util ============================ */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const CSRF = $('meta[name="csrf-token"]').content;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
  return el;
}
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  return append(el, kids);
}
const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

async function api(path, body, opts = {}) {
  const res = await fetch(path, {
    method: "POST", signal: opts.signal,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
    body: JSON.stringify(body || {}),
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* bukan JSON */ }
  if (!res.ok || !data) {
    const e = new Error((data && data.message) || `Permintaan gagal (HTTP ${res.status})`);
    e.status = res.status; e.data = data;
    throw e;
  }
  return data;
}

function toast(msg) {
  const t = h("div", { class: "toast", role: "status" }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 2700);
}
function countUp(el, to, dur = 900) {
  to = Number(to) || 0;
  if (reduced || to === 0) { el.textContent = to.toLocaleString("id-ID"); return; }
  const t0 = performance.now();
  (function step(now) {
    const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(to * e).toLocaleString("id-ID");
    if (p < 1) requestAnimationFrame(step);
  })(t0);
}
function setStatus(el, kind, text, spinner) {
  clear(el); el.dataset.kind = kind || "";
  if (spinner) el.append(h("span", { class: "spin" }));
  el.append(document.createTextNode(text || ""));
}
function download(name, text, type = "text/plain") {
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch (_) {
    const ta = h("textarea", { style: "position:fixed;opacity:0" }); ta.value = text;
    document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
  toast("Tersalin ke clipboard");
}
const today = () => new Date().toISOString().slice(0, 10);

document.addEventListener("pointerdown", e => {
  const b = e.target.closest(".btn");
  if (!b || b.disabled || reduced) return;
  const r = b.getBoundingClientRect(), d = Math.max(r.width, r.height);
  const s = h("span", { class: "ripple", style: `width:${d}px;height:${d}px;left:${e.clientX - r.left - d / 2}px;top:${e.clientY - r.top - d / 2}px` });
  b.append(s); setTimeout(() => s.remove(), 650);
});

/* ============================ monitor EKG ============================ */
const Monitor = (() => {
  const canvas = $("#ecg"), ctx = canvas.getContext("2d");
  const colors = { source: "#6cc8ff", target: "#ffcf5a" };
  const tr = { source: { state: "off" }, target: { state: "off" } };
  let W = 0, H = 0, running = false, lastT = 0, clock = 0;
  const SPEED = 170, GAP = 30;
  const g = (x, mu, s) => Math.exp(-((x - mu) ** 2) / (2 * s * s));
  const beat = p => 0.13 * g(p, .16, .028) - 0.12 * g(p, .295, .011) + 1.0 * g(p, .32, .010) - 0.26 * g(p, .347, .013) + 0.3 * g(p, .58, .05);
  const pvc = p => -0.15 * g(p, .2, .02) + 1.25 * g(p, .26, .035) - 0.55 * g(p, .4, .045) - 0.25 * g(p, .6, .05);
  function sample(t, time) {
    const kick = (t.kickT != null && time - t.kickT < 0.6) ? 0.85 * pvc((time - t.kickT) / 0.6) : 0;
    return base(t, time) + kick;
  }
  function base(t, time) {
    const noise = (Math.sin(time * 61) + Math.sin(time * 37.3 + 1)) * 0.012;
    switch (t.state) {
      case "ok": { const P = 1.15, k = Math.floor(time / P); return beat((time / P) - k) + noise; }
      case "busy": { const P = 0.46, k = Math.floor(time / P); return 0.85 * beat((time / P) - k) + noise * 3; }
      case "warn": { const P = 1.05, k = Math.floor(time / P), p = (time / P) - k; return (k % 4 === 3 ? pvc(p) : beat(p)) + noise; }
      default: return noise * 0.6;
    }
  }
  function layout() {
    const r = canvas.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2);
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    for (const key of Object.keys(tr)) {
      const el = $(`[data-trace="${key}"]`).getBoundingClientRect(), t = tr[key];
      t.x0 = el.left - r.left; t.w = Math.max(40, Math.floor(el.width)); t.cy = el.top - r.top + el.height / 2; t.amp = Math.min(el.height * .42, 40);
      t.buf = new Float32Array(t.w).fill(NaN); t.col = 0;
    }
    if (reduced) staticFill();
  }
  function staticFill() {
    for (const t of Object.values(tr)) for (let i = 0; i < t.w; i++) t.buf[i] = sample(t, i / SPEED);
    draw(null);
  }
  function draw(head) {
    ctx.clearRect(0, 0, W, H);
    ctx.lineJoin = "round"; ctx.lineCap = "round";
    for (const [key, t] of Object.entries(tr)) {
      ctx.strokeStyle = colors[key]; ctx.shadowColor = colors[key]; ctx.shadowBlur = t.state === "off" ? 0 : 7;
      ctx.globalAlpha = t.state === "off" ? 0.45 : 1; ctx.lineWidth = 2;
      ctx.beginPath(); let pen = false;
      for (let i = 0; i < t.w; i++) {
        const v = t.buf[i];
        if (Number.isNaN(v) || (head && ((i - t.col + t.w) % t.w) < GAP)) { pen = false; continue; }
        const x = t.x0 + i, y = t.cy - v * t.amp;
        if (!pen) { ctx.moveTo(x, y); pen = true; } else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }
    ctx.globalAlpha = 1; ctx.shadowBlur = 0;
  }
  function frame(now) {
    if (!running) return;
    const dt = Math.min(0.05, (now - lastT) / 1000 || 0.016); lastT = now; clock += dt;
    for (const t of Object.values(tr)) {
      const adv = Math.max(1, Math.round(dt * SPEED));
      for (let k = 0; k < adv; k++) {
        t.col = (t.col + 1) % t.w;
        t.buf[t.col] = sample(t, clock - (adv - 1 - k) / SPEED);
      }
    }
    draw(true);
    requestAnimationFrame(frame);
  }
  function start() {
    if (reduced || running) return;
    running = true; lastT = performance.now(); requestAnimationFrame(frame);
  }
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) running = false; else start();
  });
  return {
    init() { layout(); if (reduced) staticFill(); else start(); },
    layout,
    kick() { for (const t of Object.values(tr)) t.kickT = clock; },
    set(side, state) {
      tr[side].state = state;
      $(`#ch-${side}`).dataset.state = state === "busy" ? "ok" : state;
      if (reduced) staticFill();
    },
  };
})();

/* Setiap klik tombol membuat monitor berdenyut sekali */
document.addEventListener("click", e => { if (e.target.closest && e.target.closest("button, .btn")) Monitor.kick(); });

/* ============================ dialog ============================ */
const dlg = $("#dlg");
function ask({ title, message, okText = "Lanjutkan", cancelText = "Batal", confirmText = null, danger = false, info = false }) {
  return new Promise(resolve => {
    $("#dlg-title").textContent = title;
    $("#dlg-msg").textContent = message || "";
    const ok = $("#dlg-ok"), cancel = $("#dlg-cancel"), box = $("#dlg-confirm"), inp = $("#dlg-confirm-input");
    ok.textContent = okText; cancel.textContent = cancelText; cancel.hidden = info;
    ok.classList.toggle("danger", danger);
    box.hidden = !confirmText; inp.value = "";
    if (confirmText) { $("#dlg-confirm-label").textContent = `Ketik ${confirmText} untuk melanjutkan`; ok.disabled = true; } else ok.disabled = false;
    let done = false;
    const finish = async val => {
      if (done) return; done = true;
      dlg.removeAttribute("data-open"); await sleep(reduced ? 0 : 200);
      dlg.close(); cleanup(); resolve(val);
    };
    const onInput = () => { ok.disabled = inp.value.trim() !== confirmText; };
    const onSubmit = e => { e.preventDefault(); if (!ok.disabled) finish(true); };
    const onCancel = () => finish(false);
    const onEsc = e => { e.preventDefault(); finish(false); };
    const onBackdrop = e => { if (e.target === dlg) finish(false); };
    function cleanup() {
      inp.removeEventListener("input", onInput); $("#dlg-form").removeEventListener("submit", onSubmit);
      cancel.removeEventListener("click", onCancel); dlg.removeEventListener("cancel", onEsc); dlg.removeEventListener("click", onBackdrop);
    }
    inp.addEventListener("input", onInput); $("#dlg-form").addEventListener("submit", onSubmit);
    cancel.addEventListener("click", onCancel); dlg.addEventListener("cancel", onEsc); dlg.addEventListener("click", onBackdrop);
    dlg.showModal(); requestAnimationFrame(() => dlg.setAttribute("data-open", ""));
    if (confirmText) inp.focus(); else (info ? ok : cancel).focus();
  });
}
const notice = (title, message) => ask({ title, message, okText: "Mengerti", info: true });

/* ============================ koneksi ============================ */
const panels = { source: $(".conn.src"), target: $(".conn.tgt") };
const sideLabel = { source: "Source", target: "Target" };
$$(".conn").forEach(f => f.addEventListener("submit", e => e.preventDefault()));
const field = (side, name) => panels[side].elements[name];
function getConn(side) {
  const g = n => field(side, n).value;
  return { host: g("host").trim(), port: g("port").trim() || "3306", user: g("user").trim(), password: g("password"), database: g("database").trim(), label: g("label").trim() };
}
const connName = side => { const c = getConn(side); return c.label || c.database || ""; };

function updateNames() {
  for (const side of ["source", "target"]) {
    const n = connName(side), k = side === "source" ? "src" : "tgt";
    $(`#mon-${k}-db`).textContent = n || "Belum dipilih";
    $(`#rl-${k}`).textContent = n ? `${sideLabel[side]}: ${n}` : `${sideLabel[side]} belum dipilih`;
  }
  updateSteps();
}
function fillDbSelect(side, dbs, selected) {
  const sel = field(side, "database"), prev = selected || sel.value || "";
  clear(sel).append(h("option", { value: "" }, dbs.length ? "Pilih database" : "Tidak ada database"));
  dbs.forEach(d => sel.append(h("option", { value: d, selected: d === prev }, d)));
  if (prev && !dbs.includes(prev)) sel.append(h("option", { value: prev, selected: true }, `${prev} (tersimpan)`));
}
function fillBackupSelect(dbs, prev) {
  const sel = $("#backup-db"); clear(sel).append(h("option", { value: "" }, "Pilih database"));
  dbs.forEach(d => sel.append(h("option", { value: d, selected: d === prev }, d)));
}
const connected = { source: false, target: false };
async function testConn(side) {
  const st = $("[data-role=status]", panels[side]), c = getConn(side), key = side === "source" ? "src" : "tgt";
  setStatus(st, "", "Menguji koneksi dan memuat daftar database…", true);
  Monitor.set(side, "busy");
  try {
    const d = await api("/api/list-databases", { host: c.host, port: c.port, user: c.user, password: c.password });
    const dbs = d.databases || [];
    fillDbSelect(side, dbs, c.database);
    setStatus(st, "ok", `${d.message}. Pilih database di atas.`);
    connected[side] = true; Monitor.set(side, "ok");
    $(`#mon-${key}-state`).textContent = `Terhubung, MySQL ${d.version}`;
    if (side === "target") { $("#backup-panel").hidden = false; fillBackupSelect(dbs, field("target", "database").value || c.database); }
  } catch (e) {
    connected[side] = false; Monitor.set(side, "off");
    setStatus(st, "err", e.message); $(`#mon-${key}-state`).textContent = "Gagal terhubung";
  }
  updateNames();
}
$$("[data-act=test]").forEach(b => b.addEventListener("click", () => testConn(b.closest(".conn").dataset.side)));
["source", "target"].forEach(side => {
  panels[side].addEventListener("input", updateNames);
  panels[side].addEventListener("change", () => {
    updateNames();
    if (side === "target" && field(side, "database").value) {
      const b = $("#backup-db"); if (![...b.options].some(o => o.value === field(side, "database").value)) b.append(h("option", { value: field(side, "database").value }, field(side, "database").value));
      b.value = field(side, "database").value;
    }
  });
});

/* profil: password TIDAK pernah disimpan */
const PROFILE_KEY = "dbSyncKhanzaProfiles";
function profileData() {
  const strip = c => { const { password, ...rest } = c; return rest; };
  return { source: strip(getConn("source")), target: strip(getConn("target")), savedAt: new Date().toISOString() };
}
function applyProfile(p) {
  for (const side of ["source", "target"]) {
    const c = p[side]; if (!c) continue;
    for (const k of ["label", "host", "port", "user"]) if (c[k] != null) field(side, k).value = c[k];
    if (c.database) fillDbSelect(side, [c.database], c.database);
  }
  updateNames();
}
function readProfile() { try { return JSON.parse(localStorage.getItem(PROFILE_KEY) || "null"); } catch (_) { return null; } }
$("#btn-save").addEventListener("click", () => {
  try { localStorage.setItem(PROFILE_KEY, JSON.stringify(profileData())); toast("Koneksi tersimpan (tanpa password)"); }
  catch (e) { notice("Gagal menyimpan", e.message); }
});
$("#btn-load").addEventListener("click", () => {
  const p = readProfile();
  if (!p) return notice("Belum ada koneksi tersimpan", "Isi koneksi lalu klik Simpan koneksi.");
  applyProfile(p); toast("Koneksi dimuat. Isi password lalu uji koneksi.");
});

/* ============================ SQL highlight ============================ */
const KW = new Set("ALTER TABLE ADD COLUMN MODIFY CHANGE DROP INDEX KEY UNIQUE PRIMARY FOREIGN REFERENCES CONSTRAINT CREATE IF NOT EXISTS NULL DEFAULT AUTO_INCREMENT ENGINE CHARSET CHARACTER SET COLLATE COMMENT AFTER FIRST ON UPDATE DELETE CASCADE RESTRICT FULLTEXT SPATIAL USING INSERT INTO VALUES UNSIGNED ZEROFILL CURRENT_TIMESTAMP ROW_FORMAT".split(" "));
const SQL_RE = /(--[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)|('(?:[^'\\]|\\[\s\S]|'')*')|(`(?:[^`]|``)*`)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_][A-Za-z_0-9]*\b)/g;
function highlight(text) {
  const frag = document.createDocumentFragment(); let last = 0, m;
  SQL_RE.lastIndex = 0;
  while ((m = SQL_RE.exec(text))) {
    if (m.index > last) frag.append(text.slice(last, m.index));
    const cls = m[1] ? "q-c" : m[2] ? "q-s" : m[3] ? "q-i" : m[4] ? "q-n" : KW.has(m[5].toUpperCase()) ? "q-k" : null;
    frag.append(cls ? h("span", { class: cls }, m[0]) : m[0]); last = SQL_RE.lastIndex;
  }
  if (last < text.length) frag.append(text.slice(last));
  return frag;
}
function sqlBlock(title, text, { max = 60000 } = {}) {
  const shown = text.length > max ? text.slice(0, max) + "\n-- … dipotong untuk tampilan, gunakan Salin untuk SQL lengkap" : text;
  return h("div", { class: "sql-wrap" },
    h("div", { class: "sql-bar" }, h("span", {}, title), h("button", { type: "button", class: "btn ghost small", onclick: () => copyText(text) }, "Salin")),
    h("pre", { class: "sql" }, highlight(shown)));
}

/* ============================ hasil ============================ */
let lastResult = null, currentTab = null;
// Koneksi persis seperti saat membandingkan. Semua operasi atas hasil memakai salinan ini,
// bukan isi formulir saat ini, supaya SQL tidak pernah terkirim ke database lain.
let cmpConn = null;
const opConn = side => (cmpConn ? cmpConn[side] : getConn(side));
const connSig = c => [c.host, c.port, c.user, c.database].join("|");
function checkStale() {
  const note = $("#stale-note"); if (!note) return;
  if (!cmpConn) { note.hidden = true; return; }
  const changed = ["source", "target"].filter(sd => connSig(getConn(sd)) !== connSig(cmpConn[sd]));
  if (!changed.length) { note.hidden = true; return; }
  const nm = sd => `${cmpConn[sd].database} (${cmpConn[sd].host}:${cmpConn[sd].port})`;
  note.textContent = `Pilihan koneksi di formulir sudah berubah. Hasil di bawah tetap untuk Source ${nm("source")} dan Target ${nm("target")}, dan perubahan hanya akan ditulis ke Target itu. Klik "Bandingkan ulang" untuk memakai pilihan baru.`;
  note.hidden = false;
}
$$(".conn").forEach(f => { f.addEventListener("input", checkStale); f.addEventListener("change", checkStale); });
const dirLabel = d => d === "source_to_target" ? [h("i", { class: "ds" }, "Source"), " ke ", h("i", { class: "dt" }, "Target")] : [h("i", { class: "dt" }, "Target"), " ke ", h("i", { class: "ds" }, "Source")];

async function runCompare() {
  const src = getConn("source"), tgt = getConn("target"), btn = $("#btn-compare"), st = $("#compare-status");
  if (!src.database || !tgt.database) { setStatus(st, "err", "Pilih database Source dan Target dulu, lalu uji koneksinya."); return; }
  if (src.host === tgt.host && src.port === tgt.port && src.database === tgt.database) {
    if (!(await ask({ title: "Source dan Target sama", message: "Kedua sisi menunjuk database yang sama, jadi hasilnya pasti identik. Tetap lanjutkan?" }))) return;
  }
  btn.disabled = true; btn.dataset.busy = ""; $("#launch-label").textContent = "Membandingkan skema…";
  const tm = $("#launch-time"); tm.hidden = false; const t0 = performance.now();
  const tick = setInterval(() => { tm.textContent = ((performance.now() - t0) / 1000).toFixed(1) + " dtk"; }, 100);
  setStatus(st, "", "Membaca struktur kedua database. Jangan tutup halaman ini.", true);
  Monitor.set("source", "busy"); Monitor.set("target", "busy");
  try {
    const d = await api("/api/compare", { source: src, target: tgt, include_indexes: $("#opt-indexes").checked, include_fks: $("#opt-fks").checked, include_row_count: $("#opt-rowcount").checked });
    cmpConn = { source: { ...src }, target: { ...tgt } }; checkStale();
    lastResult = d; selections.source_to_target = selections.target_to_source = null; dataTables = [];
    setStatus(st, "ok", `Selesai dalam ${((performance.now() - t0) / 1000).toFixed(1)} detik.`);
    renderResults(d);
    updateSteps();
    $("#s-review").scrollIntoView({ behavior: reduced ? "auto" : "smooth" });
  } catch (e) {
    setStatus(st, "err", e.message);
    Monitor.set("source", connected.source ? "ok" : "off"); Monitor.set("target", connected.target ? "ok" : "off");
  } finally {
    clearInterval(tick); btn.disabled = false; delete btn.dataset.busy; $("#launch-label").textContent = "Bandingkan ulang"; tm.hidden = true;
  }
}
$("#btn-compare").addEventListener("click", runCompare);

function renderResults(d) {
  const s = d.summary;
  $("#s-review").hidden = false;
  $("#review-sub").textContent = `Dibandingkan pukul ${new Date(d.compared_at).toLocaleTimeString("id-ID")}: ${connName("source")} dengan ${connName("target")}.`;
  ["src", "tgt"].forEach(k => { const b = $(`#mon-${k}-n`); b.removeAttribute("data-empty"); b.textContent = ""; countUp(b, k === "src" ? s.source_table_count : s.target_table_count); });
  Monitor.set("source", "ok");
  const needsWork = s.only_in_source_count + s.tables_with_diff_count > 0;
  Monitor.set("target", needsWork ? "warn" : "ok");
  $("#mon-tgt-state").textContent = needsWork ? "Perlu disamakan dengan Source" : "Sudah sama dengan Source";
  const segs = [
    { cls: "add", n: s.only_in_source_count, label: "belum ada di Target" },
    { cls: "chg", n: s.tables_with_diff_count, label: "struktur berbeda" },
    { cls: "ext", n: s.only_in_target_count, label: "hanya di Target" },
    { cls: "same", n: s.identical_tables, label: "identik" },
  ];
  $$("#vitals .vital").forEach((v, i) => { v.removeAttribute("data-empty"); const b = $("b", v); b.textContent = ""; countUp(b, segs[i].n, 1100); });
  const total = segs.reduce((a, x) => a + x.n, 0) || 1, tri = clear($("#triage")), leg = clear($("#triage-legend"));
  segs.forEach(x => { tri.append(h("i", { class: x.cls, "data-w": (x.n / total * 100).toFixed(3), title: `${x.n} ${x.label}` })); leg.append(h("span", { class: `lg ${x.cls}` }, h("b", {}, x.n.toLocaleString("id-ID")), x.label)); });
  requestAnimationFrame(() => requestAnimationFrame(() => $$("#triage i").forEach(i => { i.style.width = i.dataset.w + "%"; })));
  $("#cta-count").textContent = (d.statements_source_to_target || []).length;
  $("#cta-bar").hidden = false;

  const tabs = [
    { id: "src-only", label: "Belum ada di Target", n: s.only_in_source_count, tone: "add" },
    { id: "diff", label: "Struktur berbeda", n: s.tables_with_diff_count, tone: "chg" },
    { id: "tgt-only", label: "Hanya di Target", n: s.only_in_target_count, tone: "ext" },
    { id: "same", label: "Identik", n: s.identical_tables, tone: "same" },
    { id: "views", label: "View", n: s.only_views_source + s.only_views_target + s.changed_views },
    { id: "data", label: "Sinkron data", n: null },
    { id: "history", label: "Riwayat", n: null },
  ];
  const bar = clear($("#tabs"));
  tabs.forEach(t => bar.append(h("button", { type: "button", class: `tab ${t.tone || ""}`, role: "tab", id: `tab-${t.id}`, "data-tab": t.id, "data-tone": t.tone, "aria-selected": "false", onclick: () => selectTab(t.id) },
    t.label, t.n != null && h("span", { class: "count" }, t.n))));
  bar.append(h("span", { class: "tab-ink", "aria-hidden": "true" }));
  const first = tabs.find(t => t.n > 0 && ["src-only", "diff", "tgt-only"].includes(t.id)) || tabs[3];
  selectTab(first.id, true);
}
function placeInk() {
  const t = $(".tab[aria-selected=true]"), ink = $(".tab-ink"); if (!t || !ink) return;
  ink.style.left = t.offsetLeft + "px"; ink.style.width = t.offsetWidth + "px";
}
addEventListener("resize", () => { placeInk(); Monitor.layout(); });
function selectTab(id, instant) {
  currentTab = id;
  $$(".tab").forEach(t => t.setAttribute("aria-selected", String(t.dataset.tab === id)));
  placeInk();
  const p = clear($("#panel")); p.removeAttribute("style");
  p.style.animation = "none"; void p.offsetWidth; p.style.animation = "";
  p.setAttribute("aria-labelledby", `tab-${id}`);
  ({ "src-only": renderSrcOnly, diff: renderDiff, "tgt-only": renderTgtOnly, same: renderSame, views: renderViews, data: renderData, history: renderHistory })[id](p);
  applySearch();
}
$("#search").addEventListener("input", applySearch);
function applySearch() {
  const q = $("#search").value.toLowerCase().trim();
  $$("#panel [data-name]").forEach(el => { el.hidden = !!q && !el.dataset.name.includes(q); });
}

/* ----- komponen baris ----- */
function row({ name, tone, tag, meta, body, i = 0 }) {
  const el = h("article", { class: `row ${tone}`, "data-name": name.toLowerCase(), style: `--i:${i}` });
  const pad = h("div", { class: "row-pad" });
  let built = false;
  const hd = h("button", { type: "button", class: "row-h", "aria-expanded": "false", onclick: () => {
    const open = el.toggleAttribute("data-open"); hd.setAttribute("aria-expanded", String(open));
    if (open && !built && body) { built = true; append(pad, [body()]); }
  } }, h("span", { class: "row-name" }, h("code", {}, name), tag && h("span", { class: "tag" }, tag)), h("span", { class: "meta" }, meta || ""), h("span", { class: "chev", "aria-hidden": "true" }));
  el.append(hd, h("div", { class: "row-body" }, h("div", { class: "row-in" }, pad)));
  return el;
}
function emptyWithLine(title, text) {
  const ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg"), path = document.createElementNS(ns, "path");
  svg.setAttribute("viewBox", "0 0 120 30"); svg.setAttribute("aria-hidden", "true");
  path.setAttribute("d", "M0 15h38l5-9 7 20 6-11h64"); path.setAttribute("stroke-linejoin", "round"); svg.append(path);
  return h("div", { class: "empty" }, svg, h("b", {}, title), h("span", {}, text));
}
function chips(arr, cls) { return h("div", { class: "chips" }, arr.map(x => h("span", { class: `chip ${cls}` }, x))); }
function colTable(cols) {
  return h("div", { class: "scroll-x" }, h("table", { class: "cols" },
    h("thead", {}, h("tr", {}, ["Kolom", "Tipe", "Null", "Key", "Default", "Extra", "Komentar"].map(x => h("th", {}, x)))),
    h("tbody", {}, cols.map(c => h("tr", {}, h("td", {}, c.Field), h("td", {}, c.Type), h("td", {}, c.Null), h("td", {}, c.Key || ""), h("td", {}, c.Default == null ? "NULL" : String(c.Default)), h("td", {}, c.Extra || ""), h("td", {}, c.Comment || ""))))));
}
function list(items) { const l = h("div", { class: "list" }); append(l, items); return l; }
const fmtRows = n => (n == null ? "" : `${Number(n).toLocaleString("id-ID")} baris`);

function renderSrcOnly(p) {
  const a = lastResult.detail_only_in_source;
  if (!a.length) return p.append(emptyWithLine("Semua tabel Source sudah ada di Target", "Tidak ada tabel baru yang perlu dibuat."));
  p.append(h("div", { class: "hint ok" }, "Tabel ini ada di Source tetapi belum ada di Target. Saat disinkronkan, tabelnya dibuat kosong di Target."),
    list(a.map((t, i) => row({ name: t.table, tone: "add", tag: "akan dibuat", i, meta: [`${t.column_count} kolom`, t.engine, fmtRows(t.row_count)].filter(Boolean).join(", "),
      body: () => h("div", { style: "display:grid;gap:14px" }, colTable(t.columns), sqlBlock("CREATE TABLE", t.create_sql || "")) }))));
}
function renderTgtOnly(p) {
  const a = lastResult.detail_only_in_target;
  if (!a.length) return p.append(emptyWithLine("Tidak ada tabel khusus Target", "Semua tabel Target juga ada di Source."));
  p.append(h("div", { class: "hint" }, "Tabel ini hanya ada di Target. Sinkronisasi Source ke Target tidak menyentuhnya."),
    list(a.map((t, i) => row({ name: t.table, tone: "ext", tag: "hanya di Target", i, meta: [`${t.column_count} kolom`, t.engine, fmtRows(t.row_count)].filter(Boolean).join(", "),
      body: () => h("div", { style: "display:grid;gap:14px" }, colTable(t.columns), sqlBlock("CREATE TABLE", t.create_sql || "")) }))));
}
function renderSame(p) {
  const a = lastResult.identical_tables;
  if (!a.length) return p.append(emptyWithLine("Belum ada tabel identik", "Semua tabel bersama memiliki perbedaan."));
  p.append(h("div", { class: "hint ok" }, "Struktur kolom, index, dan foreign key tabel-tabel ini sama persis. Buka satu untuk melihat kolomnya."),
    list(a.map((n, i) => row({ name: n, tone: "same", tag: "identik", i,
      body: () => { const box = h("div", {}, h("span", { class: "status" }, h("span", { class: "spin" }), "Memuat kolom…"));
        api("/api/table-detail", { side: "source", table: n, source: opConn("source"), target: opConn("target") })
          .then(d => { clear(box).append(colTable(d.columns)); }).catch(e => setStatus($(".status", box), "err", e.message)); return box; } }))));
}

const propList = diffs => h("dl", { class: "prop" }, diffs.map(d => [
  h("dt", {}, d.property),
  h("dd", {}, h("span", { class: "v-s" }, fmtVal(d.source)), "  →  ", h("span", { class: "v-t" }, fmtVal(d.target)))]));
const fmtVal = v => v == null ? "NULL" : Array.isArray(v) ? v.join(", ") : v === "" ? "(kosong)" : String(v);
const fkText = f => `(${f.columns.join(", ")}) mengacu ke ${f.ref_table}(${f.ref_columns.join(", ")})${f.on_delete !== "RESTRICT" ? " hapus: " + f.on_delete : ""}${f.on_update !== "RESTRICT" ? " ubah: " + f.on_update : ""}`;
function renderDiff(p) {
  const a = lastResult.table_diffs;
  if (!a.length) return p.append(emptyWithLine("Tidak ada perbedaan struktur", "Semua tabel bersama sama persis."));
  p.append(h("div", { class: "hint warn" }, "Tinjau SQL ALTER sebelum menjalankannya. Perubahan yang mengubah kolom atau index lama tidak jalan di Mode Aman."),
    list(a.map((t, i) => {
      const d = t.diff, ix = t.index_diff, fk = t.fk_diff, parts = [];
      if (d.only_in_source.length) parts.push(`${d.only_in_source.length} kolom baru`);
      if (d.modified.length) parts.push(`${d.modified.length} kolom diubah`);
      if (ix && (ix.only_in_source.length + ix.only_in_target.length + ix.modified.length)) parts.push("index");
      if (fk.only_in_source.length + fk.only_in_target.length) parts.push("foreign key");
      if (t.meta_diff.length) parts.push(t.meta_diff.map(m => m.property.toLowerCase()).join(" dan "));
      return row({ name: t.table, tone: "chg", tag: "berbeda", i, meta: parts.join(", "), body: () => diffBody(t) });
    })));
}
function diffBody(t) {
  const d = t.diff, ix = t.index_diff, fk = t.fk_diff, out = [];
  const sec = (title, tone, ...kids) => h("div", { class: `diff-line ${tone}` }, h("span", { class: "lbl" }, title), ...kids);
  if (d.only_in_source.length) out.push(sec("Kolom ada di Source, belum di Target", "add", chips(d.only_in_source, "add")));
  if (d.only_in_target.length) out.push(sec("Kolom hanya ada di Target", "ext", chips(d.only_in_target, "ext")));
  if (d.modified.length) out.push(sec("Kolom berbeda (nilai Source → nilai Target)", "chg", ...d.modified.map(m => h("div", {}, h("code", {}, m.column), propList(m.differences)))));
  if (ix) {
    if (ix.only_in_source.length) out.push(sec("Index ada di Source, belum di Target", "add", chips(ix.only_in_source, "add")));
    if (ix.only_in_target.length) out.push(sec("Index hanya ada di Target", "ext", chips(ix.only_in_target, "ext")));
    if (ix.modified.length) out.push(sec("Index berbeda", "chg", ...ix.modified.map(m => h("div", {}, h("code", {}, m.index), propList(m.differences)))));
  }
  if (fk.only_in_source.length) out.push(sec("Foreign key ada di Source, belum di Target", "add", chips(fk.only_in_source.map(fkText), "add")));
  if (fk.only_in_target.length) out.push(sec("Foreign key hanya ada di Target", "ext", chips(fk.only_in_target.map(fkText), "ext")));
  if (t.meta_diff.length) out.push(sec("Properti tabel", "chg", propList(t.meta_diff)));
  const sqlOf = items => items.map(x => x.sql).join("\n") || "-- tidak ada perubahan";
  out.push(h("div", { class: "sec-t" }, h("span", { class: "dir" }, "SQL ", ...dirLabel("source_to_target")), kindChips(t.alter_source_to_target)), sqlBlock("ALTER, dijalankan di Target", sqlOf(t.alter_source_to_target)));
  out.push(h("div", { class: "sec-t" }, h("span", { class: "dir" }, "SQL ", ...dirLabel("target_to_source")), kindChips(t.alter_target_to_source)), sqlBlock("ALTER, dijalankan di Source", sqlOf(t.alter_target_to_source)));
  return h("div", { style: "display:grid;gap:14px" }, ...out);
}
function kindChips(items) {
  return h("span", { class: "chips" }, items.filter(x => !x.manual).map(x => h("span", { class: `kind ${x.additive ? "safe" : "warn"}`, title: x.additive ? "Hanya menambah" : "Mengubah yang sudah ada" }, x.kind.toLowerCase())));
}
function renderViews(p) {
  const v = lastResult.views, blocks = [];
  const group = (title, tone, arr) => arr.length && blocks.push(h("div", { class: `diff-line ${tone}` }, h("span", { class: "lbl" }, title), chips(arr, tone)));
  group("View ada di Source, belum di Target", "add", v.only_in_source);
  group("View hanya ada di Target", "ext", v.only_in_target);
  group("View di kedua sisi tetapi definisinya berbeda", "chg", v.changed);
  if (!blocks.length) return p.append(emptyWithLine("View sama di kedua sisi", `${v.common.length} view ditemukan di kedua database.`));
  p.append(h("div", { class: "hint" }, "View hanya dibandingkan, tidak disinkronkan otomatis, karena definisinya memuat nama database. Salin dari SHOW CREATE VIEW bila perlu."), h("div", { style: "display:grid;gap:18px" }, ...blocks));
}

/* ============================ drawer penerapan ============================ */
const drawer = $("#drawer");
const selections = { source_to_target: null, target_to_source: null };
let syncDir = "source_to_target", combinedSql = "", running = false, cancelRun = false, ranOk = false;
const dirNow = () => $('input[name="sync-dir"]:checked').value;
const stmtsOf = dir => (lastResult && lastResult[`statements_${dir}`]) || [];
function selOf(dir) { if (!selections[dir]) selections[dir] = new Set(stmtsOf(dir).map(s => s.id)); return selections[dir]; }
function activeStmts(dir) { const safe = $("#opt-safe").checked; return stmtsOf(dir).filter(s => !safe || s.additive); }
function chosen(dir) { const sel = selOf(dir); return activeStmts(dir).filter(s => sel.has(s.id)); }
const execSide = dir => dir === "source_to_target" ? "target" : "source";

function openDrawer() {
  if (!lastResult) return;
  ranOk = false; $("#btn-recompare").hidden = true; $("#run-area").hidden = true; $("#btn-run").hidden = false;
  drawer.showModal(); requestAnimationFrame(() => drawer.setAttribute("data-open", ""));
  renderDrawer();
}
async function closeDrawer() {
  if (running) return toast("Sedang berjalan. Batalkan dulu bila ingin menutup.");
  drawer.removeAttribute("data-open"); await sleep(reduced ? 0 : 480); drawer.close();
}
drawer.addEventListener("cancel", e => { e.preventDefault(); closeDrawer(); });
$("[data-close]", drawer).addEventListener("click", closeDrawer);
$("#btn-sync").addEventListener("click", openDrawer);
$("#step-apply").addEventListener("click", e => { if (lastResult) { e.preventDefault(); openDrawer(); } });

function renderDrawer() {
  const dir = dirNow(); syncDir = dir;
  const target = execSide(dir);
  $("#dr-sub").replaceChildren(...["Perubahan ditulis ke ", h("b", {}, `${sideLabel[target]}: ${connName(target) || "(belum dipilih)"}`)]);
  renderStmtList(); renderNotes(dir); updateCombined();
}
function renderStmtList() {
  const dir = dirNow(), all = stmtsOf(dir), act = activeStmts(dir), sel = selOf(dir);
  const q = $("#stmt-filter").value.toLowerCase().trim();
  const box = clear($("#stmts")), note = clear($("#dr-hidden-note"));
  const hidden = all.length - act.length;
  if (hidden > 0) note.append(h("div", { class: "hint" }, `${hidden} statement yang mengubah atau menghapus struktur lama disembunyikan oleh Mode Aman. Matikan Mode Aman untuk melihatnya.`));
  const shown = act.filter(s => !q || s.table.toLowerCase().includes(q));
  if (!shown.length) box.append(emptyWithLine(all.length ? "Tidak ada yang cocok" : "Tidak ada statement untuk arah ini", all.length ? "Ubah filter nama tabel." : "Struktur kedua sisi sudah sama untuk arah ini."));
  shown.forEach((s, i) => {
    const item = h("div", { class: "stmt", style: `--i:${i}` });
    const cb = h("input", { type: "checkbox", checked: sel.has(s.id) || null, "aria-label": `Pilih ${s.kind} ${s.table}`, onchange: () => { cb.checked ? sel.add(s.id) : sel.delete(s.id); updateCombined(); } });
    let built = false;
    const tg = h("button", { type: "button", class: "btn quiet small", onclick: () => {
      const open = item.toggleAttribute("data-open"); tg.textContent = open ? "Sembunyikan" : "Lihat SQL";
      if (open && !built) { built = true; $(".stmt-sql > div", item).append(h("pre", { class: "sql" }, highlight(s.sql))); }
    } }, "Lihat SQL");
    item.append(h("div", { class: "stmt-h" }, h("label", { class: "check" }, cb), h("span", { class: `kind ${s.additive ? "safe" : "warn"}` }, s.kind.toLowerCase()), h("code", {}, s.table), tg),
      h("div", { class: "stmt-sql" }, h("div", {})));
    box.append(item);
  });
}
function renderNotes(dir) {
  const notes = (lastResult[`notes_${dir}`]) || [], fold = $("#notes-fold");
  fold.hidden = !notes.length; if (!notes.length) return;
  $("#notes-sum").textContent = `${notes.length} hal perlu ditangani manual (tidak dijalankan otomatis)`;
  clear($("#notes-list")).append(...notes.map(n => h("div", {}, h("code", {}, n.table), ": ", n.text)));
}
function updateCombined() {
  const dir = dirNow(), sel = chosen(dir);
  combinedSql = sel.length ? `-- SinkronKhanza, ${today()}\n-- Arah: ${dir === "source_to_target" ? "Source ke Target" : "Target ke Source"}\n\nSET FOREIGN_KEY_CHECKS = 0;\n\n${sel.map(s => s.sql).join("\n\n")}\n\nSET FOREIGN_KEY_CHECKS = 1;\n` : "-- tidak ada statement yang dicentang";
  const box = clear($("#sql-box")); box.append(highlight(combinedSql.length > 40000 ? combinedSql.slice(0, 40000) + "\n-- … dipotong untuk tampilan" : combinedSql));
  $("#sql-sum").textContent = `SQL gabungan: ${sel.length} dari ${activeStmts(dir).length} statement dipilih`;
  $("#btn-run").disabled = !sel.length || running;
}
$$('input[name="sync-dir"]').forEach(r => r.addEventListener("change", renderDrawer));
$("#opt-safe").addEventListener("change", () => { renderStmtList(); updateCombined(); });
$("#stmt-filter").addEventListener("input", renderStmtList);
$("#btn-all").addEventListener("click", () => { const s = selOf(dirNow()); activeStmts(dirNow()).forEach(x => s.add(x.id)); renderStmtList(); updateCombined(); });
$("#btn-none").addEventListener("click", () => { const s = selOf(dirNow()); activeStmts(dirNow()).forEach(x => s.delete(x.id)); renderStmtList(); updateCombined(); });
$("#btn-copy-sql").addEventListener("click", () => copyText(combinedSql));
$("#btn-dl-sql").addEventListener("click", () => download(`db-sync-khanza-${today()}.sql`, combinedSql, "application/sql"));
$("#btn-cancel-run").addEventListener("click", () => { cancelRun = true; $("#btn-cancel-run").disabled = true; });
$("#btn-recompare").addEventListener("click", async () => { await closeDrawer(); runCompare(); });

/* alat perbaikan statement gagal */
const stripFK = sql => sql.replace(/,?\s*CONSTRAINT\s+`[^`]+`\s+FOREIGN\s+KEY\s*\([^)]*\)\s*REFERENCES\s+`[^`]+`\s*\([^)]*\)[^,)]*/gi, "").replace(/,?\s*FOREIGN\s+KEY\s*\([^)]*\)\s*REFERENCES\s+`[^`]+`\s*\([^)]*\)[^,)]*/gi, "").replace(/,\s*\)/g, "\n)");
const ifNotExists = sql => /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS/i.test(sql) ? sql : sql.replace(/CREATE\s+TABLE\s+/i, "CREATE TABLE IF NOT EXISTS ");
function uniquify(sql) {
  const sfx = "_s" + String(Date.now()).slice(-6);
  return sql.replace(/CONSTRAINT\s+`([^`]+)`/gi, (m, n) => /_s\d+$/.test(n) ? m : `CONSTRAINT \`${n}${sfx}\``)
    .replace(/,\s*KEY\s+`([^`]+)`/gi, (m, n) => (n.toUpperCase() === "PRIMARY" || /_s\d+$/.test(n)) ? m : `, KEY \`${n}${sfx}\``)
    .replace(/,\s*UNIQUE\s+KEY\s+`([^`]+)`/gi, (m, n) => /_s\d+$/.test(n) ? m : `, UNIQUE KEY \`${n}${sfx}\``);
}
function explain(msg) {
  const m = (msg || "").toLowerCase();
  if (m.includes("ditolak")) return "Server menolak statement ini: di luar yang diizinkan (CREATE/ALTER TABLE) atau tidak lolos Mode Aman. Ubah SQL atau matikan Mode Aman bila memang perlu.";
  if (m.includes("errno: 121") || m.includes("duplicate key on write")) return "Errno 121: nama KEY/CONSTRAINT bentrok dengan objek lain di database, atau ada sisa tabel dari percobaan sebelumnya. Coba 'Perbaiki errno 121', lalu jalankan ulang.";
  if (m.includes("errno: 150") || m.includes("foreign key")) return "Foreign key gagal: tabel atau kolom referensi belum ada, atau tipe dan charset berbeda. Coba 'Buat tanpa FOREIGN KEY'.";
  if (m.includes("already exists")) return "Objek sudah ada. Boleh dilewati, atau pakai CREATE IF NOT EXISTS.";
  if (m.includes("duplicate column")) return "Kolom sudah ada. Statement ini boleh dilewati.";
  if (m.includes("duplicate")) return "Nama index atau constraint duplikat. Ubah namanya atau buang FOREIGN KEY.";
  return "Edit SQL di bawah sesuai pesan error, lalu klik Perbaiki dan jalankan ulang.";
}
function failItem(index, st, message, side, safe) {
  const ta = h("textarea", { spellcheck: "false" }); ta.value = st.sql;
  const msg = h("span", { class: "dim" }), box = h("div", { class: "fail" });
  const btns = [];
  const tool = (label, fn) => h("button", { type: "button", class: "btn quiet small", style: "--fg:#cfe9ef;border-color:#476c7a", onclick: () => { ta.value = fn(ta.value); msg.textContent = "SQL disesuaikan. Klik Perbaiki dan jalankan ulang."; } }, label);
  if (/^\s*CREATE\s+TABLE/i.test(st.sql)) {
    if (/errno:\s*150|foreign key/i.test(message)) btns.push(tool("Buat tanpa FOREIGN KEY", stripFK));
    if (/errno:\s*121|duplicate key on write/i.test(message)) btns.push(tool("Perbaiki errno 121", s => ifNotExists(uniquify(stripFK(s)))));
    btns.push(tool("CREATE IF NOT EXISTS", ifNotExists));
  }
  const retry = h("button", { type: "button", class: "btn small", onclick: async () => {
    const sql = ta.value.trim(); if (!sql) return; retry.disabled = true; msg.textContent = "Menjalankan…";
    try {
      await api("/api/execute-one", { side, sql, safe_mode: safe, source: opConn("source"), target: opConn("target") });
      box.classList.add("fixed"); clear(box).append(h("div", { class: "ok" }, `Berhasil diperbaiki: [${index + 1}] ${st.table}. Sudah ada di database tujuan.`)); toast("Statement berhasil dijalankan");
    } catch (e) { retry.disabled = false; msg.textContent = ""; msg.append(h("span", { class: "bad" }, e.message)); }
  } }, "Perbaiki dan jalankan ulang");
  box.append(h("b", { class: "bad" }, `Gagal [${index + 1}] ${st.table}`), h("div", { class: "bad" }, message), h("div", { class: "tip" }, explain(message)), ta, h("div", { class: "btn-row" }, ...btns, retry, msg));
  return box;
}
const logLine = (cls, text) => { const l = h("div", { class: `l ${cls}` }, text); const log = $("#run-log"); log.append(l); log.scrollTop = log.scrollHeight; return l; };

$("#btn-run").addEventListener("click", async () => {
  const dir = dirNow(), side = execSide(dir), sel = chosen(dir), safe = $("#opt-safe").checked;
  if (!sel.length) return notice("Belum ada yang dipilih", "Centang minimal satu statement.");
  const c = opConn(side);
  const go = await ask({
    title: `Tulis ke ${sideLabel[side]}?`, danger: true, okText: "Jalankan sekarang", confirmText: c.database,
    message: `${sel.length} statement akan dijalankan ke ${sideLabel[side]}: ${connName(side)} (${c.host}:${c.port}).\nMode Aman: ${safe ? "aktif" : "MATI, bisa mengubah kolom dan index yang sudah ada"}.\n\nPastikan backup sudah dibuat. DDL di MySQL tidak bisa di-rollback.`,
  });
  if (!go) return;
  running = true; cancelRun = false; $("#btn-run").disabled = true; $("#btn-cancel-run").disabled = false;
  $("#run-area").hidden = false; clear($("#run-log")); $("#prog").classList.remove("done");
  const bar = $("#prog i"), txt = $("#prog-text"); bar.style.width = "0%";
  let okN = 0, failN = 0;
  $("#run-area").scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "nearest" });
  for (let i = 0; i < sel.length; i++) {
    if (cancelRun) break;
    const st = sel[i];
    setStatus(txt, "", `Menjalankan ${i + 1} dari ${sel.length}: ${st.table}`, true); bar.style.width = (i / sel.length * 100) + "%";
    try {
      await api("/api/execute-one", { side, sql: st.sql, safe_mode: safe, source: opConn("source"), target: opConn("target") });
      okN++; logLine("ok", `Berhasil [${i + 1}] ${st.kind.toLowerCase()} ${st.table}`);
    } catch (e) { failN++; $("#run-log").append(failItem(i, st, e.message, side, safe)); }
  }
  running = false; bar.style.width = "100%"; $("#prog").classList.add("done");
  const cancelled = cancelRun;
  setStatus(txt, failN ? "err" : "ok", `${cancelled ? "Dibatalkan" : "Selesai"}: ${okN} berhasil, ${failN} gagal.`);
  $("#btn-cancel-run").disabled = true; $("#btn-run").disabled = false; $("#btn-recompare").hidden = false;
  saveHistory({ at: new Date().toISOString(), type: cancelled ? "struktur (dibatalkan)" : "struktur", database: c.database, side, ok: okN, fail: failN, source_label: connName("source"), target_label: connName("target") });
  if (!failN && !cancelled) { ranOk = true; updateSteps(); }
  toast(failN ? "Selesai dengan beberapa kegagalan" : "Sinkronisasi struktur selesai");
  if (!failN && !cancelled) document.dispatchEvent(new CustomEvent("sk:celebrate"));
});

/* ============================ sinkron data ============================ */
let dataTables = [], dataCancel = null, dataRunning = false;
const badgeFor = t => !t.has_pk ? ["ext", "tanpa PK"] : t.risky ? ["ext", "transaksi, berisiko"] : t.large ? ["chg", "besar"] : ["add", "aman"];
function renderData(p) {
  p.append(h("div", { class: "hint warn" }, "Sinkron data hanya menyisipkan (INSERT) baris yang ada di Source tetapi belum ada di Target, berdasarkan PRIMARY KEY. Tidak ada UPDATE atau DELETE. Baris yang sudah ada tidak ditimpa, walau isinya berbeda."));
  const maxRows = h("input", { type: "number", id: "data-max", value: "500", min: "1", max: "20000" });
  const dry = h("input", { type: "checkbox", id: "data-dry", checked: true });
  const exact = h("input", { type: "checkbox", id: "data-exact" });
  const status = h("div", { class: "status", id: "data-status", role: "status" });
  const listEl = h("div", { class: "list", id: "data-list" });
  const logEl = h("div", { class: "log", id: "data-log", hidden: true });
  const bRun = h("button", { type: "button", class: "btn", onclick: () => runData(false) }, "Jalankan sinkron data");
  const bCancel = h("button", { type: "button", class: "btn quiet", id: "data-cancel", disabled: true, onclick: () => dataCancel && dataCancel.abort() }, "Batalkan");
  p.append(
    h("div", { class: "data-tools" },
      h("label", { class: "field" }, h("span", {}, "Maks baris per tabel"), maxRows),
      h("label", { class: "check" }, dry, "Pratinjau dulu (tidak menulis)"),
      h("label", { class: "check" }, exact, "Hitung baris pasti (lebih lambat)"),
      h("button", { type: "button", class: "btn quiet small", onclick: loadOverview }, "Muat daftar tabel"),
      h("button", { type: "button", class: "btn quiet small", onclick: () => { $$(".data-check").forEach(cb => { const t = dataTables[+cb.dataset.i]; cb.checked = !!(t && t.has_pk && !t.large && !t.risky); }); } }, "Centang yang aman")),
    h("div", { class: "btn-row", style: "margin-bottom:10px" }, h("button", { type: "button", class: "btn quiet", onclick: () => runData(true) }, "Pratinjau INSERT"), bRun, bCancel), status, listEl, logEl);
  paintData();
}
async function loadOverview() {
  const st = $("#data-status"); setStatus(st, "", "Memuat daftar tabel bersama…", true);
  try {
    const d = await api("/api/data-overview", { source: opConn("source"), target: opConn("target"), exact: $("#data-exact").checked });
    dataTables = d.tables; paintData();
    setStatus(st, "ok", `${d.count} tabel bersama.${d.approx ? " Jumlah baris adalah perkiraan; centang 'Hitung baris pasti' bila perlu." : ""}`);
  } catch (e) { setStatus(st, "err", e.message); }
}
function paintData() {
  const box = clear($("#data-list")); if (!box) return;
  if (!dataTables.length) return box.append(emptyWithLine("Belum ada daftar tabel", "Klik Muat daftar tabel."));
  dataTables.forEach((t, i) => {
    const [tone, label] = badgeFor(t), approx = t.approx ? "≈ " : "";
    const cb = h("input", { type: "checkbox", class: "data-check", "data-i": i, disabled: !t.has_pk || null, "aria-label": `Pilih ${t.table}` });
    const r = h("article", { class: `row ${tone}`, "data-name": t.table.toLowerCase(), style: `--i:${i}` },
      h("div", { class: "drow" }, h("label", { class: "check" }, cb), h("span", { class: "row-name" }, h("code", {}, t.table), h("span", { class: "tag" }, label)),
        h("span", { class: "meta" }, `Source ${approx}${t.rows_source ?? "?"}, Target ${approx}${t.rows_target ?? "?"}${t.pk.length ? ", PK: " + t.pk.join(", ") : ""}`)));
    box.append(r);
  });
  applySearch();
}
async function runData(forcePreview) {
  if (dataRunning) return;
  const sel = $$(".data-check").filter(c => c.checked).map(c => dataTables[+c.dataset.i]);
  if (!sel.length) return notice("Belum ada tabel dipilih", "Muat daftar tabel, lalu centang tabel yang punya PRIMARY KEY.");
  const dry = forcePreview || $("#data-dry").checked, maxRows = Math.max(1, +$("#data-max").value || 500), tgt = opConn("target");
  if (!dry) {
    const risky = sel.filter(t => t.risky).length;
    const ok = await ask({ title: "Tulis data ke Target?", danger: true, okText: "Sisipkan sekarang", confirmText: tgt.database,
      message: `${sel.length} tabel, maksimal ${maxRows} baris per tabel, ke Target: ${connName("target")}.\nHanya INSERT baris yang hilang.${risky ? `\n\nPerhatian: ${risky} tabel yang dipilih adalah tabel transaksi atau berisiko.` : ""}\n\nPastikan backup Target sudah dibuat.` });
    if (!ok) return;
  }
  dataRunning = true; dataCancel = new AbortController(); $("#data-cancel").disabled = false;
  const log = $("#data-log"); log.hidden = false; clear(log); const st = $("#data-status");
  if (dry) log.append(h("div", { class: "l info" }, "PRATINJAU. Tidak ada yang ditulis ke database."));
  let missing = 0, okN = 0, failN = 0;
  try {
    for (let i = 0; i < sel.length; i++) {
      if (dataCancel.signal.aborted) break;
      const t = sel[i]; setStatus(st, "", `${dry ? "Pratinjau" : "Sinkron"} ${i + 1} dari ${sel.length}: ${t.table}`, true);
      const base = { source: opConn("source"), target: opConn("target"), table: t.table, max_rows: maxRows };
      try {
        if (dry) {
          const d = await api("/api/data-diff", base, { signal: dataCancel.signal });
          missing += d.missing_count;
          logLine2(log, d.missing_count ? "info" : "dim", `${t.table}: ${d.missing_count} baris belum ada di Target (dipindai ${d.scanned_source.toLocaleString("id-ID")})${d.truncated ? ", ada lagi di luar batas" : ""}${d.inserts[0] ? "\n   " + d.inserts[0].slice(0, 220) : ""}`);
        } else {
          const d = await api("/api/data-sync", base, { signal: dataCancel.signal });
          okN += d.success_count; failN += d.error_count; missing += d.missing_count;
          logLine2(log, d.error_count ? "bad" : d.missing_count ? "ok" : "dim", d.message + (d.truncated ? " (masih ada baris lain, naikkan batas)" : ""));
          d.errors.slice(0, 5).forEach(er => logLine2(log, "bad", `   ${JSON.stringify(er.key)}: ${er.message}`));
        }
      } catch (e) { if (e.name === "AbortError") break; failN++; logLine2(log, "bad", `${t.table}: ${e.message}`); }
    }
  } finally {
    const aborted = dataCancel.signal.aborted; dataRunning = false; dataCancel = null; $("#data-cancel").disabled = true;
    setStatus(st, failN ? "err" : "ok", `${aborted ? "Dibatalkan. " : ""}${dry ? `Pratinjau: ${missing} baris kandidat.` : `Berhasil ${okN}, gagal ${failN}.`}`);
    saveHistory({ at: new Date().toISOString(), type: dry ? "data (pratinjau)" : "data", database: tgt.database, side: "target", ok: dry ? missing : okN, fail: failN, source_label: connName("source"), target_label: connName("target") });
  }
}
function logLine2(log, cls, text) { log.append(h("div", { class: `l ${cls}`, style: "white-space:pre-wrap" }, text)); log.scrollTop = log.scrollHeight; }

/* ============================ riwayat ============================ */
const HKEY = "dbSyncKhanzaHistory";
function readHistory() { try { return JSON.parse(localStorage.getItem(HKEY) || "[]"); } catch (_) { return []; } }
function saveHistory(entry) { try { const a = readHistory(); a.unshift(entry); localStorage.setItem(HKEY, JSON.stringify(a.slice(0, 30))); } catch (_) { /* penyimpanan penuh/diblokir */ } }
function renderHistory(p) {
  const a = readHistory();
  p.append(h("div", { class: "btn-row", style: "margin-bottom:12px" }, h("button", { type: "button", class: "btn quiet small", onclick: async () => { if (await ask({ title: "Hapus riwayat?", message: "Semua riwayat sync di browser ini dihapus.", okText: "Hapus", danger: true })) { localStorage.removeItem(HKEY); selectTab("history"); } } }, "Hapus riwayat")));
  if (!a.length) return p.append(emptyWithLine("Belum ada riwayat", "Riwayat tersimpan di browser ini, maksimal 30 entri. Password tidak pernah dicatat."));
  p.append(list(a.map((x, i) => row({ name: new Date(x.at).toLocaleString("id-ID"), tone: x.fail ? "ext" : "add", tag: x.type, i, meta: `${x.database || ""}: ${x.ok || 0} berhasil, ${x.fail || 0} gagal${x.source_label ? `, ${x.source_label} ke ${x.target_label}` : ""}` }))));
}

/* ============================ backup & laporan ============================ */
$("#btn-backup").addEventListener("click", async () => {
  const db = $("#backup-db").value, st = $("#backup-status"), btn = $("#btn-backup");
  if (!db) return notice("Pilih database", "Pilih database Target yang akan di-backup.");
  const structOnly = $('input[name="backup-mode"]:checked').value === "structure";
  if (!(await ask({ title: "Buat backup?", message: `Database: ${db}\nIsi: ${structOnly ? "struktur saja" : "struktur dan data"}\n\nFile SQL akan diunduh ke komputer ini. Database besar bisa butuh beberapa menit.`, okText: "Buat backup" }))) return;
  const c = getConn("target"); btn.disabled = true; setStatus(st, "", "Membuat backup. Jangan tutup halaman…", true);
  try {
    const res = await fetch("/api/backup", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify({ host: c.host, port: c.port, user: c.user, password: c.password, database: db, structure_only: structOnly }) });
    if (!res.ok) { let m = `HTTP ${res.status}`; try { m = (await res.json()).message || m; } catch (_) {} throw new Error(m); }
    const blob = await res.blob(), method = res.headers.get("X-Backup-Method");
    const tail = await blob.slice(Math.max(0, blob.size - 400)).text(), complete = /Dump completed/i.test(tail);
    const name = (/filename="?([^";]+)"?/i.exec(res.headers.get("Content-Disposition") || "") || [])[1] || `backup_${db}.sql`;
    const a = h("a", { href: URL.createObjectURL(blob), download: name }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    const mb = (blob.size / 1048576).toFixed(1);
    setStatus(st, complete ? "ok" : "err", complete ? `Backup selesai (${method}, ${mb} MB): ${name}${method === "pymysql-fallback" ? ". Cadangan cadangan ini hanya berisi tabel, tanpa view/trigger/routine." : ""}` : `Backup TIDAK LENGKAP (${mb} MB). Jangan dipakai; periksa pesan error di server.`);
    saveHistory({ at: new Date().toISOString(), type: "backup", database: db, side: "target", ok: complete ? 1 : 0, fail: complete ? 0 : 1, target_label: connName("target") });
  } catch (e) { setStatus(st, "err", `Gagal backup: ${e.message}`); }
  btn.disabled = false;
});
$("#btn-export").addEventListener("click", () => {
  const d = lastResult; if (!d) return; const s = d.summary, L = [];
  L.push("=".repeat(66), "DB SYNC KHANZA - LAPORAN PERBANDINGAN SKEMA", `Waktu  : ${d.compared_at}`, `Source : ${connName("source")}`, `Target : ${connName("target")}`, "=".repeat(66), "",
    `Tabel Source            : ${s.source_table_count}`, `Tabel Target            : ${s.target_table_count}`, `Identik                 : ${s.identical_tables}`,
    `Belum ada di Target     : ${s.only_in_source_count}`, `Hanya ada di Target     : ${s.only_in_target_count}`, `Struktur berbeda        : ${s.tables_with_diff_count}`, `View beda definisi      : ${s.changed_views}`, "");
  if (d.only_in_source.length) L.push("-".repeat(50), "BELUM ADA DI TARGET (akan dibuat):", ...d.only_in_source.map(t => "  + " + t), "");
  if (d.only_in_target.length) L.push("-".repeat(50), "HANYA ADA DI TARGET:", ...d.only_in_target.map(t => "  - " + t), "");
  if (d.table_diffs.length) {
    L.push("-".repeat(50), "TABEL DENGAN PERBEDAAN STRUKTUR:");
    d.table_diffs.forEach(td => {
      L.push("", `  [${td.table}]`);
      if (td.diff.only_in_source.length) L.push(`    Kolom di Source saja : ${td.diff.only_in_source.join(", ")}`);
      if (td.diff.only_in_target.length) L.push(`    Kolom di Target saja : ${td.diff.only_in_target.join(", ")}`);
      td.diff.modified.forEach(m => L.push(`    Kolom berbeda: ${m.column} (${m.differences.map(x => `${x.property}: ${fmtVal(x.source)} -> ${fmtVal(x.target)}`).join("; ")})`));
      const ix = td.index_diff; if (ix) { ix.only_in_source.length && L.push(`    Index di Source saja : ${ix.only_in_source.join(", ")}`); ix.only_in_target.length && L.push(`    Index di Target saja : ${ix.only_in_target.join(", ")}`); ix.modified.forEach(m => L.push(`    Index berbeda: ${m.index} (${m.differences.map(x => `${x.property}: ${fmtVal(x.source)} -> ${fmtVal(x.target)}`).join("; ")})`)); }
      td.fk_diff.only_in_source.forEach(f => L.push(`    FK di Source saja    : ${f.name} ${fkText(f)}`)); td.fk_diff.only_in_target.forEach(f => L.push(`    FK di Target saja    : ${f.name} ${fkText(f)}`));
      td.meta_diff.forEach(m => L.push(`    ${m.property}: ${fmtVal(m.source)} -> ${fmtVal(m.target)}`));
    });
  }
  download(`db-sync-laporan-${today()}.txt`, L.join("\n") + "\n"); toast("Laporan diunduh");
});

/* ============================ langkah ============================ */
function updateSteps() {
  const done = {
    connect: !!(field("source", "database").value && field("target", "database").value),
    compare: !!lastResult,
    review: !!lastResult && !$("#s-review").hidden,
    apply: ranOk,
  };
  const order = ["connect", "compare", "review", "apply"]; let cur = order.find(k => !done[k]) || "apply";
  $$("#steps li").forEach(li => { const k = li.dataset.step; li.toggleAttribute("data-done", done[k]); li.toggleAttribute("data-current", k === cur); });
}

/* ============================ mulai ============================ */
(function init() {
  const p = readProfile(); if (p) applyProfile(p);
  updateNames();
  $("#cta-bar").hidden = true;
  const start = () => Monitor.init();
  (document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve()).then(start);
  if (window.ResizeObserver) new ResizeObserver(() => Monitor.layout()).observe($(".channels"));
})();
})();
