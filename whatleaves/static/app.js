"use strict";
/* What Leaves Home: the whole front end. No framework, no build step, nothing loaded from outside. */

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const plural = (n, w, p) => `${n} ${n === 1 ? w : (p || w + "s")}`;

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1000)), u.length - 1);
  return (n / 1000 ** i).toFixed(i && n / 1000 ** i < 100 ? 1 : 0) + " " + u[i];
}
function ago(iso) {
  if (!iso) return "never";
  const m = (Date.now() - new Date(iso)) / 60000;
  if (m < 1) return "just now";
  if (m < 60) return `${Math.round(m)} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
function when(iso) {
  return iso ? new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "–";
}

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && !path.startsWith("/api/session") && !path.startsWith("/api/login")) { boot(); throw new Error("signed out"); }
  if (!r.ok) throw Object.assign(new Error(data.error || r.status), { data });
  return data;
}

/* ---------- icons */
const I = (d, extra = "") => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" ${extra}>${d}</svg>`;
const ICON = {
  tv: I('<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M8 21h8M12 17v4"/>'),
  camera: I('<path d="M3 8a2 2 0 0 1 2-2h2l1.5-2h7L17 6h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><circle cx="12" cy="12.5" r="3.5"/>'),
  speaker: I('<rect x="6" y="3" width="12" height="18" rx="3"/><circle cx="12" cy="14" r="3"/><circle cx="12" cy="7.5" r="1"/>'),
  fan: I('<circle cx="12" cy="12" r="1.6"/><path d="M12 10.4c0-4 1-7 3.5-7S18 7 13.5 11M13.6 12c4 0 7 1 7 3.5S17 18 13 13.5M12 13.6c0 4-1 7-3.5 7S6 17 10.5 13M10.4 12c-4 0-7-1-7-3.5S7 6 11 10.5"/>'),
  climate: I('<path d="M12 2v20M4.9 6.5l14.2 11M4.9 17.5l14.2-11"/><path d="M9.5 3.5 12 6l2.5-2.5M9.5 20.5 12 18l2.5 2.5"/>'),
  air: I('<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>'),
  plug: I('<path d="M9 2v5M15 2v5M6 7h12v4a6 6 0 0 1-12 0zM12 17v5"/>'),
  light: I('<path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V16h8v-1.3A7 7 0 0 0 12 2z"/>'),
  vacuum: I('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/><path d="M7 7.5h3"/>'),
  printer: I('<path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="7"/>'),
  phone: I('<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/>'),
  laptop: I('<rect x="4" y="4" width="16" height="11" rx="2"/><path d="M2 19h20"/>'),
  watch: I('<rect x="6" y="6" width="12" height="12" rx="3"/><path d="M9 6V2h6v4M9 18v4h6v-4"/>'),
  door: I('<path d="M3 21h18M5 21V4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v17M5 9h14M5 15h14"/>'),
  device: I('<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>'),
  alert: I('<path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'),
  check: I('<path d="M20 6 9 17l-5-5"/>'),
  search: I('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'),
  pencil: I('<path d="M12 20h9M16.5 3.5a2.1 2.1 0 1 1 3 3L7 19l-4 1 1-4z"/>'),
  back: I('<path d="M15 18l-6-6 6-6"/>'),
  globe: I('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
  home: I('<path d="M3 11 12 3l9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>'),
  shield: I('<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>'),
};
const PALETTE = ["#14b8a6", "#6366f1", "#f59e0b", "#ec4899", "#0ea5e9", "#84cc16", "#a855f7", "#f97316", "#64748b"];

/* ---------- small pieces */
const grade = (d, cls = "") => `<span class="grade ${d.verdict} ${cls}" title="${esc(d.label)} (score ${d.score})">${esc(d.grade)}</span>`;
const kind = (k) => `<span class="kind">${ICON[k] || ICON.device}</span>`;
const companyChip = (c) => `<span class="chip ${c.tracking ? "bad" : ""}">${(c.flags || []).join("")} ${esc(c.company)}</span>`;

function spark(points) {
  const vals = points.map((p) => p.bytes_out || p.lookups * 300);
  const max = Math.max(...vals, 1), w = 200, h = 34, step = w / Math.max(vals.length - 1, 1);
  const xy = vals.map((v, i) => [i * step, h - 3 - (v / max) * (h - 6)]);
  const line = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><path class="a" d="${line}L${w},${h}L0,${h}Z"/><path class="l" d="${line}"/></svg>`;
}

function barChart(points) {
  const w = 720, h = 150, pad = 22, bw = (w - pad) / points.length;
  const vals = points.map((p) => p.bytes_out), useBytes = vals.some((v) => v > 0);
  const series = useBytes ? vals : points.map((p) => p.lookups);
  const max = Math.max(...series, 1);
  const bars = series.map((v, i) => {
    const bh = (v / max) * (h - pad - 8);
    const hr = new Date(points[i].hour);
    const label = hr.toLocaleTimeString(undefined, { hour: "numeric" });
    return `<rect class="b" x="${(pad + i * bw + 2).toFixed(1)}" y="${(h - pad - bh).toFixed(1)}" width="${(bw - 4).toFixed(1)}" height="${Math.max(bh, 1).toFixed(1)}" rx="3"><title>${label}: ${useBytes ? bytes(v) + " sent" : plural(v, "lookup")}</title></rect>`;
  }).join("");
  const ticks = points.map((p, i) => i % 6 === 0 ? `<text x="${pad + i * bw + bw / 2}" y="${h - 6}" text-anchor="middle">${new Date(p.hour).toLocaleTimeString(undefined, { hour: "numeric" })}</text>` : "").join("");
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Activity over the last 24 hours">
    <line class="g" x1="${pad}" x2="${w}" y1="${h - pad}" y2="${h - pad}"/>${bars}${ticks}</svg>
    <div class="muted" style="font-size:12px;margin-top:6px">${useBytes ? "Data sent per hour" : "Lookups per hour"}, last 24 hours</div>`;
}

/* ---------- state and routing */
let overviewCache = null, statusCache = null, deviceFilter = "all", search = "";

async function loadOverview() { overviewCache = await api("/api/overview"); return overviewCache; }

function setTab(name) {
  document.querySelectorAll(".tabs a").forEach((a) =>
    a.dataset.tab === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
}

async function route() {
  const [, view, arg] = (location.hash || "#/").slice(1).split("/");
  const main = $("#main");
  try {
    if (!view) { setTab("overview"); main.innerHTML = renderOverview(await loadOverview()); }
    else if (view === "devices") { setTab("devices"); if (arg) deviceFilter = arg; main.innerHTML = renderDevices(overviewCache || await loadOverview()); wireDevices(); }
    else if (view === "device") { setTab("devices"); main.innerHTML = renderDevice(await api("/api/device?client=" + encodeURIComponent(decodeURIComponent(arg)))); wireDevice(); }
    else if (view === "companies") { setTab("companies"); main.innerHTML = renderCompanies(overviewCache || await loadOverview()); }
    else if (view === "app") { setTab("app"); main.innerHTML = renderApp(await api("/api/app")); }
    else if (view === "settings") { setTab(""); main.innerHTML = renderSettings(); wireSettings(); }
    else location.hash = "#/";
  } catch (e) {
    if (e.message !== "signed out") main.innerHTML = `<div class="card empty">Couldn't load this page: ${esc(e.message)}</div>`;
  }
  main.firstElementChild?.classList.add("view");
}

async function refreshStatus() {
  try {
    const s = await api("/api/status");
    statusCache = s;
    const src = { adguard: "AdGuard Home", files: "collector files", demo: "demo data" }[s.source] || s.source;
    $("#status").innerHTML = `<span class="dot ${s.last_error ? "err" : ""}"></span><span>${s.last_error ? "Reading failed" : `${src} · ${ago(s.last_poll)}`}</span>`;
    $("#status").title = s.last_error || `Reads every ${Math.round(s.poll_seconds / 60)} min, keeps ${s.keep_days} days`;
  } catch (e) { /* the gate takes over if signed out */ }
}

/* ---------- overview */
function renderOverview(o) {
  const c = o.counts;
  const demo = statusCache?.source === "demo" ? `<div class="demo">You're looking at made-up demo devices. Connect your AdGuard Home (see the README) to see your own network.</div>` : "";
  const f = o.finding;
  const finding = f ? `<a class="finding ${f.verdict}" href="#/device/${encodeURIComponent(f.client)}">
      <span class="ico">${ICON.alert}</span>
      <span><div class="k">Biggest finding</div><div class="t">${esc(f.device)}: ${esc(f.text)}</div><span class="go">See what ${esc(f.device)} talks to →</span></span></a>`
    : c.total ? `<div class="finding good"><span class="ico">${ICON.check}</span><span><div class="k">Biggest finding</div><div class="t">Nothing stands out. Every device looks fine so far.</div></span></div>` : "";
  const total = o.companies.reduce((a, x) => a + x.bytes_out, 0);
  const top = o.companies.filter((x) => x.bytes_out > 0).slice(0, 8);
  const flow = total ? `<div class="card flow"><div class="bar">${top.map((x, i) => `<span style="width:${(100 * x.bytes_out / total).toFixed(2)}%;background:${x.tracking ? "var(--concern-ring)" : PALETTE[i % PALETTE.length]}" title="${esc(x.company)}: ${bytes(x.bytes_out)}"></span>`).join("")}</div>
      <div class="legend">${top.map((x, i) => `<div class="li"><span class="sw" style="background:${x.tracking ? "var(--concern-ring)" : PALETTE[i % PALETTE.length]}"></span><span class="nm">${x.flags.join("")} ${esc(x.company)}</span><span class="vl">${bytes(x.bytes_out)}</span></div>`).join("")}</div></div>` : "";
  const stat = (key, n, label) => `<a class="stat ${key}" href="#/devices/${key}"><div class="n">${n}</div><div class="l">${label}</div></a>`;
  return `<section>
    <h1>${esc(o.headline)}</h1>
    <p class="lede">What each device in your home talks to on the internet, in plain words.</p>
    ${demo}
    <div class="stats">${stat("all", c.total, "Devices watched")}${stat("good", c.good, "Look fine")}${stat("check", c.check, "Worth a look")}${stat("concern", c.concern, "Concern")}</div>
    ${finding}
    <h2>Your devices <small>sorted by what needs attention</small></h2>
    ${o.devices.length ? `<div class="grid">${[...o.devices].sort((a, b) => a.score - b.score).map(tile).join("")}</div>` : `<div class="card empty">No devices yet. They appear after the first read.</div>`}
    ${flow ? `<h2>Where your data goes <small>data sent, by company</small></h2>${flow}` : ""}
  </section>`;
}

function tile(d) {
  return `<a class="tile" href="#/device/${encodeURIComponent(d.client)}">
    <div class="row">${kind(d.kind)}<div><div class="name">${esc(d.name || d.client)}</div><div class="sub">${esc(d.label)}${d.name ? " · " + esc(d.client) : ""}</div></div>${grade(d)}</div>
    <div class="sum">${esc(d.summary)}</div>
    <div class="chips">${d.companies_brief.map(companyChip).join("")}</div>
    ${spark(d.activity)}
    <div class="foot"><span>${plural(d.company_count, "company", "companies")}</span><span>Last seen ${ago(d.last)}</span></div>
  </a>`;
}

/* ---------- devices */
function renderDevices(o) {
  const btn = (k, l) => `<button data-f="${k}" aria-pressed="${deviceFilter === k}">${l}</button>`;
  return `<section>
    <h1>Devices</h1><p class="lede">${plural(o.counts.total, "device")} seen. Pick one to see who it talks to and why it got its grade.</p>
    <div class="toolbar">
      <label class="search">${ICON.search}<input id="q" placeholder="Search devices, addresses, companies" value="${esc(search)}" aria-label="Search"></label>
      <div class="seg" role="group" aria-label="Filter">${btn("all", "All")}${btn("concern", "Concern")}${btn("check", "Worth a look")}${btn("good", "Look fine")}</div>
    </div>
    <div class="card list" id="dlist"></div></section>`;
}
function fillDevices() {
  const q = search.toLowerCase();
  const rows = overviewCache.devices
    .filter((d) => deviceFilter === "all" || d.verdict === deviceFilter)
    .filter((d) => !q || [d.name, d.client, d.summary, ...d.companies_brief.map((c) => c.company)].join(" ").toLowerCase().includes(q))
    .sort((a, b) => a.score - b.score);
  $("#dlist").innerHTML = `<div class="lrow lhead"><span></span><span>Device</span><span class="hide-sm">Talks to</span><span class="num hide-sm">Sent per day</span><span class="hide-sm">Last seen</span><span>Grade</span></div>` +
    (rows.length ? rows.map((d) => `<a class="lrow" href="#/device/${encodeURIComponent(d.client)}">
      ${kind(d.kind)}<span><div style="font-weight:600">${esc(d.name || d.client)}</div><div class="muted" style="font-size:12.5px">${esc(d.client)} · ${esc(d.label)}</div></span>
      <span class="hide-sm chips">${d.companies_brief.map(companyChip).join("")}</span>
      <span class="num hide-sm">${bytes(d.per_day_out)}</span><span class="hide-sm muted">${ago(d.last)}</span>${grade(d)}</a>`).join("")
      : `<div class="empty">No devices match.</div>`);
}
function wireDevices() {
  fillDevices();
  $("#q").addEventListener("input", (e) => { search = e.target.value; fillDevices(); });
  document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => {
    deviceFilter = b.dataset.f;
    document.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    fillDevices();
  }));
}

/* ---------- one device */
function ring(d) {
  const r = 30, c = 2 * Math.PI * r, frac = d.score / 100;
  const col = { good: "var(--good-ring)", check: "var(--check-ring)", concern: "var(--concern-ring)" }[d.verdict];
  return `<div class="ring"><svg viewBox="0 0 74 74" aria-hidden="true"><circle cx="37" cy="37" r="${r}" fill="none" stroke="var(--line)" stroke-width="7"/>
    <circle cx="37" cy="37" r="${r}" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${(c * frac).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 37 37)"/>
    <text x="37" y="45" text-anchor="middle" class="gl" fill="${col}">${esc(d.grade)}</text></svg>
    <div><div class="badge ${d.verdict}">${esc(d.label)}</div><div class="muted" style="font-size:12.5px;margin-top:6px">Score ${d.score} of 100</div></div></div>`;
}
function renderDevice(d) {
  const sym = { good: "✓", warn: "!", bad: "✕" };
  const reasons = d.reasons.map((r) => `<li class="${r.level}"><span class="ri">${sym[r.level]}</span><span>${esc(r.text)}</span></li>`).join("");
  const comps = d.companies.map((c) => `<div class="card comp">
      <div class="top"><span class="cn">${esc(c.company)}</span>
        ${c.tracking ? '<span class="chip bad">ads or tracking</span>' : ""}${c.time ? '<span class="chip">time service</span>' : ""}
        ${c.company === d.maker ? '<span class="chip ok">maker</span>' : ""}
        <span class="bytes">${c.bytes_out ? `↑ ${bytes(c.bytes_out)} · ↓ ${bytes(c.bytes_in)}` : plural(c.lookups, "lookup")}</span></div>
      <div class="meta">${c.countries.map((x) => x.flag + " " + x.code).join(", ") || (c.connections ? "Location unknown" : c.tracking ? "Looked up, never connected (blocked)" : "Looked up only, no connection seen")}${c.hosting.length ? ` · on ${esc(c.hosting.join(", "))}` : ""}${c.connections ? ` · ${plural(c.connections, "connection")}` : ""}</div>
      <div class="chips">${c.domains.slice(0, 6).map((x) => `<span class="chip mono">${esc(x.name)} · ${x.count}</span>`).join("")}${c.domains.length > 6 ? `<span class="chip">+${c.domains.length - 6} more</span>` : ""}</div>
      ${c.addresses.length ? `<details><summary>Addresses (${c.addresses.length})</summary><div class="chips" style="margin-top:8px">${c.addresses.map((a) => `<span class="chip mono">${esc(a)}</span>`).join("")}</div></details>` : ""}
    </div>`).join("");
  const lk = d.lookups_detail.map((l) => `<tr><td class="mono">${esc(l.name)}${l.blocked ? ' <span class="chip bad">blocked</span>' : ""}</td><td class="num">${l.count}</td><td class="mono">${esc(l.addresses.join(", "))}</td><td>${when(l.last)}</td></tr>`).join("");
  const cn = d.connections.map((c) => `<tr><td class="mono">${esc(c.dst)}${c.local ? ' <span class="chip">local</span>' : ""}</td><td>${c.dport}/${esc(c.proto)}</td><td class="mono">${c.names.length ? esc(c.names.join(", ")) : (c.local ? "" : '<span class="chip warn">no lookup</span>')}</td><td class="num">${bytes(c.bytes_out)}</td><td class="num">${bytes(c.bytes_in)}</td><td>${when(c.last)}</td></tr>`).join("");
  return `<section>
    <a class="back" href="#/devices">${ICON.back} All devices</a>
    <div class="dhead">${kind(d.kind)}
      <div><div class="dtitle"><h1 id="dname">${esc(d.name || d.client)}</h1><button class="edit" id="rename" aria-label="Rename" title="Rename">${ICON.pencil}</button></div>
      <div class="muted">${esc(d.client)} · ${esc(d.summary)}</div></div>${ring(d)}</div>
    <div class="cols">
      <div class="card pad"><h2 style="margin-top:0">Why it got ${esc(d.grade)}</h2><ul class="reasons">${reasons || "<li>Not enough data yet.</li>"}</ul></div>
      <div class="card pad"><div class="kpis">
        <div class="kpi"><b>${bytes(d.per_day_out)}</b><span>sent per day (estimate)</span></div>
        <div class="kpi"><b>${plural(d.company_count, "company", "companies")}</b><span>it talks to</span></div>
        <div class="kpi"><b>${d.lookups}</b><span>lookups kept</span></div>
        <div class="kpi"><b>${ago(d.last)}</b><span>last seen</span></div></div>
        <div style="margin-top:18px">${barChart(d.activity)}</div></div>
    </div>
    <h2>Who it talks to <small>by company, biggest first</small></h2>
    <div class="grid">${comps || '<div class="card empty">Nothing seen yet.</div>'}</div>
    <details class="card tech"><summary>Technical details: every lookup and connection</summary>
      <div class="pad"><h3>Lookups</h3><div class="scroll"><table><thead><tr><th>Name</th><th class="num">Times</th><th>Answers</th><th>Last</th></tr></thead><tbody>${lk || '<tr><td colspan="4" class="muted">None</td></tr>'}</tbody></table></div>
      <h3 style="margin-top:22px">Connections</h3><div class="scroll"><table><thead><tr><th>Address</th><th>Port</th><th>Looked up as</th><th class="num">Sent</th><th class="num">Received</th><th>Last</th></tr></thead><tbody>${cn || '<tr><td colspan="6" class="muted">None recorded. Connections need a source that records them, such as the collector.</td></tr>'}</tbody></table></div></div>
    </details></section>`;
}
function wireDevice() {
  const btn = $("#rename");
  btn?.addEventListener("click", () => {
    const h = $("#dname"), client = decodeURIComponent(location.hash.split("/")[2]);
    const input = Object.assign(document.createElement("input"), { className: "namefield", value: h.textContent, ariaLabel: "Device name" });
    h.replaceWith(input); btn.classList.add("hidden"); input.focus(); input.select();
    const save = async () => { await api("/api/name", { client, name: input.value }); overviewCache = null; route(); };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); if (e.key === "Escape") route(); });
    input.addEventListener("blur", save);
  });
}

/* ---------- companies */
function renderCompanies(o) {
  const rows = o.companies.map((c, i) => `<div class="card comp">
      <div class="top"><span class="cn">${c.flags.join("")} ${esc(c.company)}</span>${c.tracking ? '<span class="chip bad">ads or tracking</span>' : ""}
      <span class="bytes">${c.bytes_out ? "↑ " + bytes(c.bytes_out) : plural(c.lookups, "lookup")}</span></div>
      <div class="meta">Used by ${plural(c.devices.length, "device")}</div>
      <div class="chips">${c.devices.map((n) => `<span class="chip">${esc(n)}</span>`).join("")}</div></div>`).join("");
  return `<section><h1>Companies</h1><p class="lede">Everyone your devices talk to, across the whole home. Red means ads or tracking.</p>
    <div class="grid" style="margin-top:22px">${rows || '<div class="card empty">Nothing yet.</div>'}</div></section>`;
}

/* ---------- this app */
function renderApp(a) {
  const s = a.status, internet = a.summary.filter((r) => !r.local), local = a.summary.filter((r) => r.local);
  const row = (r) => `<tr><td class="mono">${esc(r.host)}</td><td>${esc(r.purpose)}</td><td>${r.local ? '<span class="chip ok">home network</span>' : '<span class="chip warn">internet</span>'}</td><td class="num">${r.calls}</td><td class="num">${bytes(r.bytes)}</td><td>${ago(r.last)}</td><td class="num">${r.failures || ""}</td></tr>`;
  const calls = a.calls.slice(0, 60).map((c) => `<tr><td>${when(c.time)}</td><td class="mono">${esc(c.host)}</td><td>${esc(c.purpose)}</td><td class="num">${bytes(c.bytes)}</td><td>${esc(c.status)}</td></tr>`).join("");
  const own = a.owners.enabled ? (a.owners.ready ? "Loaded and kept on this machine" : a.owners.error ? "Couldn't download: " + esc(a.owners.error) : "Loading…") : "Off (offline mode)";
  return `<section><h1>What this app itself contacts</h1>
    <p class="lede">A tool that watches what leaves your home should show its own traffic too. Every network request this app makes is recorded here.</p>
    <div class="trust">
      <div class="card"><b><span class="ok-ico">${ICON.check}</span>No telemetry</b><p>It never reports usage, errors or anything else to anyone.</p></div>
      <div class="card"><b><span class="ok-ico">${ICON.check}</span>No update checks</b><p>It doesn't phone home to look for new versions.</p></div>
      <div class="card"><b><span class="ok-ico">${ICON.check}</span>Nothing loaded from outside</b><p>No outside fonts, scripts or images; the browser is told to refuse them.</p></div>
      <div class="card"><b>${ICON.globe} ${plural(internet.length, "internet destination")}</b><p>${s.offline ? "Offline mode: it never contacts the internet." : `Only the address-ownership list, once a month. Turn it off with WL_OFFLINE=1.`}</p></div>
    </div>
    <h2>Every place it has contacted <small>kept ${s.keep_days} days</small></h2>
    <div class="card pad scroll"><table><thead><tr><th>Where</th><th>Why</th><th>Network</th><th class="num">Times</th><th class="num">Data</th><th>Last</th><th class="num">Failed</th></tr></thead>
      <tbody>${[...internet, ...local].map(row).join("") || '<tr><td colspan="7" class="muted">Nothing yet.</td></tr>'}</tbody></table></div>
    <h2>Most recent requests</h2>
    <div class="card pad scroll"><table><thead><tr><th>When</th><th>Where</th><th>Why</th><th class="num">Data</th><th>Result</th></tr></thead>
      <tbody>${calls || '<tr><td colspan="5" class="muted">None yet. In demo mode nothing is read from your network.</td></tr>'}</tbody></table></div>
    <h2>About</h2><div class="card pad"><table><tbody>
      <tr><td>Version</td><td>${esc(s.version)}</td></tr><tr><td>Source</td><td>${esc(s.source)}</td></tr>
      <tr><td>Reads every</td><td>${Math.round(s.poll_seconds / 60)} min</td></tr><tr><td>Keeps</td><td>${s.keep_days} days</td></tr>
      <tr><td>Address-ownership list</td><td>${own}</td></tr><tr><td>Login</td><td>${s.auth ? "On" : "Off (WL_AUTH=off)"}</td></tr></tbody></table></div></section>`;
}

/* ---------- settings */
function renderSettings() {
  const auth = statusCache?.auth;
  return `<section><h1>Settings</h1>
    ${auth ? `<h2>Change password</h2><form class="card pad form" id="pw">
      <label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
      <label>New password<input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
      <button class="btn">Change password</button><div class="msg" id="pwmsg"></div></form>
      <h2>Sign out</h2><div class="card pad"><button class="btn ghost" id="logout">Sign out</button></div>`
      : `<div class="card pad">Login is off (WL_AUTH=off): something in front of this app handles sign-in.</div>`}
    <h2>Names</h2><div class="card pad">Rename a device from its page (the pencil next to its name), or set names in advance with WL_NAMES.</div></section>`;
}
function wireSettings() {
  $("#pw")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target), m = $("#pwmsg");
    try { await api("/api/password", { current: f.get("current"), password: f.get("password") }); m.className = "msg ok"; m.textContent = "Password changed."; e.target.reset(); }
    catch (err) { m.className = "msg err"; m.textContent = err.message; }
  });
  $("#logout")?.addEventListener("click", async () => { await api("/api/logout", {}); boot(); });
}

/* ---------- sign-in gate */
function gate(mode) {
  const setup = mode === "setup";
  $("#shell").classList.add("hidden");
  const g = $("#gate");
  g.className = "gate";
  g.innerHTML = `<form class="card form" id="gform">
      <div class="brand"><img src="/logo.svg" alt="" width="30" height="30"><span>What Leaves Home</span></div>
      <h1>${setup ? "Create your login" : "Sign in"}</h1>
      <p class="muted" style="margin:0 0 6px">${setup ? "This is the first visit, so choose the username and password for this page. You can change the password later in Settings." : "Use the login you created for this page."}</p>
      <label>Username<input name="user" value="${setup ? "admin" : ""}" autocomplete="username" required></label>
      <label>Password<input type="password" name="password" autocomplete="${setup ? "new-password" : "current-password"}" ${setup ? 'minlength="8"' : ""} required></label>
      <button class="btn">${setup ? "Create login" : "Sign in"}</button><div class="msg err" id="gmsg"></div></form>`;
  $("#gform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try { await api(setup ? "/api/setup" : "/api/login", { user: f.get("user"), password: f.get("password") }); boot(); }
    catch (err) { $("#gmsg").textContent = err.message; }
  });
  $("input[name=" + (setup ? "password" : "user") + "]", g).focus();
}

async function boot() {
  const s = await api("/api/session");
  if (s.auth === "setup" || s.auth === "login") return gate(s.auth);
  $("#gate").className = "hidden";
  $("#shell").classList.remove("hidden");
  await refreshStatus();
  route();
}

window.addEventListener("hashchange", () => { window.scrollTo(0, 0); route(); });
setInterval(async () => { await refreshStatus(); if (!location.hash.includes("settings") && !document.querySelector(".namefield")) { overviewCache = null; route(); } }, 120000);
boot();
