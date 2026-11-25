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

/* ---------- live demo (static files, no server): see tools/build_demo.py */
const DEMO_FILE = (path) => {
  const [p, q] = path.split("?");
  if (p === "/api/device") return "api/device/" + encodeURIComponent(new URLSearchParams(q).get("client")).replace(/%/g, "~") + ".json";
  if (p === "/api/session") return null;
  return "api/" + p.replace("/api/", "") + ".json";
};
// Keep the demo's times fresh: move every timestamp forward by however old the build is.
function shiftTimes(obj, ms) {
  if (Array.isArray(obj)) return obj.map((x) => shiftTimes(x, ms));
  if (obj && typeof obj === "object") { for (const k in obj) obj[k] = shiftTimes(obj[k], ms); return obj; }
  if (typeof obj === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(obj)) {
    const t = Date.parse(obj);
    return isNaN(t) ? obj : new Date(t + ms).toISOString();
  }
  return obj;
}
async function demoApi(path, body) {
  if (body !== undefined) throw Object.assign(new Error("This is the live demo: nothing can be changed here. Install it to try that."), { data: { ok: false, message: "This is the live demo: nothing can be changed here. Install it to try that." } });
  const file = DEMO_FILE(path);
  if (!file) return { auth: "off" };
  if (path.startsWith("/api/new-clients")) return [];
  const r = await fetch(file);
  if (!r.ok) throw new Error("Not part of the demo");
  return shiftTimes(await r.json(), Date.now() - Date.parse(window.WL_DEMO.generated));
}

async function api(path, body) {
  if (window.WL_DEMO) return demoApi(path, body);
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
  media: I('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m10 9 5 3-5 3z"/>'),
  home: I('<path d="M3 11 12 3l9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>'),
  download: I('<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>'),
  dns: I('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
  proxy: I('<path d="M4 7h11M4 17h11M15 4l3 3-3 3M15 14l3 3-3 3"/>'),
  ai: I('<path d="M12 3v3M12 18v3M3 12h3M18 12h3"/><rect x="7" y="7" width="10" height="10" rx="3"/><circle cx="12" cy="12" r="1.5"/>'),
  db: I('<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'),
  monitor: I('<path d="M3 12h4l3-8 4 16 3-8h4"/>'),
  service: I('<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>'),
  copy: I('<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>'),
  router: I('<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9a6 6 0 0 1 8 0M5.5 6.5a10 10 0 0 1 13 0"/>'),
};
// Data colours for the "where your data goes" bar; red stays reserved for tracking.
const PALETTE = ["#4c6ef5", "#15aabf", "#f59f00", "#ae3ec9", "#82c91e", "#fd7e14", "#0ca678", "#e64980", "#868e96"];

/* ---------- theme: Auto (follows the system), Light or Dark, remembered in this browser */
const THEMES = ["auto", "light", "dark"];
function getTheme() { try { return localStorage.getItem("wl-theme") || "auto"; } catch (e) { return "auto"; } }
function applyTheme(t) {
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  const b = document.getElementById("theme");
  if (b) { b.innerHTML = { auto: ICON_AUTO, light: ICON_SUN, dark: ICON_MOON }[t]; b.title = `Theme: ${t} (click to change)`; b.setAttribute("aria-label", b.title); }
}
const ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const ICON_MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
const ICON_AUTO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"/></svg>';
applyTheme(getTheme());

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
let overviewCache = null, statusCache = null, deviceFilter = "all", search = "", showQuiet = false;

async function loadOverview() { overviewCache = await api("/api/overview"); return overviewCache; }

function setTab(name) {
  document.querySelectorAll(".tabs a").forEach((a) =>
    a.dataset.tab === name ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
}

async function route() {
  const [, view, arg] = (location.hash || "#/").slice(1).split("/");
  const main = $("#main");
  try {
    if (!view) { setTab("overview"); main.innerHTML = renderOverview(await loadOverview()); wireCopy(); }
    else if (view === "devices") { setTab("devices"); if (arg) deviceFilter = arg; main.innerHTML = renderDevices(overviewCache || await loadOverview()); wireDevices(); }
    else if (view === "services") { setTab("devices"); const [o, a] = await Promise.all([overviewCache || loadOverview(), api("/api/agent")]); overviewCache = o; main.innerHTML = renderServices(o, a); wireCopy(); wireQuiet(); }
    else if (view === "device") { setTab("devices"); main.innerHTML = renderDevice(await api("/api/device?client=" + encodeURIComponent(decodeURIComponent(arg)))); wireDevice(); wireCopy(); }
    else if (view === "companies") { setTab("companies"); main.innerHTML = renderCompanies(overviewCache || await loadOverview()); }
    else if (view === "app") { setTab("app"); main.innerHTML = renderApp(await api("/api/app")); }
    else if (view === "settings") { setTab(""); main.innerHTML = renderSettings(); wireSettings(); }
    else if (view === "connect") { setTab(""); main.innerHTML = renderConnect(); wireConnect(); }
    else if (view === "start") { setTab(""); main.innerHTML = renderStart(); wireStart(); }
    else if (view === "first-device") { setTab(""); main.innerHTML = renderFirstDevice(); wireFirstDevice(); }
    else if (view === "visible") { setTab(""); main.innerHTML = renderVisible(overviewCache || await loadOverview()); }
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
  const demo = window.WL_DEMO
    ? `<a class="card pad connectcta" href="${esc(window.WL_DEMO.repo || "#/")}"><span class="ico">${ICON.home}</span><span><b>This is the live demo, with made-up devices.</b> Install it on any always-on machine and point one device at it: you'll see your own in five minutes.</span><span class="go">Get it →</span></a>`
    : statusCache?.source === "demo"
    ? `<a class="card pad connectcta" href="#/connect"><span class="ico">${ICON.dns}</span><span><b>These are made-up demo devices.</b> Connect your AdGuard Home to see your own network: it takes a minute.</span><span class="go">Connect →</span></a>` : "";
  const f = o.finding;
  const finding = f ? `<a class="finding ${f.verdict}" href="#/device/${encodeURIComponent(f.client)}">
      <span class="ico">${ICON.alert}</span>
      <span><div class="k">Biggest finding</div><div class="t">${esc(f.device)}: ${esc(f.text)}</div><span class="go">See what ${esc(f.device)} talks to, and what you can do →</span></span></a>`
    : c.total ? `<div class="finding good"><span class="ico">${ICON.check}</span><span><div class="k">Biggest finding</div><div class="t">Nothing stands out. Everything with traffic looks fine so far.</div></span></div>` : "";
  const all = [...o.devices, ...o.services];
  const attention = all.filter((d) => d.verdict === "concern" || d.verdict === "check").sort((a, b) => a.score - b.score);
  const fine = all.filter((d) => d.verdict === "good").sort((a, b) => (a.name || a.client).localeCompare(b.name || b.client));
  const quiet = all.filter((d) => d.verdict === "quiet").length;
  const anyTile = (d) => (d.service ? serviceTile(d) : tile(d));
  const fineChip = (d) => `<a class="chip fine" href="#/device/${encodeURIComponent(d.client)}"><span class="g">${esc(d.grade)}</span>${esc(d.name || d.client)}${d.service ? `<span class="muted"> · ${esc(d.service.host)}</span>` : ""}</a>`;
  const total = o.companies.reduce((a, x) => a + x.bytes_out, 0);
  const top = o.companies.filter((x) => x.bytes_out > 0).slice(0, 8);
  const flow = total ? `<div class="card flow"><div class="bar">${top.map((x, i) => `<span style="width:${(100 * x.bytes_out / total).toFixed(2)}%;background:${x.tracking ? "var(--concern-ring)" : PALETTE[i % PALETTE.length]}" title="${esc(x.company)}: ${bytes(x.bytes_out)}"></span>`).join("")}</div>
      <div class="legend">${top.map((x, i) => `<div class="li"><span class="sw" style="background:${x.tracking ? "var(--concern-ring)" : PALETTE[i % PALETTE.length]}"></span><span class="nm">${x.flags.join("")} ${esc(x.company)}</span><span class="vl">${bytes(x.bytes_out)}</span></div>`).join("")}</div></div>` : "";
  const stat = (key, n, label) => `<a class="stat ${key}" href="#/devices/${key}"><div class="n">${n}</div><div class="l">${label}</div></a>`;
  const rules = o.block_rules || [];
  const blockCard = rules.length ? `<h2>What your home could block <small>ad and tracking services, across everything</small></h2>
    <div class="card pad">
      <p style="margin-top:0">${plural(rules.length, "ad or tracking service")} reached by your devices and services. ${isPihole() ? "Add these to Pi-hole's denylist" : "Paste these into AdGuard Home under <b>Filters → Custom filtering rules</b>"}. Blocking can switch off some free extras; remove a line if something stops working.</p>
      ${rulesBlock(rules.map((r) => r.rule))}
      <div class="chips">${rules.slice(0, 12).map((r) => `<span class="chip bad mono">${esc(r.rule)}</span><span class="muted" style="font-size:12px;align-self:center">${esc(r.used_by.join(", "))}</span>`).join("")}</div>
      ${adguardLink()}
    </div>` : "";
  return `<section>
    <h1>${esc(o.headline)}</h1>
    <p class="lede">What the devices and services in your home talk to on the internet, in plain words.</p>
    ${demo}
    ${o.router ? `<a class="finding check" href="#/visible" style="margin-top:16px"><span class="ico">${ICON.router}</span><span>
      <div class="k">Your devices are hidden behind your router</div>
      <div class="t">${Math.round(o.router.share * 100)}% of lookups come from one address (${esc(o.router.client)}): your router asks on every device's behalf, so they can't be told apart.</div>
      <span class="go">See each device separately: your options, step by step →</span></span></a>` : ""}
    <div class="stats">${stat("all", c.total - c.quiet, "With traffic")}${stat("good", c.good, "Look fine")}${stat("check", c.check, "Worth a look")}${stat("concern", c.concern, "Concern")}</div>
    ${finding}
    ${attention.length ? `<h2>Needs a look <small>worst first</small></h2><div class="grid">${attention.map(anyTile).join("")}</div>` : ""}
    ${blockCard}
    ${fine.length ? `<h2>Looking fine <small>${plural(fine.length, "device or service", "devices and services")}</small></h2><div class="chips finelist">${fine.slice(0, 24).map(fineChip).join("")}${fine.length > 24 ? `<a class="chip" href="#/devices">+${fine.length - 24} more</a>` : ""}</div>` : ""}
    ${quiet ? `<p class="muted" style="margin-top:14px">${plural(quiet, "service")} had no traffic and ${quiet === 1 ? "isn't" : "aren't"} shown here. <a href="#/services">See all services →</a></p>` : ""}
    ${!o.services.length ? `<a class="card pad finding good" href="#/services" style="margin-top:22px"><span class="ico">${ICON.service}</span><span><div class="t">See what each app on your servers sends out</div><span class="go">Set up services: one command per server →</span></span></a>` : ""}
    ${flow ? `<h2>Where your data goes <small>data sent, by company</small></h2>${flow}` : ""}
  </section>`;
}
// AdGuard takes "||domain^" rules; Pi-hole takes plain domains added as wildcard denies.
const isPihole = () => statusCache?.source === "pihole";
function rulesBlock(rules) {
  return isPihole()
    ? cmdBlock("Domains for Pi-hole", rules.map((r) => r.replace(/^\|\|/, "").replace(/\^$/, "")).join("\n"),
               "In Pi-hole: Domains → add each as a <b>wildcard</b> deny (or paste the list into a local adlist).")
    : cmdBlock("AdGuard rules", rules.join("\n"));
}
function adguardLink() {
  const u = statusCache?.adguard_url || (statusCache?.adguard_ui_port ? `${location.protocol}//${location.hostname}:${statusCache.adguard_ui_port}` : "");
  if (!u) return "";
  return isPihole() ? `<p style="margin-bottom:0"><a href="${esc(u)}/admin/groups/domains" target="_blank" rel="noopener">Open Pi-hole's domains →</a></p>`
    : `<p style="margin-bottom:0"><a href="${esc(u)}/#custom_rules" target="_blank" rel="noopener">Open AdGuard's custom rules →</a></p>`;
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

/* ---------- devices and services */
function dsToggle(which, o) {
  return `<div class="seg big" role="tablist" aria-label="Devices or services">
    <a role="tab" href="#/devices" aria-selected="${which === "devices"}">Devices <span class="cnt">${o.counts.devices}</span></a>
    <a role="tab" href="#/services" aria-selected="${which === "services"}">Services <span class="cnt">${o.counts.services}</span></a></div>`;
}
function renderDevices(o) {
  const btn = (k, l) => `<button data-f="${k}" aria-pressed="${deviceFilter === k}">${l}</button>`;
  return `<section>
    ${dsToggle("devices", o)}
    <h1>Devices</h1><p class="lede">${plural(o.counts.devices, "device")} seen on your network. Pick one to see who it talks to and why it got its grade.</p>
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
function renderServices(o, a) {
  const byHost = {}, quietBy = {};
  o.services.forEach((s) => {
    const h = s.service.host;
    if (s.verdict === "quiet" && !showQuiet) quietBy[h] = (quietBy[h] || 0) + 1;
    else (byHost[h] = byHost[h] || []).push(s);
  });
  const nQuiet = Object.values(quietBy).reduce((a, b) => a + b, 0);
  const hostNames = [...new Set([...Object.keys(byHost), ...Object.keys(quietBy)])].sort();
  const hosts = hostNames.map((h) => `<h2>${ICON.service.replace("<svg", '<svg width="18" height="18"')} ${esc(h)} <small>${plural((byHost[h] || []).length, "with traffic", "with traffic")}${quietBy[h] ? `, ${quietBy[h]} quiet` : ""}</small></h2>
    ${byHost[h] ? `<div class="grid">${byHost[h].sort((x, y) => x.score - y.score).map(serviceTile).join("")}</div>` : `<p class="muted">Nothing from this server has talked to the internet yet.</p>`}`).join("");
  const quietToggle = (nQuiet || showQuiet) && o.services.some((s) => s.verdict === "quiet")
    ? `<button class="btn ghost" id="quiet">${showQuiet ? "Hide quiet services" : `Show ${plural(nQuiet, "quiet service")}`}</button>` : "";
  return `<section>${dsToggle("services", o)}
    <h1>Services</h1>
    <p class="lede">The apps running on your home servers, and what each one sends out. A small agent on each server tells them apart.</p>
    ${quietToggle ? `<div class="toolbar">${quietToggle}<span class="muted">Quiet means no internet traffic seen yet.</span></div>` : ""}
    ${hosts || ""}
    ${setupPanel(a, o.services.length === 0)}
    ${scanPanel(o.scan)}</section>`;
}
function serviceTile(d) {
  return `<a class="tile" href="#/device/${encodeURIComponent(d.client)}">
    <div class="row">${kind(d.kind)}<div><div class="name">${esc(d.name)}</div><div class="sub">${esc(d.label)}${d.service.ports.length ? " · " + esc(d.service.ports.join(", ")) : ""}</div></div>${grade(d)}</div>
    <div class="sum">${esc(d.summary)}</div>
    <div class="chips">${d.companies_brief.map(companyChip).join("")}</div>
    ${spark(d.activity)}
    <div class="foot"><span class="mono" style="font-size:11.5px">${esc(d.service.image || d.service.network || "")}</span><span>Last seen ${ago(d.last)}</span></div></a>`;
}
function commands(ip, token) {
  const url = location.origin;
  const docker = `docker run -d --name whatleaves-agent --restart unless-stopped --network host --pid host --cap-add SYS_PTRACE -v /var/run/docker.sock:/var/run/docker.sock:ro -e WL_URL=${url} -e WL_TOKEN=${token} python:3.12-alpine sh -c 'wget -qO /agent.py "$WL_URL/whatleaves-agent.py" && exec python /agent.py'`;
  const install = `curl -fsSL ${url}/install-agent.sh | sudo WL_URL=${url} WL_TOKEN=${token} sh`;
  return { docker, install };
}
function cmdBlock(label, text, note) {
  return `<div class="cmd"><div class="cmdh"><span>${label}</span><button class="copy" data-copy="${esc(text)}">${ICON.copy} Copy</button></div><pre class="mono">${esc(text)}</pre>${note ? `<div class="muted" style="font-size:12.5px">${note}</div>` : ""}</div>`;
}
function setupPanel(a, empty) {
  const c = commands("", a.token);
  const agents = a.agents.length ? `<p class="muted">Reporting now: ${a.agents.map((h) => `<b>${esc(h.host)}</b> (${plural(h.services, "service")}, ${ago(h.last_seen)})`).join(", ")}.</p>` : "";
  const sugg = a.suggestions.map((h) => `<div class="card pad sugg">
      <div class="top"><span class="kind">${ICON.service}</span><div><div class="cn">${esc(h.name || h.ip)}</div><div class="muted mono" style="font-size:12.5px">${esc(h.ip)}</div></div>
      <span class="chip ok" style="margin-left:auto">Suggested</span></div>
      <ul class="why">${h.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
      <p class="muted" style="margin:0 0 4px;font-size:13px">Open a terminal on ${esc(h.name || h.ip)} (for example <span class="mono">ssh you@${esc(h.ip)}</span>) and run one of these:</p>
      ${h.docker ? cmdBlock("With Docker (recommended here)", c.docker) + cmdBlock("Or as a system service", c.install) : cmdBlock("As a system service", c.install) + cmdBlock("Or with Docker", c.docker)}
    </div>`).join("");
  return `<h2>${empty ? "Set up services" : "Add another server"} <small>one command per server</small></h2>
    <div class="card pad setup">
      <p style="margin-top:0">Services on one server all share its address, so the DNS log alone can't tell them apart. Run the agent on each server and this page shows every app separately. It only reads which program opened each connection, and sends that here with your token.</p>
      ${agents}
      ${a.suggestions.length ? `<p><b>These machines look like servers:</b></p><div class="grid">${sugg}</div>` :
        `<p class="muted">No other machines look like servers yet${o_scan_hint()}. You can still add any machine:</p>${cmdBlock("With Docker", c.docker)}${cmdBlock("Or as a system service", c.install)}`}
      <p class="muted" style="font-size:12.5px;margin-bottom:0">The commands contain your token: treat them like a password. The agent's code is at <a href="whatleaves-agent.py">whatleaves-agent.py</a>; the installer is <a href="install-agent.sh">install-agent.sh</a>.</p>
    </div>`;
}
function o_scan_hint() { return statusCache?.scan_hosts ? "" : " (turning on the scan, WL_SCAN_TARGETS, helps find them)"; }
function scanPanel(rows) {
  if (!rows.length) return `<h2>Listening on your network</h2><div class="card pad muted">Off. Set <span class="mono">WL_SCAN_TARGETS</span> to your home range (for example 192.168.1.0/24) to check daily for services listening on common ports. It only accepts private ranges, and every scan is listed on the This app tab.</div>`;
  const tr = rows.map((r) => `<tr><td class="mono">${esc(r.ip)}</td><td class="num">${r.port}</td><td>${esc(r.guess)}</td><td>${esc(r.title)}</td><td>${ago(r.last_seen)}</td></tr>`).join("");
  return `<h2>Listening on your network <small>from the daily scan</small></h2><div class="card pad scroll"><table><thead><tr><th>Address</th><th class="num">Port</th><th>Probably</th><th>Page title</th><th>Last seen</th></tr></thead><tbody>${tr}</tbody></table></div>`;
}
function wireQuiet() {
  $("#quiet")?.addEventListener("click", () => { showQuiet = !showQuiet; route(); });
}
function wireCopy() {
  document.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); }
    catch (e) { const pre = b.closest(".cmd").querySelector("pre"); const r = document.createRange(); r.selectNodeContents(pre); getSelection().removeAllRanges(); getSelection().addRange(r); }
    b.innerHTML = `${ICON.check} Copied`; setTimeout(() => (b.innerHTML = `${ICON.copy} Copy`), 1800);
  }));
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
  const col = { good: "var(--good-ring)", check: "var(--check-ring)", concern: "var(--concern-ring)", quiet: "var(--line-2)" }[d.verdict];
  return `<div class="ring"><svg viewBox="0 0 74 74" aria-hidden="true"><circle cx="37" cy="37" r="${r}" fill="none" stroke="var(--line)" stroke-width="7"/>
    <circle cx="37" cy="37" r="${r}" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${(c * frac).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 37 37)"/>
    <text x="37" y="45" text-anchor="middle" class="gl" fill="${col}">${esc(d.grade)}</text></svg>
    <div><div class="badge ${d.verdict}">${esc(d.label)}</div><div class="muted" style="font-size:12.5px;margin-top:6px">${d.verdict === "quiet" ? "Nothing to grade yet" : `Score ${d.score} of 100`}</div></div></div>`;
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
    <a class="back" href="${d.service ? "#/services" : "#/devices"}">${ICON.back} ${d.service ? "All services" : "All devices"}</a>
    <div class="dhead">${kind(d.kind)}
      <div><div class="dtitle"><h1 id="dname">${esc(d.name || d.client)}</h1><button class="edit" id="rename" aria-label="Rename" title="Rename">${ICON.pencil}</button></div>
      <div class="muted">${d.service ? `Runs on <b>${esc(d.service.host)}</b>${d.service.image ? " · <span class='mono'>" + esc(d.service.image) + "</span>" : ""}${d.service.ports.length ? " · ports " + esc(d.service.ports.join(", ")) : ""}` : esc(d.client)} · ${esc(d.summary)}</div></div>${ring(d)}</div>
    ${d.router ? `<a class="finding check" href="#/visible" style="margin-top:18px"><span class="ico">${ICON.router}</span><span><div class="t">This is your router, asking on behalf of every device behind it.</div><span class="go">See each device separately →</span></span></a>` : ""}
    <div class="cols">
      <div class="card pad"><h2 style="margin-top:0">Why it got ${esc(d.grade)}</h2><ul class="reasons">${reasons || "<li>Not enough data yet.</li>"}</ul></div>
      <div class="card pad"><div class="kpis">
        <div class="kpi"><b>${bytes(d.per_day_out)}</b><span>sent per day (estimate)</span></div>
        <div class="kpi"><b>${plural(d.company_count, "company", "companies")}</b><span>it talks to</span></div>
        <div class="kpi"><b>${d.lookups}</b><span>${d.service ? "lookups by its server that match" : "lookups kept"}</span></div>
        <div class="kpi"><b>${ago(d.last)}</b><span>last seen</span></div></div>
        <div style="margin-top:18px">${barChart(d.activity)}</div></div>
    </div>
    ${d.actions && d.actions.length ? `<h2>What you can do</h2><div class="actions">${d.actions.map(actionCard).join("")}</div>` : ""}
    <h2>Who it talks to <small>by company, biggest first</small></h2>
    <div class="grid">${comps || '<div class="card empty">Nothing seen yet.</div>'}</div>
    <details class="card tech"><summary>Technical details: every lookup and connection</summary>
      <div class="pad"><h3>Lookups</h3><div class="scroll"><table><thead><tr><th>Name</th><th class="num">Times</th><th>Answers</th><th>Last</th></tr></thead><tbody>${lk || '<tr><td colspan="4" class="muted">None</td></tr>'}</tbody></table></div>
      <h3 style="margin-top:22px">Connections</h3><div class="scroll"><table><thead><tr><th>Address</th><th>Port</th><th>Looked up as</th><th class="num">Sent</th><th class="num">Received</th><th>Last</th></tr></thead><tbody>${cn || '<tr><td colspan="6" class="muted">None recorded. Connections need a source that records them, such as the collector.</td></tr>'}</tbody></table></div></div>
    </details></section>`;
}
function actionCard(a) {
  const ico = { bad: ICON.alert, warn: ICON.alert, good: ICON.check, info: ICON.globe }[a.level] || ICON.check;
  return `<div class="card pad action ${a.level}"><div class="at"><span class="ico">${ico}</span><b>${esc(a.title)}</b></div>
    <p>${esc(isPihole() ? a.text.replace("Paste these rules into AdGuard Home under Filters → Custom filtering rules.", "Add these to Pi-hole's denylist.") : a.text)}</p>${a.rules.length ? rulesBlock(a.rules) + adguardLink() : ""}</div>`;
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
  const named = o.companies.filter((c) => !c.unexplained);
  const unnamed = o.companies.filter((c) => c.unexplained);
  const card = (c) => `<div class="card comp">
      <div class="top"><span class="cn">${c.flags.join("")} ${esc(c.company)}</span>${c.tracking ? '<span class="chip bad">ads or tracking</span>' : ""}
      <span class="bytes">${c.bytes_out ? "↑ " + bytes(c.bytes_out) : plural(c.lookups, "lookup")}</span></div>
      <div class="meta">Used by ${plural(c.devices.length, "device or service", "devices and services")}</div>
      <div class="chips">${c.devices.map((n) => `<span class="chip">${esc(n)}</span>`).join("")}</div></div>`;
  // Unidentified destinations, grouped by whose network they're on.
  const byOwner = {};
  unnamed.forEach((c) => (byOwner[c.owner || "Network unknown"] = byOwner[c.owner || "Network unknown"] || []).push(c));
  const owners = Object.entries(byOwner).map(([owner, list]) => ({ owner, list,
    bytes: list.reduce((a, c) => a + c.bytes_out, 0), addresses: list.reduce((a, c) => a + c.addresses, 0),
    devices: [...new Set(list.flatMap((c) => c.devices))], flags: [...new Set(list.flatMap((c) => c.flags))] }))
    .sort((a, b) => b.bytes - a.bytes || b.addresses - a.addresses);
  const ownerRow = (g) => `<details class="card owner"><summary>
      <span class="cn">${g.flags.join("")} ${esc(g.owner)}</span>
      <span class="muted">${plural(g.addresses, "address", "addresses")} · ${plural(g.devices.length, "device or service", "devices and services")}</span>
      <span class="bytes">${g.bytes ? "↑ " + bytes(g.bytes) : ""}</span></summary>
      <div class="pad" style="padding-top:0">${g.list.map((c) => `<div class="urow"><span>${esc(c.company.replace(" on " + g.owner, ""))}</span><span class="muted">${esc(c.devices.join(", "))}</span><span class="num">${c.bytes_out ? bytes(c.bytes_out) : ""}</span></div>`).join("")}</div></details>`;
  return `<section><h1>Companies</h1><p class="lede">Everyone your devices and services talk to, across the whole home. Red means ads or tracking.</p>
    <div class="grid" style="margin-top:22px">${named.map(card).join("") || '<div class="card empty">Nothing named yet.</div>'}</div>
    ${owners.length ? `<h2>Unidentified destinations <small>addresses nothing looked up, grouped by whose network they're on</small></h2>
      <p class="muted" style="margin-top:-6px">These were reached without a DNS lookup we saw: fixed addresses, peers, relays, or a lookup older than the data kept. The network owner says who hosts it, not who runs it; the label says what kind of traffic it was.</p>
      <div class="owners">${owners.map(ownerRow).join("")}</div>` : ""}</section>`;
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
  if (window.WL_DEMO) return demoOnly("Settings");
  const auth = statusCache?.auth;
  return `<section><h1>Settings</h1>
    ${auth ? `<h2>Change password</h2><form class="card pad form" id="pw">
      <label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
      <label>New password<input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
      <button class="btn">Change password</button><div class="msg" id="pwmsg"></div></form>
      <h2>Sign out</h2><div class="card pad"><button class="btn ghost" id="logout">Sign out</button></div>`
      : `<div class="card pad">Login is off (WL_AUTH=off): something in front of this app handles sign-in.</div>`}
    <h2>Data source</h2><div class="card pad">${statusCache?.configurable
      ? `Reading from <b>${esc({ adguard: "AdGuard Home", demo: "demo data" }[statusCache.source] || statusCache.source)}</b>${statusCache.adguard_url ? ` at <span class="mono">${esc(statusCache.adguard_url)}</span>` : ""}. <a href="#/connect">${statusCache.source === "demo" ? "Connect your AdGuard Home →" : "Change the connection →"}</a>`
      : `Set by environment settings (${esc(statusCache?.source || "")}); change them in <span class="mono">.env</span>.`}</div>
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

/* ---------- per-device DNS steps (shared by the guide and the wizard) */
const DEVICE_STEPS = [
  ["iPhone, iPad", "Settings → Wi-Fi → (i) next to your network → Configure DNS → Manual → remove the existing servers, add the address."],
  ["Mac", "System Settings → Wi-Fi → Details on your network → DNS → replace the servers with the address."],
  ["Windows", "Settings → Network & internet → Wi-Fi (or Ethernet) → Hardware properties → DNS server assignment → Edit → Manual → IPv4 on → the address."],
  ["Android phone or tablet", "Settings → Wi-Fi → your network → Edit → Advanced → IP settings: Static, then DNS 1 = the address. (Android's \"Private DNS\" needs AdGuard with encryption set up, so it's harder.)"],
  ["Apple TV", "Settings → Network → your network → Configure DNS → Manual → the address."],
  ["Google TV, Android TV", "Settings → Network & Internet → your network → IP settings: Static → DNS 1 = the address."],
  ["Samsung, LG and other smart TVs", "Network settings → IP or advanced settings → DNS: Manual (or Enter manually) → the address."],
  ["PlayStation, Xbox, Switch", "Network settings → set up connection → manual / advanced → DNS: Manual → primary = the address."],
  ["Roku, smart plugs, fans, appliances", "No DNS setting. Use a helper router, or your router's DNS setting, for these."],
];
function thisAddress() {
  // Only an address other devices can use: not this machine's loopback.
  const h = location.hostname;
  if (/^127\.|^\[?::1\]?$/.test(h)) return "";
  return /^[0-9.]+$|^\[?[0-9a-f:]+\]?$/i.test(h) ? h : "";
}

/* ---------- see each device separately */
function renderVisible(o) {
  const ip = thisAddress() || "the address of the machine running AdGuard";
  const r = o.router;
  const step = (who, how) => `<tr><td><b>${who}</b></td><td>${how}</td></tr>`;
  return `<section><h1>See each device separately</h1>
    <p class="lede">The goal is one line per device: the TV, the speaker, each phone. That needs each device to ask AdGuard directly, instead of asking your router.</p>
    ${r ? `<div class="finding check" style="margin-top:16px"><span class="ico">${ICON.router}</span><span><div class="t">Right now ${Math.round(r.share * 100)}% of lookups come from ${esc(r.client)}, your router, so devices are hidden behind it.</div>
      <div>Below are the ways to fix that, best first. You can mix them: for example, the router for most things and a few devices set by hand.</div></span></div>` : ""}
    <h2>1. Change the DNS your router hands out <small>best: every device at once</small></h2>
    <div class="card pad">
      <p style="margin-top:0">In your router's settings, look for <b>DHCP</b> or <b>LAN</b> settings and a <b>DNS server</b> field, and enter <span class="mono">${esc(ip)}</span>. Every device picks it up as it reconnects. Many standalone routers allow this (often under "DHCP server" or "LAN"); routers running OpenWrt, OPNsense, pfSense and UniFi always do.</p>
      <p style="margin-bottom:0" class="muted"><b>Google Wifi, Nest Wifi and eero can't.</b> Their DNS setting only changes where the router itself forwards lookups, which is why everything shows as the router. With one of those, use 2 and 3, or 4.</p>
    </div>
    <h2>2. Set DNS on each device <small>no new hardware; phones, computers, most TVs</small></h2>
    <div class="card pad scroll">
      <p style="margin-top:0">Set the DNS server to <span class="mono">${esc(ip)}</span> on the devices you care about most. Each takes about a minute.</p>
      <table><tbody>
        ${DEVICE_STEPS.map(([who, how]) => step(who, how)).join("")}
      </tbody></table>
      <p class="muted" style="margin-bottom:0">Also switch off IPv6 DNS from the router: either give the device the address for IPv6 too, or turn IPv6 off in the router's app (Google Home app → Wi-Fi → Settings → Advanced networking → IPv6). Otherwise some lookups still go through the router.</p>
    </div>
    <h2>3. A small helper router for appliances <small>for devices with no DNS setting</small></h2>
    <div class="card pad"><p style="margin:0">A pocket travel router (about $30 to $120; some have AdGuard built in) plugged into your network gives a few appliances their own Wi-Fi. Set its DNS to <span class="mono">${esc(ip)}</span>, move the appliances onto it in their apps, and each shows up separately. Good for the devices near it; it doesn't replace your mesh.</p></div>
    <h2>4. A router that hands out AdGuard <small>every device, permanently</small></h2>
    <div class="card pad"><p style="margin:0">Use a router that lets you set the DNS it hands out (see 1), and keep good Wi-Fi coverage with access points that mesh in access-point mode. A mesh like Google Wifi can't be kept as the router here: in bridge mode it loses its extra points. This takes an evening and some hardware, and gives every device its own line.</p></div>
    <p class="muted" style="margin-top:18px">Until then, the router's line shows the whole home as one: still useful for what the house as a whole talks to.</p>
  </section>`;
}

/* ---------- first-run wizard */
async function wizardDone() {
  await api("/api/wizard", { done: true }).catch(() => {});
  if (statusCache) statusCache.wizard_done = true;
}
function renderStart() {
  const bundle = statusCache?.source === "adguard-log";
  const choice = (id, icon, title, text) => `<button class="card pad choice" id="${id}"><span class="ico">${icon}</span><span><b>${title}</b><span class="muted">${text}</span></span></button>`;
  return `<section class="wizard"><div class="step">Welcome</div><h1>How do you want to start?</h1>
    <p class="lede">You can change this later in Settings. Nothing here changes your network.</p>
    <div class="choices">
      ${bundle ? choice("w-bundle", ICON.dns, "Set up AdGuard and my first device", "You installed AdGuard Home together with this app. Two short steps, then you'll see your first device.") : ""}
      ${!bundle ? choice("w-connect", ICON.dns, "Connect my AdGuard Home", "You already run AdGuard Home. Enter its address and login, test, done.") : ""}
      ${!bundle ? choice("w-demo", ICON.media, "Look around the demo first", "Made-up devices, every kind of result. Connect yours whenever you like.") : ""}
    </div></section>`;
}
function wireStart() {
  $("#w-bundle")?.addEventListener("click", () => (location.hash = "#/first-device"));
  $("#w-connect")?.addEventListener("click", () => { sessionStorageSet("wl-after-connect", "first-device"); location.hash = "#/connect"; });
  $("#w-demo")?.addEventListener("click", async () => { await wizardDone(); location.hash = "#/"; });
}
function sessionStorageSet(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* fine */ } }
function sessionStorageTake(k) { try { const v = sessionStorage.getItem(k); sessionStorage.removeItem(k); return v; } catch (e) { return null; } }

let waitTimer = null;
function renderFirstDevice() {
  const ip = thisAddress();
  const waitingAg = statusCache?.waiting_for_adguard;
  const agUrl = statusCache?.adguard_url || (statusCache?.adguard_ui_port ? `${location.protocol}//${location.hostname}:${statusCache.adguard_ui_port}` : "");
  return `<section class="wizard"><div class="step">First device</div><h1>Point one device here</h1>
    <p class="lede">Pick a phone, laptop or TV. Set its DNS to this machine and you'll see it on its own line in a few minutes. Only that device changes; nothing else on your network does.</p>
    ${waitingAg && agUrl ? `<div class="finding check" style="margin-top:16px"><span class="ico">${ICON.alert}</span><span><div class="t">First, finish AdGuard Home's setup</div>
      <div>Open <a href="${esc(agUrl)}" target="_blank" rel="noopener">${esc(agUrl)}</a> and follow its five steps. Keep its web page on port ${esc(statusCache.adguard_ui_port || "3000")} and DNS on port 53.</div></span></div>` : ""}
    <div class="card pad" style="margin-top:18px">
      <div class="addr"><span class="muted">The address to enter</span><b class="mono">${esc(ip || "this machine's address on your network (for example 192.168.1.10)")}</b>${ip ? `<button class="copy" data-copy="${esc(ip)}">${ICON.copy} Copy</button>` : ""}</div>
      <div class="seg dtype" role="group" aria-label="Device type">${DEVICE_STEPS.slice(0, 8).map(([who], i) => `<button data-i="${i}" aria-pressed="${i === 0}">${esc(who)}</button>`).join("")}</div>
      <p id="dsteps" class="dsteps">${esc(DEVICE_STEPS[0][1])}</p>
      <p class="muted" style="margin-bottom:0;font-size:13px">On your phone? Open this page there: <span class="mono">${esc(location.origin)}/#/first-device</span></p>
    </div>
    <div class="card pad waitbox" id="waitbox"><span class="pulse"></span><span><b>Waiting for a new device…</b><span class="muted">This updates by itself as soon as its first lookups arrive.</span></span></div>
    <p style="margin-top:18px"><a href="#/" id="w-skip">Skip for now →</a></p></section>`;
}
function wireFirstDevice() {
  wireCopy();
  document.querySelectorAll(".dtype button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".dtype button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    $("#dsteps").textContent = DEVICE_STEPS[+b.dataset.i][1];
  }));
  $("#w-skip")?.addEventListener("click", () => wizardDone());
  const since = new Date().toISOString();
  clearInterval(waitTimer);
  const check = async () => {
    if (!document.getElementById("waitbox")) return clearInterval(waitTimer);
    const found = await api("/api/new-clients?since=" + encodeURIComponent(since)).catch(() => []);
    if (!found.length) return;
    clearInterval(waitTimer);
    const d = found[0];
    $("#waitbox").outerHTML = `<div class="finding good" style="margin-top:18px"><span class="ico">${ICON.check}</span><span>
      <div class="k">Found it</div><div class="t">${esc(d.name || d.client)} is here, with ${plural(d.lookups, "lookup")} so far.</div>
      <a class="go" href="#/device/${encodeURIComponent(d.client)}" id="w-see">See what it talks to →</a></span></div>`;
    $("#w-see").addEventListener("click", () => { overviewCache = null; wizardDone(); });
  };
  waitTimer = setInterval(check, 5000);
}

/* ---------- connect AdGuard Home */
function demoOnly(title) {
  return `<section><h1>${title}</h1><div class="card pad">This is the live demo: nothing can be changed here. <a href="${esc(window.WL_DEMO.repo || "#/")}">Install it</a> to connect your own network, in about five minutes.</div></section>`;
}
function renderConnect() {
  if (window.WL_DEMO) return demoOnly("Connect your AdGuard Home");
  if (!statusCache?.configurable) return `<section><h1>Connect AdGuard Home</h1><div class="card pad">The source is set by environment settings (.env), so it's changed there, not here.</div></section>`;
  return `<section><h1>Connect your DNS filter</h1>
    <p class="lede">What Leaves Home reads your DNS filter's query log. It only reads; it changes nothing there.</p>
    <div class="cols">
      <form class="card pad form" id="cform" style="max-width:none">
        <div class="seg" role="radiogroup" aria-label="Which DNS filter"><button type="button" data-t="adguard" aria-pressed="true">AdGuard Home</button><button type="button" data-t="pihole" aria-pressed="false">Pi-hole</button></div>
        <input type="hidden" name="type" value="adguard">
        <label><span id="urllabel">AdGuard Home address</span><input name="url" placeholder="http://192.168.1.2:3000" value="${esc(statusCache.adguard_url || "")}" required></label>
        <label id="userrow">Username<input name="user" autocomplete="off"></label>
        <label><span id="pwlabel">Password</span><input type="password" name="password" autocomplete="off"></label>
        <div style="display:flex;gap:10px"><button class="btn ghost" type="button" id="ctest">Test</button><button class="btn" id="csave" disabled>Save and start reading</button></div>
        <div class="msg" id="cmsg"></div>
      </form>
      <div class="card pad"><h2 style="margin-top:0">Good to know</h2><ul class="why">
        <li>The address is the one you open AdGuard's web page at, including the port.</li>
        <li>The login is saved in this app's database on this machine, and used only to read the query log.</li>
        <li>Saving replaces the demo devices with your own. The first results appear within a minute.</li>
        <li>If every lookup comes from one address, your router is answering DNS for every device; the test will tell you, and how to fix it.</li>
      </ul></div>
    </div><div id="cresult"></div></section>`;
}
function wireConnect() {
  const form = $("#cform");
  if (!form) return;
  form.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => {
    const ph = b.dataset.t === "pihole";
    form.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    form.elements.type.value = b.dataset.t;
    $("#urllabel").textContent = ph ? "Pi-hole address" : "AdGuard Home address";
    form.elements.url.placeholder = ph ? "http://192.168.1.2" : "http://192.168.1.2:3000";
    $("#userrow").classList.toggle("hidden", ph);
    $("#pwlabel").textContent = ph ? "App password (Pi-hole → Settings → Web interface / API)" : "Password";
    $("#csave").disabled = true;
  }));
  const data = () => Object.fromEntries(new FormData(form));
  const show = (r) => {
    const m = $("#cmsg");
    m.className = "msg " + (r.ok ? "ok" : "err");
    m.textContent = r.ok ? `Connected to ${/^Pi-hole/.test(r.version) ? r.version : "AdGuard Home " + r.version}: ${r.lookups} recent lookups from ${plural(r.clients, "address", "addresses")}.` : r.message;
    $("#csave").disabled = !r.ok;
    $("#cresult").innerHTML = r.ok && r.router_suspect ? `<div class="finding check" style="margin-top:16px"><span class="ico">${ICON.alert}</span><span>
      <div class="k">Heads up</div><div class="t">${Math.round(r.top_share * 100)}% of lookups come from one address (${esc(r.top_client)}): probably your router.</div>
      <div>Your router is answering DNS for every device and passing it on, so they'd all show up as one. Fix it by setting AdGuard Home's address as the DNS server in your router's DHCP settings, or see the README section "Every device shows up as my router". You can still save now.</div></span></div>` : "";
  };
  $("#ctest").addEventListener("click", async () => { $("#cmsg").textContent = "Testing…"; show(await api("/api/connect/test", data()).catch((e) => e.data || { ok: false, message: e.message })); });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await api("/api/connect/save", data()).catch((err) => err.data || { ok: false, message: err.message });
    show(r);
    if (r.saved) {
      overviewCache = null; await refreshStatus();
      const next = sessionStorageTake("wl-after-connect");
      setTimeout(() => (location.hash = next ? "#/" + next : "#/"), 1200);
    }
  });
}

/* ---------- sign-in gate */
function gate(mode) {
  const setup = mode === "setup";
  $("#shell").classList.add("hidden");
  const g = $("#gate");
  g.className = "gate";
  g.innerHTML = `<form class="card form" id="gform">
      <div class="brand"><img src="logo.svg" alt="" width="30" height="30"><span>What Leaves Home</span></div>
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
  const st = statusCache || {};
  if (!st.wizard_done && !window.WL_DEMO && (st.configurable || st.source === "adguard-log") && (!location.hash || location.hash === "#/")) {
    location.hash = "#/start";
    return;  // the hashchange runs route()
  }
  route();
}

window.addEventListener("hashchange", () => { window.scrollTo(0, 0); route(); });
document.getElementById("theme")?.addEventListener("click", () => {
  const next = THEMES[(THEMES.indexOf(getTheme()) + 1) % THEMES.length];
  try { localStorage.setItem("wl-theme", next); } catch (e) { /* private window: just this visit */ }
  applyTheme(next);
});
setInterval(async () => { await refreshStatus(); if (!location.hash.includes("settings") && !document.querySelector(".namefield")) { overviewCache = null; route(); } }, 120000);
boot();
