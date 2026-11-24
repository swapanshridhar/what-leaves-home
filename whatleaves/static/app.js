"use strict";

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1000)), u.length - 1);
  return (n / 1000 ** i).toFixed(i ? 1 : 0) + " " + u[i];
}

function when(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  const mins = (Date.now() - d) / 60000;
  if (mins < 1) return "just now";
  if (mins < 60) return Math.round(mins) + " min ago";
  if (mins < 24 * 60) return Math.round(mins / 60) + " h ago";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " +
         d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

async function get(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + ": " + r.status);
  return r.json();
}

let current = null;

async function loadStatus() {
  const s = await get("/api/status");
  const src = { adguard: "AdGuard Home", files: "collector files", demo: "demo data" }[s.source] || s.source;
  $("#status").textContent = `Source: ${src} · keeps ${s.keep_days} days · ` +
    (s.last_error ? `last read failed: ${s.last_error}` : s.last_poll ? `updated ${when(s.last_poll)}` : "first read pending");
  const banner = $("#banner");
  if (s.source === "demo") {
    banner.hidden = false;
    banner.textContent = "You are looking at made-up demo devices. Set WL_ADGUARD_URL (see the README) to see your own network.";
  } else {
    banner.hidden = true;
  }
}

async function loadDevices() {
  const list = await get("/api/devices");
  const ul = $("#devices");
  if (!list.length) {
    ul.innerHTML = '<li class="empty">No devices yet. Data appears after the first read.</li>';
    return;
  }
  ul.innerHTML = list.map((d) => `
    <li><button data-client="${esc(d.client)}" aria-current="${d.client === current}">
      <div class="dname">${esc(d.name || d.client)}</div>
      <div class="dmeta">${d.name ? esc(d.client) + " · " : ""}${plural(d.sites, "site")} · ${plural(d.destinations, "destination")} · last seen ${when(d.last)}</div>
    </button></li>`).join("");
  ul.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => show(b.dataset.client)));
  if (!current) show(list[0].client);
}

function table(cols, rows) {
  if (!rows.length) return '<p class="sub">None recorded.</p>';
  return `<div class="scroll"><table><thead><tr>${cols.map((c) => `<th class="${c.num ? "num" : ""}">${c.label}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td class="${c.num ? "num" : ""}">${c.cell(r)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

async function show(client) {
  current = client;
  document.querySelectorAll("#devices button").forEach((b) => b.setAttribute("aria-current", b.dataset.client === client));
  const d = await get("/api/device?client=" + encodeURIComponent(client));
  const out = d.connections.reduce((a, c) => a + c.bytes_out, 0);
  const inn = d.connections.reduce((a, c) => a + c.bytes_in, 0);
  const remote = d.connections.filter((c) => !c.local).length;
  const lookups = d.lookups.reduce((a, l) => a + l.count, 0);
  $("#detail").innerHTML = `
    <h2>${esc(d.name || d.client)}</h2>
    <div class="sub">${esc(d.client)}</div>
    <div class="stats">
      <div class="stat"><b>${d.sites.length}</b><span>sites looked up</span></div>
      <div class="stat"><b>${lookups}</b><span>lookups</span></div>
      <div class="stat"><b>${remote}</b><span>internet destinations</span></div>
      <div class="stat"><b>${bytes(out)}</b><span>sent</span></div>
      <div class="stat"><b>${bytes(inn)}</b><span>received</span></div>
    </div>
    ${d.flags.map((f) => `<div class="flag">${esc(f)}</div>`).join("")}
    <h3>Sites</h3>
    ${table([
      { label: "Site", cell: (s) => `<span class="mono">${esc(s.site)}</span>${s.blocked ? '<span class="tag block">blocked</span>' : ""}` },
      { label: "Names", num: true, cell: (s) => s.names },
      { label: "Lookups", num: true, cell: (s) => s.count },
      { label: "Last seen", cell: (s) => when(s.last) },
    ], d.sites)}
    <h3>Connections</h3>
    ${table([
      { label: "Destination", cell: (c) => `<span class="mono">${esc(c.dst)}</span>${c.local ? '<span class="tag">local</span>' : ""}` },
      { label: "Port", num: true, cell: (c) => `${c.dport}<span class="tag">${esc(c.proto)}</span>` },
      { label: "Looked up as", cell: (c) => c.names.length ? `<span class="mono">${c.names.map(esc).join("<br>")}</span>` : (c.local ? "" : '<span class="tag block">no lookup</span>') },
      { label: "Sent", num: true, cell: (c) => bytes(c.bytes_out) },
      { label: "Received", num: true, cell: (c) => bytes(c.bytes_in) },
      { label: "Last seen", cell: (c) => when(c.last) },
    ], d.connections)}
    <h3>Names looked up</h3>
    ${table([
      { label: "Name", cell: (l) => `<span class="mono">${esc(l.name)}</span>${l.blocked ? '<span class="tag block">blocked</span>' : ""}` },
      { label: "Lookups", num: true, cell: (l) => l.count },
      { label: "Answers", cell: (l) => `<span class="mono">${l.addresses.map(esc).join(", ")}</span>` },
      { label: "Last seen", cell: (l) => when(l.last) },
    ], d.lookups)}`;
}

async function refresh() {
  try {
    await loadStatus();
    await loadDevices();
    if (current) await show(current);
  } catch (e) {
    $("#status").textContent = "Can't reach the server: " + e.message;
  }
}

refresh();
setInterval(refresh, 60000);
