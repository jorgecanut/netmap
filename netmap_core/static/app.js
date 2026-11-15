/* NetMap web UI. Plain JS, no build step. Sections:
   1 helpers  2 API + login  3 map  4 state/polling  5 header  6 map layers
   7 live list  8 history list  9 timeline  10 settings drawer  11 boot      */
"use strict";

// ---------------------------------------------------------------- 1 helpers
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEV_NAMES = ["none","info","low","medium","high"];
const SEV_COLORS = [null, null, "#fab219", "#f07c3c", "#d03b3b"];
let regionNames = null;
try { regionNames = new Intl.DisplayNames(["en"], {type:"region"}); } catch(e) {}
function countryName(cc){
  if(!cc) return "";
  try { return regionNames ? regionNames.of(cc) : cc; } catch(e) { return cc; }
}
function flagEmoji(cc){
  if(!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0)));
}
function place(g, dirs){
  if(!g) return (dirs || []).includes("internal") ? "↔ your local network" : "location pending…";
  return flagEmoji(g.cc) + " " + (g.city ? g.city + ", " : "") + (countryName(g.cc) || "Unknown");
}
function fmtBytes(b){
  if(b == null) return "–";
  if(b < 1024) return b + " B";
  if(b < 1048576) return (b/1024).toFixed(1) + " KB";
  if(b < 1073741824) return (b/1048576).toFixed(1) + " MB";
  return (b/1073741824).toFixed(2) + " GB";
}
const fmtRate = b => b == null ? "n/a" : fmtBytes(Math.round(b)) + "/s";
function fmtDur(s){
  s = Math.max(0, Math.round(s));
  if(s < 60) return s + "s";
  if(s < 3600) return Math.floor(s/60) + "m " + (s%60) + "s";
  if(s < 86400) return Math.floor(s/3600) + "h " + Math.floor(s%3600/60) + "m";
  return Math.floor(s/86400) + "d " + Math.floor(s%86400/3600) + "h";
}
const ago = s => fmtDur(s) + " ago";
function fmtTime(t, withDate){
  const d = new Date(t * 1000);
  const p = n => String(n).padStart(2, "0");
  const hm = p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  return withDate ? d.getFullYear() + "-" + p(d.getMonth()+1) + "-" + p(d.getDate()) + " " + hm : hm;
}
const sevClass = s => s > 0 ? " sev-" + s : "";
function badges(flags){
  return (flags || []).map(f => '<span class="badge s' + f.severity + (f.suppressed ? " supp" : "")
    + '" title="' + esc((f.src === "rule" ? "Rule" : f.src === "verdict" ? "Your verdict" : "Blocklist")
      + " · " + f.category + " · " + SEV_NAMES[f.severity] + (f.meaning ? " — " + f.meaning : "")
      + (f.suppressed ? " (you trust this — not counted)" : "")) + '">'
    + (f.src === "rule" ? "&#9881; " : "&#9888; ") + esc(f.name) + "</span>").join("");
}
function devChip(d){
  return '<span class="dev" style="--c:' + esc(d.color || "#3987e5") + '" title="'
    + esc((d.ip || "") + (d.subnet ? " · " + d.subnet : "")) + '">' + esc(d.name) + "</span>";
}
const DIR_LABEL = {out:"out", in:"in", internal:"internal"};

// ------------------------------------------------------------ 2 API + login
let CSRF = null, ME = null;
async function api(method, path, body){
  const opt = {method, headers:{}, cache:"no-store"};
  if(method !== "GET"){
    opt.headers["Content-Type"] = "application/json";
    opt.headers["X-NetMap-CSRF"] = CSRF || "";
    opt.body = JSON.stringify(body || {});
  }
  const res = await fetch(path, opt);
  let data = null;
  try { data = await res.json(); } catch(e) { data = {error: "bad response (" + res.status + ")"}; }
  if(res.status === 401 && path !== "/api/me"){ showLogin(); throw new Error("login required"); }
  if(!res.ok) throw new Error(data && data.error || ("HTTP " + res.status));
  return data;
}

function showLogin(){
  const setup = ME && ME.setup;
  $("loginOverlay").hidden = false;
  $("loginTitle").textContent = setup ? "Set up NetMap" : "NetMap";
  $("loginHelp").textContent = setup
    ? "Choose the admin password. The setup code is in the NetMap log (docker logs netmap)."
    : "Log in as admin.";
  $("setupCode").hidden = !setup;
  $("pw2").hidden = !setup;
  $("loginBtn").textContent = setup ? "Save password" : "Log in";
  (setup ? $("setupCode") : $("pw1")).focus();
}
$("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const msg = $("loginMsg");
  msg.innerHTML = "";
  try{
    let r;
    if(ME && ME.setup){
      if($("pw1").value !== $("pw2").value) throw new Error("the two passwords differ");
      r = await api("POST", "/api/setup", {code: $("setupCode").value, password: $("pw1").value});
    } else {
      r = await api("POST", "/api/login", {password: $("pw1").value});
    }
    CSRF = r.csrf;
    $("pw1").value = $("pw2").value = "";
    $("loginOverlay").hidden = true;
    boot();
  }catch(err){
    msg.innerHTML = '<div class="msg err">' + esc(err.message) + "</div>";
  }
});

// ------------------------------------------------------------------- 3 map
const HAS_MAP = typeof L !== "undefined";
let map = null, tileBanner = null;
if(HAS_MAP){
  map = L.map("map", {worldCopyJump:true, zoomControl:true, minZoom:2}).setView([25, 0], 2);
  const osmAttr = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';
  let tileOK = false, tileErrs = 0, fellBack = false;
  // Primary: Esri World Dark Gray (free, no API key; CARTO now needs one).
  // Fallback: OpenStreetMap with a CSS dark filter. Both need a Referer, which
  // the server's Referrer-Policy sends (origin only).
  const base = L.tileLayer(
    "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
    attribution: 'Tiles &copy; <a href="https://www.esri.com">Esri</a> &mdash; Esri, HERE, Garmin, &copy; OpenStreetMap contributors',
    maxZoom:16, referrerPolicy:"strict-origin-when-cross-origin"}).addTo(map);
  const fallback = () => {
    if(fellBack) return;
    fellBack = true;
    map.removeLayer(base);
    const osm = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      {attribution: osmAttr, maxZoom:19, className:"osm-dark",
       referrerPolicy:"strict-origin-when-cross-origin"});   // OSM tile policy needs a Referer
    let ok = false;
    osm.on("tileload", () => { ok = true; });
    osm.on("tileerror", () => { if(!ok) tileBanner = "Map tiles are unreachable; connections still plot."; });
    osm.addTo(map);
  };
  base.on("tileload", () => { tileOK = true; });
  base.on("tileerror", () => { if(!tileOK && ++tileErrs >= 3) fallback(); });
  setTimeout(() => { if(!tileOK) fallback(); }, 8000);
} else {
  $("map").innerHTML = '<div class="empty">Map library could not load (cdnjs.cloudflare.com). '
    + "The list on the right still works.</div>";
}
const BLUE = "#3987e5", GREEN = "#199e70";

function arcPoints(a, b){
  let lon2 = b[1];
  if(Math.abs(lon2 - a[1]) > 180) lon2 += (a[1] > lon2 ? 360 : -360);
  const p0 = a, p2 = [b[0], lon2];
  const mx = (p0[0]+p2[0])/2, my = (p0[1]+p2[1])/2, dx = p2[0]-p0[0], dy = p2[1]-p0[1];
  const dist = Math.hypot(dx, dy) || 1, bow = Math.min(dist * 0.18, 14);
  const c = [mx + (-dy/dist)*bow, my + (dx/dist)*bow], pts = [];
  for(let i = 0; i <= 40; i++){
    const t = i/40, u = 1-t;
    pts.push([u*u*p0[0] + 2*u*t*c[0] + t*t*p2[0], u*u*p0[1] + 2*u*t*c[1] + t*t*p2[1]]);
  }
  return pts;
}
function dotIcon(cls, size, color){
  return L.divIcon({className:"", iconSize:[size, size], html:'<div class="nm-dot ' + cls + '"'
    + (color ? ' style="--c:' + esc(color) + '"' : "") + '><span class="ring"></span><span class="core"></span></div>'});
}

// ------------------------------------------------------- 4 state + polling
const S = {
  scope: "local", side: "live", data: null, expanded: new Set(),
  q: "", subnets: new Set(), flagged: false,
  live: true, t: null, range: 86400, playing: null,
  hist: [], histNext: null, histKey: "",
};
let pollTimer = null;

async function refresh(){
  if(!S.live) return;
  try{
    render(await api("GET", "/api/live?scope=" + S.scope));
  }catch(e){ /* server briefly unavailable or logged out; next tick retries */ }
}
function startPolling(){
  clearInterval(pollTimer);
  pollTimer = setInterval(refresh, 2500);
  refresh();
}

function setScope(scope){
  if(S.scope === scope) return;
  S.scope = scope;
  $("scopeLocal").classList.toggle("on", scope === "local");
  $("scopeNetwork").classList.toggle("on", scope === "network");
  $("tagline").textContent = scope === "local"
    ? "This machine. Every connection. One map." : "Every device. Every connection. One map.";
  S.subnets.clear(); S.expanded.clear(); S.data = null;
  clearLayers();
  goLive();
  if(S.side === "history") loadHistory(true);
  syncHash();
}
$("scopeLocal").onclick = () => setScope("local");
$("scopeNetwork").onclick = () => setScope("network");

function hostVisible(h){
  if(S.flagged && !h.severity) return false;
  if(S.subnets.size && !h.devices.some(d => S.subnets.has(d.subnet))) return false;
  if(S.q){
    const hay = [h.ip, h.domain, h.geo && h.geo.city, h.geo && countryName(h.geo.cc),
      h.geo && h.geo.cc, h.geo && h.geo.org, ...h.devices.map(d => d.name + " " + d.ip + " " + d.subnet),
      ...h.flags.map(f => f.name + " " + f.category), h.severity ? "flagged threat" : "",
      ...h.dirs].join(" ").toLowerCase();
    if(!hay.includes(S.q)) return false;
  }
  return true;
}

function render(d){
  S.data = d;
  renderHeader(d);
  renderChips(d);
  renderMap(d);
  if(S.side === "live") renderList();
}

// ------------------------------------------------------------- 5 header
function renderHeader(d){
  const st = d.stats;
  $("ver").textContent = "v" + d.version;
  $("tActive").textContent = st.active;
  $("tHosts").textContent = st.hosts;
  $("tFlagged").textContent = st.flagged;
  $("tileFlagged").classList.toggle("hot", !!st.flagged);
  $("tCountries").textContent = st.countries;
  if(S.scope === "local"){
    $("tExtraLbl").textContent = "↓ / ↑ rate";
    $("tExtra").textContent = d.rates && d.rates.down != null
      ? fmtRate(d.rates.down) + " / " + fmtRate(d.rates.up) : "n/a";
  } else {
    $("tExtraLbl").textContent = "devices";
    $("tExtra").textContent = st.devices;
  }
  const gp = $("geoPill");
  const geoOk = d.geo_offline === "ok" || d.geo_state === "ok";
  gp.className = "pill" + (geoOk ? "" : d.geo_state === "waiting" ? " warn" : " bad");
  $("geoTxt").textContent = "geo: " + (d.geo_offline === "ok" ? "offline db"
    : d.geo_offline === "building" ? "building db…" : d.geo_state === "ok" ? "online" : d.geo_state);
  const th = d.threat || {}, tp = $("threatPill");
  tp.hidden = !th.loaded && !(th.errors || []).length;
  tp.className = "pill" + (st.flagged ? " bad" : (th.errors || []).length ? " warn" : "");
  $("threatTxt").textContent = "threat lists: " + (th.loaded || 0).toLocaleString()
    + ((th.errors || []).length ? " · " + th.errors.length + " failing" : "");
  const rp = $("routerPill");
  if(S.scope === "network" && d.router){
    rp.hidden = false;
    const r = d.router;
    rp.className = "pill" + (!r.enabled ? " off" : r.state === "connected" ? "" : r.state === "error" ? " bad" : " warn");
    $("routerTxt").textContent = "router: " + (!r.configured ? "not set up" : !r.enabled ? "off" : r.state);
    rp.title = r.error || "";
  } else rp.hidden = true;
  const tsp = $("tsPill"), tn = d.tailnet;
  if(S.scope === "local" && tn && tn.available){
    tsp.hidden = false;
    tsp.className = "pill" + (tn.error ? " warn" : "");
    $("tsTxt").textContent = tn.error ? "tailscale: not ready"
      : "tailscale: " + tn.peers.filter(p => p.online && p.active).length + " active / " + tn.peers.length;
  } else tsp.hidden = true;
  const msg = d.scan_error ? "Connection scan failed: " + d.scan_error
    : (S.scope === "network" && d.router && !d.router.configured)
      ? "The Network tab needs your router: open Settings → Router." : tileBanner;
  $("banner").hidden = !msg;
  $("banner").textContent = msg || "";
}

function renderChips(d){
  let html = '<span class="chip sev' + (S.flagged ? " on" : "") + '" data-flag="1"><span class="dot" style="--c:#d03b3b"></span>flagged only</span>';
  if(S.scope === "network"){
    for(const s of d.subnets || []){
      html += '<span class="chip' + (S.subnets.has(s.name) ? " on" : "") + '" style="--c:' + esc(s.color)
        + '" data-subnet="' + esc(s.name) + '" title="' + esc(s.cidr) + '"><span class="dot"></span>' + esc(s.name) + "</span>";
    }
  }
  if($("chips").innerHTML !== html) $("chips").innerHTML = html;
}
$("chips").addEventListener("click", e => {
  const c = e.target.closest(".chip");
  if(!c) return;
  if(c.dataset.flag) S.flagged = !S.flagged;
  else { const n = c.dataset.subnet; S.subnets.has(n) ? S.subnets.delete(n) : S.subnets.add(n); }
  if(S.data) render(S.data);
  if(S.side === "history") loadHistory(true);
});
$("q").addEventListener("input", () => {
  S.q = $("q").value.trim().toLowerCase();
  if(S.data) render(S.data);
  if(S.side === "history"){ clearTimeout(S.qTimer); S.qTimer = setTimeout(() => loadHistory(true), 300); }
});

// ---------------------------------------------------------- 6 map layers
let homeMarker = null, homeLL = null;
const layers = new Map(), peerLayers = new Map();
function clearLayers(){
  for(const m of [layers, peerLayers]){
    for(const e of m.values()){ map && map.removeLayer(e.marker); if(e.arc) map.removeLayer(e.arc); }
    m.clear();
  }
}
function hostColor(h){
  if(h.severity >= 2) return SEV_COLORS[h.severity];
  if(S.scope === "network"){
    const d = h.devices.find(d => d.color);
    if(d) return d.color;
  }
  return BLUE;
}
function tooltipHTML(h){
  const g = h.geo || {};
  const rows = h.conns.slice(0, 8).map(c => esc(S.scope === "network" ? c.name : c.proc)
    + (c.dir === "in" ? " &larr; " : " &rarr; ") + ":" + esc(c.port) + " " + esc(c.proto.toUpperCase())
    + (c.active ? "" : " (closed)")).join("<br>");
  return (h.flags.length ? '<div class="tt-threat">&#9888; ' + esc(h.flags.map(f => f.name).join(", ")) + "</div>" : "")
    + '<div class="tt-loc">' + esc(place(h.geo)) + "</div>"
    + '<div class="tt-ip">' + esc(h.domain || h.ip) + (h.domain ? " · " + esc(h.ip) : "") + "</div>"
    + (g.org ? '<div class="tt-isp">' + esc(g.org) + "</div>" : "")
    + '<div class="tt-conns">' + rows + (h.conns.length > 8 ? "<br>… +" + (h.count - 8) + " more" : "") + "</div>";
}
function renderMap(d){
  if(!HAS_MAP) return;
  if(d.home && !homeMarker){
    homeLL = [d.home.lat, d.home.lon];
    homeMarker = L.marker(homeLL, {icon: dotIcon("home", 14), zIndexOffset:1000}).addTo(map)
      .bindTooltip('<div class="tt-loc">' + flagEmoji(d.home.cc) + " Home</div>"
        + '<div class="tt-ip">' + esc(d.home.city || "") + "</div>", {className:"nm", direction:"top", offset:[0,-8]});
    map.setView(homeLL, 3);
  }
  const seen = new Set();
  for(const h of d.hosts){
    if(!h.geo || !hostVisible(h)) continue;
    seen.add(h.ip);
    const ll = [h.geo.lat, h.geo.lon], size = Math.min(10 + h.count * 2, 22);
    const color = hostColor(h), active = h.active > 0, bad = h.severity >= 2;
    const inbound = h.dirs.includes("in") && !h.dirs.includes("out");
    const sig = [color, active, size, inbound].join("|");
    let e = layers.get(h.ip);
    if(!e){
      e = {marker: L.marker(ll, {icon: dotIcon(active ? "active" : "", size, color), zIndexOffset: bad ? 800 : 0})
             .addTo(map).bindTooltip(tooltipHTML(h), {className:"nm", direction:"top", offset:[0,-8], sticky:true}),
           arc: null, sig: ""};
      layers.set(h.ip, e);
    }
    if(e.sig !== sig){
      e.marker.setIcon(dotIcon(active ? "active" : "", size, color));
      e.marker.setZIndexOffset(bad ? 800 : 0);
      if(e.arc){ map.removeLayer(e.arc); e.arc = null; }
      e.sig = sig;
    }
    if(!e.arc && homeLL){
      e.arc = L.polyline(arcPoints(homeLL, ll), {color, weight: bad ? 2.2 : 1.5,
        opacity: bad ? .85 : active ? .6 : .18, interactive:false,
        className: active ? "nm-arc" + (inbound ? " in" : "") : ""}).addTo(map);
    }
    e.marker.setTooltipContent(tooltipHTML(h));
    e.marker.setOpacity(active || bad ? 1 : .35);
  }
  for(const [ip, e] of layers){
    if(!seen.has(ip)){ map.removeLayer(e.marker); if(e.arc) map.removeLayer(e.arc); layers.delete(ip); }
  }
  // tailscale peers (this machine only)
  const pseen = new Set();
  if(S.scope === "local" && d.tailnet){
    for(const p of d.tailnet.peers || []){
      if(!p.geo) continue;
      pseen.add(p.name);
      const on = p.online && p.active, ll = [p.geo.lat, p.geo.lon];
      let e = peerLayers.get(p.name);
      if(!e){
        e = {marker: L.marker(ll, {icon: dotIcon("peer" + (on ? " active" : ""), 14), zIndexOffset:500}).addTo(map)
          .bindTooltip('<div class="tt-loc">' + esc(p.name) + '</div><div class="tt-ip">' + esc(p.ip) + "</div>",
            {className:"nm", direction:"top", offset:[0,-8]}),
          arc: homeLL ? L.polyline(arcPoints(homeLL, ll), {color: GREEN, weight:1.5, opacity: on ? .55 : .18,
            className: on ? "nm-peerarc" : "", interactive:false}).addTo(map) : null};
        peerLayers.set(p.name, e);
      }
      e.marker.setOpacity(on ? 1 : .4);
    }
  }
  for(const [n, e] of peerLayers){
    if(!pseen.has(n)){ map.removeLayer(e.marker); if(e.arc) map.removeLayer(e.arc); peerLayers.delete(n); }
  }
}
function flyTo(ip){
  const e = layers.get(ip);
  if(e && map){ map.flyTo(e.marker.getLatLng(), Math.max(map.getZoom(), 5)); e.marker.openTooltip(); }
}

// ------------------------------------------------------------ 7 live list
$("tabLive").onclick = () => setSide("live");
$("tabHist").onclick = () => setSide("history");
function setSide(side){
  S.side = side;
  $("tabLive").classList.toggle("on", side === "live");
  $("tabHist").classList.toggle("on", side === "history");
  if(side === "history") loadHistory(true); else renderList();
  syncHash();
}

function hostRow(h){
  const open = S.expanded.has(h.ip);
  const who = S.scope === "network"
    ? h.devices.slice(0, 4).map(devChip).join(" ") + (h.devices.length > 4 ? " +" + (h.devices.length - 4) : "")
    : esc(h.devices.map(d => d.name).join(", "));
  const ports = [...new Set(h.conns.map(c => ":" + c.port))].slice(0, 6).join(" ");
  let html = '<div class="host' + (h.active ? "" : " inactive") + sevClass(h.severity) + '" data-ip="' + esc(h.ip) + '">'
    + (h.flags.length ? '<div class="badges">' + badges(h.flags) + "</div>" : "")
    + '<div class="top"><div class="who">' + who + "</div>"
    + '<div class="cnt">' + h.dirs.map(x => '<span class="dir ' + x + '">' + DIR_LABEL[x] + "</span>").join(" ")
    + " " + h.count + (h.count > 1 ? " conns" : " conn") + "</div></div>"
    + '<div class="loc">' + esc(place(h.geo, h.dirs)) + (h.geo && h.geo.org ? " · " + esc(h.geo.org) : "") + "</div>"
    + '<div class="ipline">' + esc(h.domain ? h.domain + "  " : "") + esc(h.ip) + "&ensp;" + esc(ports) + "</div>";
  if(open) html += hostDetail(h);
  return html + "</div>";
}
function hostDetail(h){
  let html = '<div class="detail">';
  for(const f of h.flags){
    if(f.meaning) html += '<div class="meaning"><b>' + esc(f.name) + ":</b> " + esc(f.meaning) + "</div>";
  }
  for(const c of h.conns){
    html += '<div class="crow"><span>' + (S.scope === "network" ? devChip(c) : esc(c.proc))
      + ' <span class="dir ' + c.dir + '">' + DIR_LABEL[c.dir] + "</span> :" + esc(c.port) + " " + esc(c.proto)
      + "</span><span>" + (c.active ? "open " + fmtDur(Date.now()/1000 - c.start)
        : "closed " + ago(c.age)) + (c.bytes_out != null ? " · ↑" + fmtBytes(c.bytes_out) + " ↓" + fmtBytes(c.bytes_in) : "")
      + "</span></div>";
  }
  html += '<div class="actions">'
    + '<button class="btn" data-verdict="trusted" data-target="ip:' + esc(h.ip) + '">Trust IP</button>'
    + '<button class="btn" data-verdict="suspicious" data-target="ip:' + esc(h.ip) + '">Mark suspicious</button>'
    + '<button class="btn danger" data-verdict="ignore" data-target="ip:' + esc(h.ip) + '">Ignore IP</button>'
    + (h.domain ? '<button class="btn" data-verdict="trusted" data-target="domain:' + esc(h.domain) + '">Trust ' + esc(h.domain) + "</button>" : "")
    + "</div></div>";
  return html;
}
function renderList(){
  if(S.side !== "live") return;
  const d = S.data, list = $("list");
  if(!d){ list.innerHTML = '<div class="empty">Waiting for data…</div>'; return; }
  const rows = d.hosts.filter(hostVisible).map(hostRow);
  let html = "";
  if(!S.live) html += '<div class="note">Showing ' + esc(fmtTime(S.t, true)) + " — press Live to return.</div>";
  html += rows.length ? rows.join("") : '<div class="empty">' + (S.q || S.flagged || S.subnets.size
    ? "No matches." : S.scope === "network" ? "No router connections yet…" : "No public connections seen yet…") + "</div>";
  if(S.scope === "local" && S.live && d.tailnet && d.tailnet.peers && d.tailnet.peers.length){
    html += '<div class="section-hd"><span class="tn">&#9679; Tailscale</span> peers</div>'
      + d.tailnet.peers.map(p => '<div class="peer' + (p.online ? "" : " off") + '"><div class="top"><b>'
        + esc(p.name) + '</b><span class="state' + (p.online ? " on" : "") + '">'
        + (p.online && p.active ? "active" : p.online ? "online" : "offline") + '</span></div><div class="mono">'
        + esc(p.ip) + (p.os ? " · " + esc(p.os) : "") + (p.relay && !p.direct ? " · via " + esc(p.relay) : "")
        + "</div></div>").join("");
  }
  const scroll = list.scrollTop;
  list.innerHTML = html;
  list.scrollTop = scroll;
}
$("list").addEventListener("click", async e => {
  const vb = e.target.closest("[data-verdict]");
  if(vb){
    e.stopPropagation();
    const v = vb.dataset.verdict, target = vb.dataset.target;
    if(v === "ignore" && !confirm("Stop logging and showing " + target + "?\nUndo it in Settings → Verdicts.")) return;
    try{ await api("POST", "/api/verdicts", {target, verdict: v}); vb.textContent = "✓ saved"; }
    catch(err){ alert(err.message); }
    return;
  }
  if(e.target.closest(".detail")) return;
  const row = e.target.closest(".host");
  if(!row) return;
  if(row.dataset.hist){
    const r = S.hist.find(x => String(x.id) === row.dataset.hist);
    if(r) jumpTo(r.start + 1, r.remote_ip);
    return;
  }
  const ip = row.dataset.ip;
  S.expanded.has(ip) ? S.expanded.delete(ip) : S.expanded.add(ip);
  renderList();
  flyTo(ip);
});

// --------------------------------------------------------- 8 history list
async function loadHistory(reset){
  const key = [S.scope, S.q, [...S.subnets].join(","), S.flagged].join("|");
  if(reset || key !== S.histKey){ S.hist = []; S.histNext = null; S.histKey = key; }
  const params = new URLSearchParams({scope: S.scope, limit: "200"});
  if(S.q) params.set("q", S.q);
  if(S.subnets.size) params.set("subnets", [...S.subnets].join(","));
  if(S.flagged) params.set("sev", "1");
  if(!reset && S.histNext) params.set("before", S.histNext);
  try{
    const r = await api("GET", "/api/history?" + params);
    if(key !== S.histKey) return;            // filters changed while loading
    S.hist = S.hist.concat(r.rows);
    S.histNext = r.next;
    renderHistory();
  }catch(err){
    $("list").innerHTML = '<div class="empty">Could not load history: ' + esc(err.message) + "</div>";
  }
}
function renderHistory(){
  if(S.side !== "history") return;
  const now = Date.now() / 1000;
  const rows = S.hist.map(c => {
    const dur = c.end ? fmtDur(c.end - c.start) : "open";
    const who = S.scope === "network" ? devChip(c) : esc(c.proc || "");
    return '<div class="host' + (c.active ? "" : " inactive") + sevClass(c.severity) + '" data-hist="' + esc(c.id) + '">'
      + (c.flags.length ? '<div class="badges">' + badges(c.flags) + "</div>" : "")
      + '<div class="top"><div class="who">' + who + ' <span class="dir ' + c.dir + '">' + DIR_LABEL[c.dir] + "</span></div>"
      + '<div class="cnt">' + esc(fmtTime(c.start, now - c.start > 86400)) + "</div></div>"
      + '<div class="loc">' + esc(place(c.geo, [c.dir])) + (c.geo && c.geo.org ? " · " + esc(c.geo.org) : "") + "</div>"
      + '<div class="ipline">' + esc(c.domain ? c.domain + "  " : "") + esc(c.remote_ip) + " :" + esc(c.port)
      + " " + esc(c.proto) + "</div>"
      + '<div class="when">' + dur + (c.bytes_out != null ? " · ↑" + fmtBytes(c.bytes_out) + " ↓" + fmtBytes(c.bytes_in) : "")
      + "</div></div>";
  });
  $("list").innerHTML = '<div class="note">Newest first · click a row to see the map at that moment</div>'
    + (rows.length ? rows.join("") : '<div class="empty">Nothing logged yet.</div>')
    + (S.histNext ? '<div class="empty"><button class="btn" id="moreBtn">Load older</button></div>' : "");
  const more = $("moreBtn");
  if(more) more.onclick = () => loadHistory(false);
}

// -------------------------------------------------------------- 9 timeline
function sliderToT(v){ const now = Date.now()/1000; return now - S.range * (1 - v/1000); }
function tToSlider(t){ const now = Date.now()/1000; return Math.round(1000 * (1 - (now - t) / S.range)); }
function goLive(){
  S.live = true; S.t = null;
  stopPlay();
  $("tSlider").value = 1000;
  $("tLabel").textContent = "live";
  $("liveBtn").classList.add("on");
  startPolling();
}
async function showAt(t){
  S.live = false; S.t = t;
  clearInterval(pollTimer);
  $("liveBtn").classList.remove("on");
  $("tLabel").textContent = fmtTime(t, true);
  try{ render(await api("GET", "/api/at?scope=" + S.scope + "&t=" + t)); }
  catch(err){ $("tLabel").textContent = "error: " + err.message; }
}
function jumpTo(t, ip){
  const now = Date.now()/1000;
  while(now - t > S.range && S.range < 31536000){
    const sel = $("tRange"), i = [...sel.options].findIndex(o => +o.value > S.range);
    if(i < 0) break;
    sel.selectedIndex = i; S.range = +sel.value;
  }
  $("tSlider").value = tToSlider(t);
  showAt(t).then(() => ip && flyTo(ip));
}
let sliderTimer = null;
$("tSlider").addEventListener("input", () => {
  const v = +$("tSlider").value;
  stopPlay();
  if(v >= 1000) return goLive();
  const t = sliderToT(v);
  $("tLabel").textContent = fmtTime(t, true);
  clearTimeout(sliderTimer);
  sliderTimer = setTimeout(() => showAt(t), 200);
});
$("tRange").onchange = () => {
  S.range = +$("tRange").value;
  if(!S.live) $("tSlider").value = Math.max(0, tToSlider(S.t));
};
$("liveBtn").onclick = goLive;
function stopPlay(){ clearInterval(S.playing); S.playing = null; $("playBtn").innerHTML = "&#9654;"; }
$("playBtn").onclick = () => {
  if(S.playing) return stopPlay();
  if(S.live) { S.t = sliderToT(0); $("tSlider").value = 0; }
  $("playBtn").innerHTML = "&#10074;&#10074;";
  S.playing = setInterval(() => {
    const t = S.t + S.range / 150;
    if(t >= Date.now()/1000) return goLive();
    $("tSlider").value = tToSlider(t);
    showAt(t);
  }, 700);
};

// ---------------------------------------------------- 10 settings drawer
let CFG = null, PANE = "router";
$("settingsBtn").onclick = () => openSettings(PANE);
$("setClose").onclick = () => { $("settings").hidden = true; };
$("settings").addEventListener("click", e => { if(e.target.id === "settings") $("settings").hidden = true; });
$("setNav").addEventListener("click", e => { const b = e.target.closest("button"); if(b) openSettings(b.dataset.pane); });
async function openSettings(pane){
  PANE = pane;
  $("settings").hidden = false;
  for(const b of $("setNav").querySelectorAll("button")) b.classList.toggle("on", b.dataset.pane === pane);
  try{ CFG = await api("GET", "/api/config"); }
  catch(err){ $("paneBody").innerHTML = '<div class="msg err">' + esc(err.message) + "</div>"; return; }
  PANES[pane]();
}
const msgBox = (kind, text) => '<div class="msg ' + kind + '">' + esc(text) + "</div>";
async function act(fn, okText, outId){
  const out = $(outId || "paneMsg");
  try{ await fn(); if(out) out.innerHTML = okText ? msgBox("ok", okText) : ""; return true; }
  catch(err){ if(out) out.innerHTML = msgBox("err", err.message); return false; }
}
const sevOptions = sel => [1,2,3,4].map(i => '<option value="' + i + '"' + (i === sel ? " selected" : "") + ">"
  + SEV_NAMES[i] + "</option>").join("");

const PANES = {
  router(){
    const r = CFG.router, st = r.status;
    const line = r.public_key ? 'command="/usr/bin/netmap-feed",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ' + r.public_key : "";
    $("paneBody").innerHTML = '<h2>Router</h2><p>NetMap reads every connection from your OpenWrt router over SSH. '
      + "Full walkthrough: <code>docs/ROUTER.md</code>.</p>"
      + '<div class="form">'
      + '<label>Enabled</label><input type="checkbox" id="rEnabled"' + (r.enabled ? " checked" : "") + ">"
      + '<label>Router address</label><input class="in" id="rHost" placeholder="192.168.2.1" value="' + esc(r.host) + '">'
      + '<label>SSH port</label><input class="in" id="rPort" type="number" value="' + esc(r.port) + '">'
      + '<label>SSH user</label><input class="in" id="rUser" value="' + esc(r.user) + '">'
      + '<label>Domain names</label><label><input type="checkbox" id="rDns"' + (r.dns ? " checked" : "") + "> read the dnsmasq query log</label>"
      + "</div>"
      + '<button class="btn primary" id="rSave">Save</button> <button class="btn" id="rTest">Test connection</button> '
      + '<button class="btn danger" id="rForget">Forget host key</button><div id="paneMsg"></div>'
      + "<h3>Status</h3>" + msgBox(st.state === "connected" ? "ok" : st.state === "error" ? "err" : "info",
          "Connections feed: " + st.state + (st.error ? " — " + st.error : "")
          + (st.events ? " · " + st.events.toLocaleString() + " events" : "")
          + " · DNS feed: " + st.dns + (st.dns_error ? " — " + st.dns_error : ""))
      + "<h3>NetMap's public key</h3><p>On the router, add this line to <code>/etc/dropbear/authorized_keys</code>. "
      + "It only lets NetMap run the <code>netmap-feed</code> script.</p>"
      + (r.key_error ? msgBox("err", r.key_error) : '<pre class="code" id="rKey">' + esc(line) + "</pre>"
        + '<button class="btn" id="rCopy">Copy</button>');
    $("rSave").onclick = () => act(() => api("POST", "/api/router", {enabled: $("rEnabled").checked,
      host: $("rHost").value, port: +$("rPort").value, user: $("rUser").value, dns: $("rDns").checked}),
      "Saved. NetMap reconnects to the router now.");
    $("rTest").onclick = async () => {
      $("paneMsg").innerHTML = msgBox("info", "Connecting…");
      try{
        const t = await api("POST", "/api/router/test");
        $("paneMsg").innerHTML = t.ok ? msgBox("ok", "Connected. The router reports " + t.devices + " DHCP leases.")
          : msgBox("err", t.error);
      }catch(err){ $("paneMsg").innerHTML = msgBox("err", err.message); }
    };
    $("rForget").onclick = () => act(() => api("POST", "/api/router/forget-host-key"), "Host key forgotten; the next connection accepts the router's current key.");
    if($("rCopy")) $("rCopy").onclick = () => navigator.clipboard.writeText(line).then(() => { $("rCopy").textContent = "Copied"; });
  },

  subnets(){
    const rows = CFG.subnets.map(s => '<tr data-id="' + s.id + '"><td><input type="color" class="in sc" value="' + esc(s.color)
      + '"></td><td><input class="in sn" value="' + esc(s.name) + '"></td><td><input class="in sr" value="' + esc(s.cidr)
      + '"></td><td><button class="btn ssave">Save</button> <button class="btn danger sdel">Delete</button></td></tr>').join("");
    const sugg = CFG.suggested_subnets.map(s => '<button class="btn sadd" data-cidr="' + esc(s.cidr) + '">+ ' + esc(s.cidr)
      + " (" + s.devices + " devices)</button>").join(" ");
    const palette = ["#3987e5","#9085e9","#36b5c9","#d36fb4","#e5a039","#7a8cff","#8fb339","#c98a5a"];
    const next = palette[CFG.subnets.length % palette.length];
    $("paneBody").innerHTML = "<h2>Subnets</h2><p>Name your networks (LAN, IoT, Guest…). Devices take the colour of their "
      + "subnet on the map, and you can filter by subnet. IPv6 devices need their prefix added here too "
      + "(e.g. <code>2a01:db8:1:2::/64</code>).</p>"
      + '<table class="t"><tr><th>Colour</th><th>Name</th><th>Range</th><th></th></tr>' + rows
      + '<tr><td><input type="color" class="in" id="nColor" value="' + next + '"></td><td><input class="in" id="nName" placeholder="IoT"></td>'
      + '<td><input class="in" id="nCidr" placeholder="192.168.3.0/24"></td><td><button class="btn primary" id="nAdd">Add</button></td></tr></table>'
      + '<div id="paneMsg"></div>' + (sugg ? "<h3>Seen on your network, not named yet</h3>" + sugg : "");
    const body = $("paneBody");
    body.querySelectorAll(".ssave").forEach(b => b.onclick = () => {
      const tr = b.closest("tr");
      act(() => api("POST", "/api/subnets", {id: +tr.dataset.id, name: tr.querySelector(".sn").value,
        cidr: tr.querySelector(".sr").value, color: tr.querySelector(".sc").value}), "Saved.");
    });
    body.querySelectorAll(".sdel").forEach(b => b.onclick = async () => {
      if(confirm("Delete this subnet? Logged connections are kept.") &&
        await act(() => api("DELETE", "/api/subnets?id=" + b.closest("tr").dataset.id))) openSettings("subnets");
    });
    body.querySelectorAll(".sadd").forEach(b => b.onclick = () => { $("nCidr").value = b.dataset.cidr; $("nName").focus(); });
    $("nAdd").onclick = async () => {
      if(await act(() => api("POST", "/api/subnets", {name: $("nName").value, cidr: $("nCidr").value, color: $("nColor").value})))
        openSettings("subnets");
    };
  },

  devices(){
    const rows = CFG.devices.map(d => '<tr><td class="mono">' + esc(d.ip) + "</td><td>" + esc(d.subnet) + '</td><td class="mono">'
      + esc(d.mac) + "</td><td>" + esc(d.lease_name) + '</td><td><input class="in dn" data-ip="' + esc(d.ip) + '" value="'
      + esc(d.name) + '" placeholder="' + esc(d.lease_name || "name") + '"></td></tr>').join("");
    $("paneBody").innerHTML = "<h2>Devices</h2><p>Devices seen by the router. Names from DHCP are used automatically; type a "
      + "name to override it (empty = back to the DHCP name). Changes save when you leave the field.</p>"
      + '<div id="paneMsg"></div><table class="t"><tr><th>IP</th><th>Subnet</th><th>MAC</th><th>DHCP name</th><th>Your name</th></tr>'
      + (rows || '<tr><td colspan="5" class="help">No devices yet — set up the router first.</td></tr>') + "</table>";
    $("paneBody").querySelectorAll(".dn").forEach(i => i.onchange = () =>
      act(() => api("POST", "/api/devices", {ip: i.dataset.ip, name: i.value}), "Saved " + i.dataset.ip + "."));
  },

  rules(){
    const rows = CFG.rules.map(r => '<tr class="' + (r.enabled ? "" : "off") + '" data-id="' + r.id + '"><td><b>' + esc(r.name)
      + '</b><br><code>' + esc(r.expr) + "</code>" + (r.error ? msgBox("err", r.error.count + " errors, last: " + r.error.last) : "")
      + '</td><td><span class="badge s' + r.severity + '">' + SEV_NAMES[r.severity] + "</span><br>" + esc(r.category)
      + '</td><td><button class="btn redit">Edit</button></td></tr>').join("");
    const fields = Object.entries(CFG.rule_fields).map(([k, v]) => "<code>" + esc(k) + "</code><span>" + esc(v) + "</span>").join("");
    const funcs = Object.values(CFG.rule_functions).map(v => "<code>" + esc(v) + "</code>").join(" ");
    $("paneBody").innerHTML = "<h2>Rules</h2><p>Your own threat checks. Each rule is one expression in Python syntax, run on every "
      + "connection when it opens and again when it closes. Matches are flagged with your category and severity. "
      + "Reference and examples: <code>docs/RULES.md</code>.</p>"
      + '<table class="t"><tr><th>Rule</th><th>Flag</th><th></th></tr>' + (rows || '<tr><td colspan="3" class="help">No rules yet.</td></tr>') + "</table>"
      + '<h3 id="rTitle">New rule</h3><input type="hidden" id="ruleId">'
      + '<div class="form"><label>Name</label><input class="in" id="ruleName" placeholder="IoT device reaching a new country">'
      + '<label>Expression</label><textarea class="in" id="ruleExpr" placeholder=\'subnet == "IoT" and direction == "out" and new_country\'></textarea>'
      + '<label>Category</label><input class="in" id="ruleCat" placeholder="iot-anomaly">'
      + '<label>Severity</label><select class="in" id="ruleSev">' + sevOptions(2) + "</select>"
      + '<label>Enabled</label><input type="checkbox" id="ruleOn" checked></div>'
      + '<button class="btn" id="ruleTest">Test on recent connections</button> <button class="btn primary" id="ruleSave">Save</button> '
      + '<button class="btn danger" id="ruleDel" hidden>Delete</button> <button class="btn" id="ruleNew" hidden>New rule</button>'
      + '<div id="paneMsg"></div><div id="ruleOut"></div>'
      + '<h3>Fields</h3><div class="fields">' + fields + "</div><h3>Functions</h3><p>" + funcs + "</p>"
      + "<p>Constants: <code>info</code> <code>low</code> <code>medium</code> <code>high</code> (for <code>threat_severity</code>). "
      + "Operators: <code>and or not == != &lt; &gt; in not in + - * /</code></p>";
    const fill = r => {
      $("ruleId").value = r ? r.id : ""; $("ruleName").value = r ? r.name : ""; $("ruleExpr").value = r ? r.expr : "";
      $("ruleCat").value = r ? r.category : ""; $("ruleSev").value = r ? r.severity : 2; $("ruleOn").checked = r ? !!r.enabled : true;
      $("rTitle").textContent = r ? "Edit rule" : "New rule"; $("ruleDel").hidden = $("ruleNew").hidden = !r;
      $("ruleOut").innerHTML = $("paneMsg").innerHTML = "";
    };
    $("paneBody").querySelectorAll(".redit").forEach(b => b.onclick = () => {
      fill(CFG.rules.find(r => r.id === +b.closest("tr").dataset.id)); $("ruleName").scrollIntoView({behavior:"smooth"});
    });
    $("ruleNew").onclick = () => fill(null);
    $("ruleSave").onclick = async () => {
      if(await act(() => api("POST", "/api/rules", {id: +$("ruleId").value || null, name: $("ruleName").value,
        expr: $("ruleExpr").value, category: $("ruleCat").value, severity: +$("ruleSev").value,
        enabled: $("ruleOn").checked}), "Saved.")) setTimeout(() => openSettings("rules"), 600);
    };
    $("ruleDel").onclick = async () => {
      if(confirm("Delete this rule? Flags it already added to the log stay.") &&
        await act(() => api("DELETE", "/api/rules?id=" + $("ruleId").value))) openSettings("rules");
    };
    $("ruleTest").onclick = async () => {
      $("ruleOut").innerHTML = msgBox("info", "Testing…");
      try{
        const r = await api("POST", "/api/rules/test", {expr: $("ruleExpr").value, scope: S.scope, limit: 5000});
        $("ruleOut").innerHTML = msgBox(r.errors ? "err" : "ok", "Matched " + r.matched + " of the last " + r.checked
          + " " + (S.scope === "network" ? "network" : "this-machine") + " connections"
          + (r.errors ? " · " + r.errors + " errors, first: " + r.first_error : ""))
          + r.samples.map(c => '<div class="mono">' + esc(fmtTime(c.start, true)) + "  " + esc(c.name) + " → "
            + esc(c.domain || c.remote_ip) + ":" + esc(c.port) + " " + esc(c.geo ? c.geo.cc : "") + "</div>").join("");
      }catch(err){ $("ruleOut").innerHTML = msgBox("err", err.message); }
    };
  },

  verdicts(){
    const rows = CFG.verdicts.map(v => '<tr><td class="mono">' + esc(v.target) + "</td><td>" + esc(v.verdict) + "</td><td>"
      + esc(v.note || "") + '</td><td><button class="btn danger vdel" data-t="' + esc(v.target) + '">Remove</button></td></tr>').join("");
    $("paneBody").innerHTML = "<h2>Verdicts</h2><p>Your decisions about specific addresses, domains or devices. "
      + "<b>trusted</b>: flags still shown but crossed out and not counted. <b>suspicious</b>: always flagged (medium). "
      + "<b>ignore</b>: not logged or shown at all.</p>"
      + '<table class="t"><tr><th>Target</th><th>Verdict</th><th>Note</th><th></th></tr>' + rows
      + '<tr><td><select class="in" id="vKind"><option>ip</option><option>domain</option><option>device</option></select>'
      + '<input class="in" id="vVal" placeholder="1.2.3.4 / netflix.com / 192.168.3.20"></td>'
      + '<td><select class="in" id="vVerdict"><option>trusted</option><option>suspicious</option><option>ignore</option></select></td>'
      + '<td><input class="in" id="vNote"></td><td><button class="btn primary" id="vAdd">Add</button></td></tr></table><div id="paneMsg"></div>';
    $("paneBody").querySelectorAll(".vdel").forEach(b => b.onclick = async () => {
      if(await act(() => api("DELETE", "/api/verdicts?target=" + encodeURIComponent(b.dataset.t)))) openSettings("verdicts");
    });
    $("vAdd").onclick = async () => {
      if(await act(() => api("POST", "/api/verdicts", {target: $("vKind").value + ":" + $("vVal").value.trim(),
        verdict: $("vVerdict").value, note: $("vNote").value}))) openSettings("verdicts");
    };
  },

  threats(){
    const rows = CFG.threats.sources.map(s => "<tr><td><b>" + esc(s.label) + "</b><br><span class=\"help\">" + esc(s.category)
      + '</span></td><td><span class="badge s' + SEV_NAMES.indexOf(s.severity) + '">' + esc(s.severity) + "</span></td><td>"
      + s.entries.toLocaleString() + "</td><td>" + (s.updated ? esc(ago(Date.now()/1000 - s.updated)) : "never")
      + (s.error ? msgBox("err", s.error) : "") + "</td></tr>").join("");
    $("paneBody").innerHTML = "<h2>Threat lists</h2><p>Public blocklists, refreshed every 6 hours. A failing list keeps its last good "
      + "copy. To add one, edit <code>SOURCES</code> in <code>netmap_core/threats.py</code>.</p>"
      + '<table class="t"><tr><th>List</th><th>Severity</th><th>Entries</th><th>Updated</th></tr>' + rows + "</table>";
  },

  account(){
    const g = CFG.geo;
    $("paneBody").innerHTML = "<h2>Account &amp; storage</h2>"
      + (ME.auth_disabled ? msgBox("info", "Login is disabled (--no-auth).") :
        '<h3>Change admin password</h3><div class="form"><label>Current</label><input class="in" type="password" id="pCur">'
        + '<label>New</label><input class="in" type="password" id="pNew"><label>Repeat</label><input class="in" type="password" id="pNew2"></div>'
        + '<button class="btn primary" id="pSave">Change password</button> <span class="help">Logs out every other session.</span>')
      + '<div id="paneMsg"></div>'
      + "<h3>Storage</h3><p>Connection log: <b>" + CFG.db_mb + " MB</b> of " + CFG.db_max_mb + " MB. When full, the oldest "
      + "connections are deleted first. Change the cap with <code>NETMAP_MAX_DB_MB</code>.</p>"
      + "<h3>Geolocation</h3><p>Offline database: <b>" + esc(g.offline) + "</b>" + (g.month ? " (DB-IP " + esc(g.month) + ")" : "")
      + ". Online fallback (ip-api.com): <b>" + esc(g.online) + "</b>. Addresses the offline database doesn't know are looked "
      + "up online once and stored.</p>";
    if($("pSave")) $("pSave").onclick = () => {
      if($("pNew").value !== $("pNew2").value){ $("paneMsg").innerHTML = msgBox("err", "the new passwords differ"); return; }
      act(() => api("POST", "/api/password", {current: $("pCur").value, new: $("pNew").value}), "Password changed.");
    };
  },
};

// -------------------------------------------------------------------- 11 boot
$("logoutBtn").onclick = async () => { try{ await api("POST", "/api/logout"); }catch(e){} location.reload(); };
$("quitBtn").onclick = async () => {
  try{ await api("POST", "/api/quit"); }catch(e){}
  clearInterval(pollTimer);
  $("stopped").hidden = false;
};
async function boot(){
  try{ ME = await api("GET", "/api/me"); }
  catch(err){ $("list").innerHTML = '<div class="empty">Cannot reach NetMap: ' + esc(err.message) + "</div>"; return; }
  if(!ME.authed){ showLogin(); return; }
  CSRF = ME.csrf;
  $("ver").textContent = "v" + ME.version;
  $("logoutBtn").hidden = ME.auth_disabled;
  $("quitBtn").hidden = !ME.auth_disabled;
  if(HAS_MAP && !boot.done) map.attributionControl.addAttribution('<a href="https://db-ip.com">IP Geolocation by DB-IP</a>');
  boot.done = true;
  // Bookmarkable views: #network, #network-history, #settings-rules, ...
  const hash = location.hash.slice(1);
  if(hash.startsWith("network")) setScope("network"); else goLive();
  if(hash.endsWith("-history")) setSide("history");
  if(hash.startsWith("settings-") && PANES[hash.slice(9)]) openSettings(hash.slice(9));
}
function syncHash(){
  const h = (S.scope === "network" ? "network" : "") + (S.side === "history" ? (S.scope === "network" ? "-history" : "local-history") : "");
  history.replaceState(null, "", h ? "#" + h : location.pathname);
}
boot();
