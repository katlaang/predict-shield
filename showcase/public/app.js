"use strict";

const ACTIONS = [
  ["restart_enforcer", "Restart"],
  ["resync_policy", "Resync"],
  ["gateway_restrict", "Restrict"],
  ["monitor_only", "Monitor only"],
];
const ACTION_NAME = Object.fromEntries(ACTIONS);
const FAULT_NAME = { loss: "Lost revocation event", consumer_paused: "Paused event listener", delay: "Delayed revocation event" };
const CLASS_NAME = { persistent: "Lasting fault", self_healing: "Self-healing fault" };
const REPO = "https://github.com/katlaang/predict-shield";

const $ = (sel) => document.querySelector(sel);
const pct = (x, d = 1) => (x === null || x === undefined ? "n/a" : `${(100 * x).toFixed(d)}%`);
const fmt = (n) => Number(n).toLocaleString("en-US");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function getJSON(path) {
  const r = await fetch(path, { cache: "force-cache" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

/* ---------- hero grid ---------- */

let view = "verifier";
let trials = [];
let selected = null;

function verifierClass(t) {
  if (t.scope === "VERIFIED") return t.oracle_denied ? "ok" : "false";
  if (t.scope === "NOT VERIFIED") return t.oracle_denied ? "missed" : "caught";
  return "abstain";
}
function cellState(t) {
  return view === "verifier" ? verifierClass(t) : (t.oracle_denied ? "fixed" : "exposed");
}

function buildGrid(rows) {
  const grid = $("#grid");
  const cfgs = [...new Map(rows.map((t) => [t.cfg, t])).values()]
    .sort((a, b) => (a.cls === b.cls ? (a.fault === b.fault ? a.cfg.localeCompare(b.cfg) : a.fault.localeCompare(b.fault))
      : a.cls === "persistent" ? -1 : 1));
  const lasting = cfgs.filter((c) => c.cls === "persistent").length;
  const colOf = new Map(cfgs.map((c, i) => [c.cfg, i + 2 + (i >= lasting ? 1 : 0)]));
  const cols = ["auto", ...Array(lasting).fill("var(--cell)"), "6px", ...Array(cfgs.length - lasting).fill("var(--cell)")];
  grid.style.gridTemplateColumns = cols.join(" ");

  const frag = document.createDocumentFragment();
  const band = (text, start, span) => {
    const el = document.createElement("div");
    el.className = "band";
    el.textContent = text;
    el.style.gridRow = "1";
    el.style.gridColumn = `${start} / span ${span}`;
    frag.appendChild(el);
  };
  band(`${lasting} lasting faults`, 2, lasting);
  band(`${cfgs.length - lasting} self-healing`, lasting + 3, cfgs.length - lasting);

  const byKey = new Map();
  for (const t of rows) {
    const k = `${t.cfg}|${t.action}`;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(t);
  }
  ACTIONS.forEach(([id, label], a) => {
    const firstRow = 2 + a * 4;
    const rl = document.createElement("div");
    rl.className = "rl";
    rl.textContent = label;
    rl.style.gridColumn = "1";
    rl.style.gridRow = `${firstRow} / span 3`;
    frag.appendChild(rl);
    if (a < ACTIONS.length - 1) {
      const sp = document.createElement("div");
      sp.style.gridRow = String(firstRow + 3);
      sp.style.height = "5px";
      frag.appendChild(sp);
    }
    for (const c of cfgs) {
      const reps = (byKey.get(`${c.cfg}|${id}`) || []).sort((x, y) => x.run.localeCompare(y.run));
      reps.forEach((t, r) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "cell";
        b.dataset.run = t.run;
        b.style.gridColumn = String(colOf.get(c.cfg));
        b.style.gridRow = String(firstRow + r);
        b.setAttribute("aria-label", `${ACTION_NAME[t.action]}, ${FAULT_NAME[t.fault]}, ${t.cfg}, repeat ${r + 1}`);
        b.setAttribute("aria-selected", "false");
        b.tabIndex = -1;
        frag.appendChild(b);
      });
    }
  });
  grid.appendChild(frag);
  const first = grid.querySelector(".cell");
  if (first) first.tabIndex = 0;
  paint();

  grid.addEventListener("click", (e) => {
    const b = e.target.closest(".cell");
    if (b) select(b);
  });
  grid.addEventListener("keydown", onGridKey);
}

function onGridKey(e) {
  const cur = e.target.closest(".cell");
  if (!cur) return;
  const col = +cur.style.gridColumn, row = +cur.style.gridRow;
  const delta = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[e.key];
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(cur); return; }
  if (!delta) return;
  e.preventDefault();
  const cells = [...document.querySelectorAll(".cell")];
  let best = null, bestD = Infinity;
  for (const c of cells) {
    const dc = +c.style.gridColumn - col, dr = +c.style.gridRow - row;
    if ((delta[0] && Math.sign(dc) === delta[0] && dr === 0) || (delta[1] && Math.sign(dr) === delta[1] && dc === 0)) {
      const d = Math.abs(dc) + Math.abs(dr);
      if (d < bestD) { bestD = d; best = c; }
    }
  }
  if (best) { cur.tabIndex = -1; best.tabIndex = 0; best.focus(); }
}

function paint() {
  const byRun = new Map(trials.map((t) => [t.run, t]));
  for (const b of document.querySelectorAll(".cell")) b.dataset.v = cellState(byRun.get(b.dataset.run));
  renderLegend();
}

function renderLegend() {
  const counts = {};
  for (const t of trials) { const k = cellState(t); counts[k] = (counts[k] || 0) + 1; }
  const items = view === "verifier"
    ? [["ok", "var(--ok)", "Said fixed, and it was"], ["caught", "var(--bad)", "Said not fixed, and it was not"],
       ["abstain", "var(--abstain)", "Said it could not tell"], ["false", "var(--signal)", "Said fixed, but it was not"]]
    : [["fixed", "var(--ok)", "Revoked access actually denied"], ["exposed", "var(--bad)", "Revoked access still open"]];
  $("#legend").innerHTML = items
    .map(([k, color, label]) => `<li><i style="background:${color}${k === "abstain" ? ";opacity:.55" : ""}"></i>${label} <b>${fmt(counts[k] || 0)}</b></li>`)
    .join("");
}

function select(b) {
  if (selected) selected.setAttribute("aria-selected", "false");
  selected = b;
  b.setAttribute("aria-selected", "true");
  const t = trials.find((x) => x.run === b.dataset.run);
  const said = { VERIFIED: "Fixed", "NOT VERIFIED": "Not fixed", INDETERMINATE: "Cannot tell" }[t.scope] || t.scope;
  const truth = t.oracle_denied ? "Fixed" : "Still exposed";
  const why = whyText(t);
  $("#replay").innerHTML = `
    <h3>${esc(ACTION_NAME[t.action])} on a ${esc(FAULT_NAME[t.fault].toLowerCase())}</h3>
    <p class="msg">${esc(CLASS_NAME[t.cls])} · configuration ${esc(t.cfg)} · trial ${esc(t.run)}</p>
    <div class="verdicts">
      <div class="verdict"><span>The verifier said</span><strong>${said}</strong></div>
      <div class="verdict"><span>The independent observer found</span><strong>${truth}</strong></div>
    </div>
    <dl>
      <dt>Faulty service</dt><dd>${esc(t.target)}${t.target === "enforcer-hidden" ? " (not reachable through the gateway in some setups)" : ""}</dd>
      <dt>Gateway reaches every service</dt><dd>${t.hidden_routed ? "Yes" : "No, one service is hidden from it"}</dd>
      <dt>Cache lifetime</dt><dd>${(t.ttl_ms / 1000).toFixed(1)} s${t.delay_ms ? `, event delayed ${(t.delay_ms / 1000).toFixed(1)} s` : ""}</dd>
      <dt>Load</dt><dd>${t.rps} requests per second</dd>
      <dt>Restart allowed by policy</dt><dd>${t.restart_ok ? "Yes" : "No (change freeze)"}</dd>
      <dt>Exposure seen at the gateway</dt><dd>${t.exp_lo.toFixed(2)}${t.exp_hi !== t.exp_lo ? `–${t.exp_hi.toFixed(2)}` : ""} s of ${t.window_s} s</dd>
      <dt>Legitimate requests failed</dt><dd>${t.failed} of ${t.observed}</dd>
    </dl>
    <p class="why">${why}</p>`;
}

function whyText(t) {
  if (t.scope === "INDETERMINATE") {
    if (t.action === "gateway_restrict") return "Blocking at the gateway produces denials from the gateway itself, which cannot show that the services behind it are fixed, so the verifier declines to call it.";
    if (!t.hidden_routed) return "The gateway's routing does not include every deployed service, so the verifier cannot see all of them and declines to call it.";
    return "The probes did not observe a denial from every service, so the verifier declines to call it.";
  }
  if (t.scope === "VERIFIED") return "Every deployed service was reached and each one denied the revoked request.";
  return "At least one revoked request was still allowed through the gateway.";
}

function wireToggle() {
  for (const b of document.querySelectorAll(".seg")) {
    b.addEventListener("click", () => {
      view = b.dataset.view;
      for (const o of document.querySelectorAll(".seg")) o.setAttribute("aria-pressed", String(o === b));
      paint();
    });
  }
}

/* ---------- actions table and costs ---------- */

function renderQ1(ev) {
  const rows = [];
  for (const [cls, label] of [["persistent", "Lasting faults (70 configurations)"], ["self_healing", "Self-healing faults (30 configurations)"]]) {
    rows.push(`<tr class="group"><td colspan="5">${label}</td></tr>`);
    for (const [id, name] of ACTIONS) {
      const s = ev.campaign.arms[cls][id];
      const share = s.configurations_remediated_in_majority_of_repeats / s.configurations;
      const w = Math.max(0, Math.round(share * 120));
      rows.push(`<tr><td>${name}</td>
        <td><span class="bar${w === 0 ? " zero" : ""}" style="width:${w || 3}px"></span>${s.configurations_remediated_in_majority_of_repeats} of ${s.configurations}</td>
        <td class="num">${s.remediated} of ${s.trials}</td>
        <td class="num">${s.exposure_seconds_upper_mean.toFixed(2)} s</td>
        <td class="num">${s.failed_requests_mean.toFixed(1)}</td></tr>`);
    }
  }
  $("#q1").innerHTML = `<thead><tr><th>Response</th><th>Configurations fixed</th><th class="num">Trials fixed</th>
    <th class="num">Gateway exposure (upper, mean)</th><th class="num">Failed legitimate requests (mean)</th></tr></thead><tbody>${rows.join("")}</tbody>`;
}

function renderCosts(ev) {
  const W = 360, H = 190, padL = 34, padB = 34, padT = 12;
  const out = [];
  for (const [cls, title] of [["persistent", "Lasting faults"], ["self_healing", "Self-healing faults"]]) {
    const arms = ev.campaign.arms[cls];
    const weights = ["1", "5", "20"];
    const maxV = Math.max(...ACTIONS.flatMap(([id]) => weights.map((w) => arms[id].mean_cost_by_missed_weight[w])));
    const y = (v) => H - padB - (v / maxV) * (H - padB - padT);
    const groupW = (W - padL) / ACTIONS.length;
    let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${title}: mean cost per trial for each response at missed-fix weights 1, 5 and 20">`;
    svg += `<line x1="${padL}" y1="${H - padB}" x2="${W}" y2="${H - padB}" stroke="var(--rule)"/>`;
    ACTIONS.forEach(([id, name], i) => {
      weights.forEach((w, j) => {
        const v = arms[id].mean_cost_by_missed_weight[w];
        const x = padL + i * groupW + 10 + j * ((groupW - 20) / 3);
        const bw = (groupW - 20) / 3 - 3;
        const best = ev.campaign.costs[cls].lowest[`1:${w}`].includes(id);
        svg += `<rect x="${x}" y="${y(v)}" width="${bw}" height="${H - padB - y(v)}" fill="${best ? "var(--ok)" : "var(--abstain)"}" opacity="${0.45 + j * 0.27}"><title>${name}, weight ${w}: ${v.toFixed(2)}${best ? " (lowest)" : ""}</title></rect>`;
      });
      svg += `<text class="axis" x="${padL + i * groupW + groupW / 2}" y="${H - padB + 16}" text-anchor="middle">${name}</text>`;
    });
    svg += `<text class="axis" x="0" y="${padT + 8}">${maxV.toFixed(0)}</text><text class="axis" x="0" y="${H - padB}">0</text></svg>`;
    const robust = ev.campaign.costs[cls].robust;
    const lowest = ev.campaign.costs[cls].lowest;
    const summary = robust
      ? `${ACTION_NAME[lowest["1:1"][0]]} is cheapest at every weight.`
      : `Cheapest at weight 1: ${lowest["1:1"].map((a) => ACTION_NAME[a]).join(" and ")}. At weights 5 and 20: ${lowest["1:5"].map((a) => ACTION_NAME[a]).join(" and ")}.`;
    out.push(`<figure><figcaption>${title}</figcaption>${svg}<p class="note">Bars left to right: a missed fix costs 1, 5 and 20 times an unnecessary action. Green marks the cheapest response. ${summary}</p></figure>`);
  }
  $("#costs").innerHTML = out.join("");
}

/* ---------- CVE ranker ---------- */

let cveMeta = null;
const cveYears = new Map();

async function loadYear(year) {
  if (!cveYears.has(year)) cveYears.set(year, getJSON(`data/cve-ranks-${year}.json`));
  return cveYears.get(year);
}

function rankCard(row) {
  const [cve, published, score, share, vendor, product, cvss, cwe] = row;
  const pos = Math.min(100, Math.max(0, share * 100));
  const band = share <= 0.01 ? "top 1%" : share <= 0.05 ? "top 5%" : share <= 0.10 ? "top 10%" : null;
  return `<div class="rank-card">
    <p class="msg">${esc(cve)} · published ${esc(published)}${vendor ? ` · ${esc(vendor)}${product ? ` ${esc(product)}` : ""}` : ""}</p>
    <div class="rank">Top ${share < 0.001 ? "0.1" : (share * 100).toFixed(share < 0.1 ? 1 : 0)}% of 2025 CVEs</div>
    <div class="rank-meter" aria-hidden="true"><div class="pin" style="left:calc(${pos}% - 1px)"></div></div>
    <div class="rank-scale"><span>Most likely exploited</span><span>Least likely</span></div>
    <p>${band ? `Within the ${band}. Under the default policy, an unfixable finding in the top 5% is quarantined after human approval.` : "Outside the top 10%. Under the default policy, it is monitored and re-checked."}
    Model score ${score.toFixed(4)}${cvss ? ` · CVSS ${cvss}` : ""}${cwe ? ` · ${esc(cwe)}` : ""}.</p>
  </div>`;
}

async function lookup(e) {
  e.preventDefault();
  const out = $("#cve-result");
  const id = $("#cve-input").value.trim().toUpperCase();
  const m = /^CVE-(\d{4})-\d{4,}$/.exec(id);
  if (!m) { out.innerHTML = `<p class="msg err">Enter an identifier like CVE-2026-12345.</p>`; return; }
  if (!cveMeta || !cveMeta.years[m[1]]) {
    out.innerHTML = `<p class="msg err">Ranks cover CVEs published from 2025 through the snapshot date. ${esc(id)} is outside that range.</p>`;
    return;
  }
  out.innerHTML = `<p class="msg">Looking up ${esc(id)}…</p>`;
  try {
    const rows = await loadYear(m[1]);
    let row = rows.find((r) => r[0] === id);
    if (!row) {
      for (const y of Object.keys(cveMeta.years)) { if (y !== m[1]) { row = (await loadYear(y)).find((r) => r[0] === id); if (row) break; } }
    }
    out.innerHTML = row ? rankCard(row) : `<p class="msg err">${esc(id)} is not in the snapshot. It may be unpublished, rejected or newer than the snapshot.</p>`;
  } catch (err) {
    out.innerHTML = `<p class="msg err">The rank file could not be loaded (${esc(err.message)}). Reload the page and try again.</p>`;
  }
}

async function renderTop() {
  const years = Object.keys(cveMeta.years).sort();
  const latest = years[years.length - 1];
  $("#top-title").textContent = `Highest-ranked CVEs published in ${latest}`;
  const rows = (await loadYear(latest)).slice().sort((a, b) => b[2] - a[2]).slice(0, 12);
  $("#top-cves").innerHTML = `<thead><tr><th>CVE</th><th>Published</th><th>Vendor and product</th><th class="num">Rank among 2025 CVEs</th></tr></thead><tbody>${
    rows.map((r) => `<tr><td><a href="https://www.cve.org/CVERecord?id=${esc(r[0])}">${esc(r[0])}</a></td><td>${esc(r[1])}</td><td>${esc(r[4])} ${esc(r[5])}</td><td class="num">${r[3] < 0.0001 ? "top 0.01%" : `top ${(r[3] * 100).toFixed(2)}%`}</td></tr>`).join("")
  }</tbody>`;
}

/* ---------- missed targets ---------- */

function renderMisses(ev) {
  const rows = ev.misses.map((m) => {
    const outcome = m.scenarios !== undefined
      ? `${m.detection} of ${m.scenarios} scenarios flagged; false alarms ${pct(m.false_alarm_rate)}`
      : `Detected ${pct(m.detection_rate, 2)} of attacks; false alarms ${pct(m.false_alarm_rate, 2)}`;
    return `<tr><td><a href="${esc(m.source)}">${esc(m.name)}</a></td><td>${esc(m.target)}</td><td>${outcome}</td></tr>`;
  });
  $("#miss-table").innerHTML = `<thead><tr><th>Test</th><th>Target set in advance</th><th>Outcome</th></tr></thead><tbody>${rows.join("")}</tbody>`;
}

/* ---------- boot ---------- */

async function boot() {
  wireToggle();
  $("#lookup").addEventListener("submit", lookup);
  try {
    const ev = await getJSON("data/evidence.json");
    renderQ1(ev);
    renderCosts(ev);
    renderMisses(ev);
  } catch (err) {
    $("#q1").outerHTML = `<p class="msg err">Results could not be loaded (${esc(err.message)}).</p>`;
  }
  try {
    const t = await getJSON("data/trials.json");
    trials = t.trials;
    buildGrid(trials);
  } catch (err) {
    $("#grid").outerHTML = `<p class="msg err">Trial records could not be loaded (${esc(err.message)}).</p>`;
  }
  try {
    cveMeta = await getJSON("data/cve-ranks-meta.json");
    await renderTop();
  } catch (err) {
    $("#top-cves").outerHTML = `<p class="msg err">CVE ranks could not be loaded (${esc(err.message)}).</p>`;
  }
}
boot();
