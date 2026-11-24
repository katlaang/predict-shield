"use strict";

// Where the "Request a pilot" button sends people. Set before deploying.
const CONTACT_URL = "";

const $ = (sel) => document.querySelector(sel);
const pct = (x, d = 1) => `${(100 * x).toFixed(d)}%`;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function getJSON(path) {
  const r = await fetch(path, { cache: "force-cache" });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

/* hero animation: four states on a loop; a click on a caption jumps to it */
function startDemo() {
  const svg = $("#netviz");
  const items = [...document.querySelectorAll("#viz-steps li")];
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let step = still ? 3 : 0;
  let timer = null;
  const show = (n) => {
    step = n;
    svg.dataset.step = String(n);
    items.forEach((li, i) => li.classList.toggle("on", i === n));
  };
  const loop = () => { timer = setTimeout(() => { show((step + 1) % 4); loop(); }, step === 1 ? 3200 : 2600); };
  show(step);
  if (!still) loop();
  items.forEach((li, i) => {
    li.tabIndex = 0;
    const go = () => { clearTimeout(timer); show(i); };
    li.addEventListener("click", go);
    li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  });
}

/* results table */
function renderResults(ev) {
  const c = ev.campaign;
  const ver = c.verifier.single_evidence;
  const exp = ev.exploit;
  const pd = ev.misses.find((m) => m.name.startsWith("Substation"));
  const v3 = ev.misses.find((m) => m.name.endsWith("v3"));
  const rows = [
    ["Verifying a fix", `${c.trials.toLocaleString("en-US")} sealed trials on a lab of independent services enforcing access revocation`,
      `Never reported a fix that hadn't happened (0 of ${(ver.TN + ver.abstain_truly_exposed).toLocaleString("en-US")} unfixed cases). Said "cannot confirm" in ${pct((ver.abstain_truly_denied + ver.abstain_truly_exposed) / ver.cases, 0)} of trials where it couldn't see every service.`,
      "ok", c.source],
    ["Choosing the response", "100 fault scenarios, four possible responses each, three repeats",
      "Restart was the only response that fixed lasting faults (70 of 70). For faults that clear on their own, waiting was the cheapest correct choice.",
      "ok", c.source],
    ["Ranking vulnerabilities", `Every CVE published in 2024 (${exp.cves.toLocaleString("en-US")}), scored once by a model trained on earlier years`,
      `Its top 5% held ${pct(exp.top.top_5pct.recall, 0)} of the vulnerabilities later confirmed as exploited.`, "ok", exp.source],
    ["Containing a route hijack", "Routed ISP lab with real routing software",
      "Detected the hijack, applied a filter after approval and verified traffic was restored. A too-broad filter was caught and rolled back.",
      "ok", "https://github.com/katlaang/predict-shield/blob/master/docs/evidence/ISP_BGP_HIJACK_LAB_2026_11_24.md"],
    ["Detecting attacks on substation traffic", "16 attack scenarios on power-grid (IEC 61850) messages",
      `Flagged ${pd.detection} of ${pd.scenarios} attacks, but false alarms were ${pct(pd.false_alarm_rate)} against a 1% target. Being reworked.`,
      "short", pd.source],
    ["Detecting attacks on a new network", "Trained on two lab networks, tested on a third",
      `Caught ${pct(v3.detection_rate, 2)} of attacks. Needs training data from the network it protects.`, "short", v3.source],
  ];
  $("#results").innerHTML = `<thead><tr><th>Capability</th><th>How it was tested</th><th>Result</th><th></th></tr></thead><tbody>${
    rows.map(([cap, how, res, kind, src]) => `<tr><td><b>${esc(cap)}</b></td><td>${esc(how)}</td><td>${esc(res)} <a href="${esc(src)}">Report</a></td><td><span class="tag ${kind}">${kind === "ok" ? "Met target" : "Fell short"}</span></td></tr>`).join("")
  }</tbody>`;
}

/* CVE ranker */
let cveMeta = null;
const years = new Map();
const loadYear = (y) => { if (!years.has(y)) years.set(y, getJSON(`data/cve-ranks-${y}.json`)); return years.get(y); };

function rankCard(row) {
  const [cve, published, , share, vendor, product, cvss, cwe] = row;
  const shown = share < 0.001 ? "0.1" : (share * 100).toFixed(share < 0.1 ? 1 : 0);
  const verdict = share <= 0.05 ? "High priority: in the top 5%. If it can't be fixed right away, PREDICT-SHIELD would propose containing it."
    : share <= 0.10 ? "Elevated: in the top 10%. Schedule the fix soon and keep watching it."
      : "Lower priority by this model. Keep it on the regular fix schedule.";
  return `<div class="rank-card">
    <p class="meta">${esc(cve)} · published ${esc(published)}${vendor ? ` · ${esc(vendor)}${product ? ` ${esc(product)}` : ""}` : ""}${cvss ? ` · CVSS ${esc(cvss)}` : ""}${cwe ? ` · ${esc(cwe)}` : ""}</p>
    <div class="rank">Top ${shown}% most likely to be exploited</div>
    <div class="meter" aria-hidden="true"><div class="pin" style="left:calc(${Math.min(100, share * 100)}% - 2px)"></div></div>
    <div class="scale"><span>Most likely</span><span>Least likely</span></div>
    <p>${verdict}</p>
  </div>`;
}

async function lookup(e) {
  e.preventDefault();
  const out = $("#cve-result");
  const id = $("#cve-input").value.trim().toUpperCase();
  const m = /^CVE-(\d{4})-\d{4,}$/.exec(id);
  if (!m) { out.innerHTML = `<p class="msg err">Enter an identifier like CVE-2025-1974.</p>`; return; }
  if (!cveMeta || !cveMeta.years[m[1]]) { out.innerHTML = `<p class="msg err">The lookup covers CVEs published from 2025 onward. Try a CVE from 2025 or 2026.</p>`; return; }
  out.innerHTML = `<p class="msg">Checking ${esc(id)}…</p>`;
  try {
    let row = (await loadYear(m[1])).find((r) => r[0] === id);
    if (!row) for (const y of Object.keys(cveMeta.years)) { if (y !== m[1]) { row = (await loadYear(y)).find((r) => r[0] === id); if (row) break; } }
    out.innerHTML = row ? rankCard(row) : `<p class="msg err">${esc(id)} isn't in the current snapshot. It may be newer, unpublished or rejected.</p>`;
  } catch (err) {
    out.innerHTML = `<p class="msg err">The ranking data didn't load. Reload the page and try again.</p>`;
  }
}

async function boot() {
  startDemo();
  const link = $("#contact-link");
  if (CONTACT_URL) link.href = CONTACT_URL;
  $("#lookup").addEventListener("submit", lookup);
  try { renderResults(await getJSON("data/evidence.json")); }
  catch { $("#results").outerHTML = `<p class="msg err">Results didn't load. Reload the page to try again.</p>`; }
  try { cveMeta = await getJSON("data/cve-ranks-meta.json"); } catch { cveMeta = null; }
}
boot();
