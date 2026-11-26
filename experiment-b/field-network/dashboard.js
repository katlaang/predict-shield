"use strict";
(function () {
  const el = (id) => document.getElementById(id);
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  let lastUpdated = 0;
  async function refresh() {
    try {
      const r = await fetch("/api/state", { cache:"no-store" });
      if (!r.ok) throw Error("HTTP " + r.status);
      const response = await r.json();
      const p = (response.panels || {}).field_network;
      if (!p || response.schema !== "predict-shield/live-state/1") throw Error("No current field-network panel");
      const tm = Date.parse(response.served_at);
      if (!Number.isFinite(tm) || Date.now() - tm > 10000) throw Error("Sensor feed is stale");
      lastUpdated = Date.now();
      el("status").textContent = "Live · MONITOR ONLY · Ground truth UNKNOWN";
      el("flows").textContent = fmt(p.flow_records);
      el("anomalies").textContent = fmt(p.anomalies);
      el("fraction").textContent = p.alert_fraction === null ? "–" : (p.alert_fraction * 100).toFixed(2) + "%";
      el("invalid").textContent = fmt(p.invalid_records);
      el("updated").textContent = response.served_at;
      el("site").textContent = p.site;
      el("freeze").textContent = (p.model_sha256 || "").slice(0,20) + "…";
    } catch (e) {
      el("status").textContent = "NO LIVE DATA: " + e.message;
    }
  }
  refresh();
  setInterval(refresh, 2000);
}());
