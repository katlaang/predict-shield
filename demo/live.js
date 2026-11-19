// Read-only client for the PREDICT-SHIELD live feed (/api/state).
// Every value is rendered with textContent, never as HTML.
(function () {
  "use strict";
  var POLL_MS = 2000;
  var STALE_MS = 6000;
  var lastServedAt = null;
  var lastAdvance = 0;

  function el(id) { return document.getElementById(id); }
  function text(id, value) { el(id).textContent = value; }

  function cell(row, value, cls) {
    var td = document.createElement("td");
    td.textContent = value === null || value === undefined || value === "" ? "-" : String(value);
    if (cls) { td.className = cls; }
    row.appendChild(td);
  }

  function outcomeClass(status) {
    if (status === "APPLIED_VERIFIED") { return "ok"; }
    if (status === "ROLLED_BACK" || status === "REFUSED") { return "warn"; }
    if (status === "ROLLBACK_FAILED" || status === "ACTIVATION_FAILED_RESTORED") { return "bad"; }
    return "";
  }

  function setFeed(live, message) {
    var pill = el("feed");
    pill.textContent = live ? "LIVE" : "NO LIVE DATA";
    pill.className = "pill " + (live ? "live" : "down");
    el("stale").style.display = live ? "none" : "block";
    if (!live) { el("stale").textContent = message; }
  }

  function render(state) {
    var incidents = state.incidents || [];
    var panels = state.panels || {};
    text("m-incidents", incidents.length);
    text("m-kept", incidents.filter(function (i) { return i.final_status === "APPLIED_VERIFIED"; }).length);
    text("m-rolled", incidents.filter(function (i) { return i.final_status === "ROLLED_BACK"; }).length);
    var intake = panels.intake || {admitted: [], rejected: 0};
    text("m-detections", (intake.admitted || []).length);

    var body = el("incidents");
    body.textContent = "";
    incidents.forEach(function (i) {
      var row = document.createElement("tr");
      cell(row, i.case_id);
      cell(row, i.stage);
      cell(row, i.channel);
      cell(row, i.seconds_from_tamper_to_detection === undefined ? null : i.seconds_from_tamper_to_detection + " s");
      cell(row, i.applied_action || i.proposed_action);
      cell(row, i.authority);
      cell(row, i.verification);
      cell(row, i.widget_working === undefined || i.widget_working === null ? null : (i.widget_working ? "working" : "disabled"),
           i.widget_working === false ? "warn" : "");
      cell(row, i.final_status, outcomeClass(i.final_status));
      row.setAttribute("data-case", i.case_id);
      body.appendChild(row);
    });

    text("intake", (intake.admitted || []).length + " admitted, " + (intake.rejected || 0) +
         " rejected. Only signed or mutually authenticated detections are admitted.");
    var det = el("detections");
    det.textContent = "";
    (intake.admitted || []).slice(-20).reverse().forEach(function (d) {
      var row = document.createElement("tr");
      cell(row, d.at); cell(row, d.source); cell(row, d.authentication); cell(row, d.assertion);
      det.appendChild(row);
    });

    var audit = panels.audit || {records: [], chain_intact: null};
    text("audit", (audit.records || []).length + " records. Hash chain " +
         (audit.chain_intact === true ? "intact." : audit.chain_intact === false ? "BROKEN." : "not yet checked."));
    var rows = el("audit-rows");
    rows.textContent = "";
    (audit.records || []).slice(-25).reverse().forEach(function (r) {
      var row = document.createElement("tr");
      cell(row, r.sequence); cell(row, r.case_id); cell(row, r.status, outcomeClass(r.status));
      cell(row, r.target_id); cell(row, (r.record_sha256 || "").slice(0, 16));
      rows.appendChild(row);
    });
    text("served-at", state.served_at);
    text("sequence", state.sequence);
  }

  function poll() {
    fetch("/api/state", {cache: "no-store"}).then(function (response) {
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      return response.json();
    }).then(function (state) {
      if (state.schema !== "predict-shield/live-state/1") { throw new Error("unexpected schema"); }
      if (state.served_at !== lastServedAt) { lastServedAt = state.served_at; lastAdvance = Date.now(); }
      render(state);
      setFeed(Date.now() - lastAdvance < STALE_MS, "The feed's timestamp has stopped advancing.");
    }).catch(function (error) {
      setFeed(false, "The live feed could not be reached (" + error.message + "). Values shown are not current.");
    });
  }

  poll();
  setInterval(poll, POLL_MS);
}());
