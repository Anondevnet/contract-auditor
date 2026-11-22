
function renderDiskPressure(d) {
  const dp = (d && d.disk_pressure) || {};
  let box = document.getElementById("disk-pressure-banner");
  if (!box) {
    box = document.createElement("div");
    box.id = "disk-pressure-banner";
    box.className = "banner";
    const host = document.getElementById("monitor-summary") || document.getElementById("counters") || document.body;
    host.prepend(box);
  }
  const paused = dp.heavy_paused;
  const free = dp.last_free_gib != null ? Number(dp.last_free_gib).toFixed(2) : "?";
  const when = dp.last_check_at || "—";
  const reason = dp.last_reason || "";
  const streak = (dp.consecutive_ok != null ? dp.consecutive_ok : "?") + "/" + (dp.required_streak || 2);
  box.textContent = (paused ? "DISK: HEAVY PAUSED" : "DISK: HEAVY RUNNING")
    + " · free " + free + " GiB · streak " + streak
    + " · checked " + when + " · " + reason;
  box.style.background = paused ? "#5c3a00" : "#0a3d2a";
  box.style.color = "#fff";
  box.style.padding = "8px 12px";
  box.style.marginBottom = "8px";
  box.style.borderRadius = "6px";
  box.style.fontSize = "13px";
}

/* Live monitor page (Phase 18). All rendering goes through el()/textContent:
   contract-controlled strings (names, source, titles) are never parsed as HTML. */

setupChrome("monitor");

const POLL_MS = 2500;
let selectedRow = null;
const SORT_MODES = ["recent", "loss", "risk", "tvl"];
const urlSort = new URLSearchParams(window.location.search).get("sort");
let sortMode = SORT_MODES.includes(urlSort) ? urlSort : "recent";
let lastDetail = null;

function fmtUsd(v) {
  if (v === null || v === undefined) return "unknown";
  const n = Number(v);
  if (n >= 1e9) return "$" + (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6) return "$" + (n / 1e6).toFixed(2) + "M";
  if (n >= 1e4) return "$" + (n / 1e3).toFixed(1) + "k";
  return "$" + n.toFixed(n < 100 ? 2 : 0);
}

function fmtDur(s) {
  if (s === null || s === undefined) return "—";
  s = Number(s);
  if (s < 60) return s.toFixed(1) + " s";
  const m = Math.floor(s / 60);
  return m + "m " + Math.round(s % 60) + "s";
}

function fmtEpoch(t) {
  if (!t) return "—";
  return new Date(t * 1000).toLocaleString("en-US", { timeZone: "America/Detroit" });
}

function shortAddr(a) {
  return a ? a.slice(0, 8) + "…" + a.slice(-6) : "";
}

function addrLink(row) {
  if (!row.explorer_url) return el("span", { class: "mono", text: row.address });
  return el("a", { href: row.explorer_url, target: "_blank", rel: "noopener noreferrer",
                   class: "mono", text: shortAddr(row.address) });
}

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

function sevChips(counts) {
  const wrap = el("span", { class: "mon-chips" });
  for (const s of SEVS) {
    if (counts && counts[s]) wrap.appendChild(el("span", { class: "badge " + s, text: s.slice(0, 4) + " " + counts[s] }));
  }
  return wrap;
}

function renderCounters(d) {
  const c = d.counters;
  setText("c-today", c.audited_today);
  setText("c-all", c.audited_all_time);
  setText("c-ftoday", c.findings_today_total);
  setText("c-fall", c.findings_all_time);
  setText("c-queue", c.queue_pending + " / " + c.unverified);
  setText("c-block", c.last_block === null ? "—" : c.last_block.toLocaleString());
  setText("c-polls", c.polls_last_hour);
  setText("c-avg", fmtDur(c.avg_scan_s));
  setText("c-tz", d.timezone);
  setText("c-cna", (c.could_not_analyze_today ?? 0) + " / " + (c.could_not_analyze_all_time ?? 0));
  setText("c-var", "~" + fmtUsd(c.confirmed_outsider_today_usd ?? c.value_at_risk_found_today_usd ?? 0));
  setText("c-unverified", "~" + fmtUsd(c.unverified_exposure_today_usd ?? 0));
  const unr = document.getElementById("c-unresolved");
  if (unr) setText("c-unresolved", "~" + fmtUsd(c.unresolved_suspicion_today_usd ?? 0));
  const dis = document.getElementById("c-disproved");
  if (dis) setText("c-disproved", "~" + fmtUsd(c.disproved_excluded_today_usd ?? 0));
  const hol = document.getElementById("c-holdings");
  if (hol) setText("c-holdings", c.holdings_unknown && !(c.holdings_all_time_usd > 0)
    ? "unknown" : "~" + fmtUsd(c.holdings_all_time_usd ?? 0));
  setText("c-var-note", "confirmed outsider only · TVL w/ findings " + fmtUsd(c.tvl_with_findings_today_usd ?? 0) +
          (c.price_as_of ? " · prices as of " + fmtEpoch(c.price_as_of) : " · prices unavailable"));
  setText("c-supp", (c.suppressed_today ?? 0) + " / " + (c.suppressed_all_time ?? 0));
  setText("c-legacy", c.legacy_needs_rescan ? c.legacy_needs_rescan + " legacy row(s) need re-scan (audit.py monitor-rescan)" : "");
  const sev = document.getElementById("c-fsev");
  clearChildren(sev);
  sev.appendChild(sevChips(c.findings_today));
}

const STAGES = ["fetching", "compiling", "analyzing", "done"];

function renderCurrent(list) {
  const box = document.getElementById("mon-current");
  clearChildren(box);
  if (!list.length) {
    box.appendChild(el("p", { class: "muted", text: "Idle — no contract is being scanned." }));
    return;
  }
  for (const r of list) {
    const steps = el("div", { class: "mon-steps" });
    const idx = STAGES.indexOf(r.stage);
    STAGES.forEach((s, i) => steps.appendChild(
      el("span", { class: "mon-step" + (i < idx ? " done" : i === idx ? " active" : ""), text: s })));
    const eta = r.eta || {};
    const etaText = eta.estimated_remaining_s === null || eta.estimated_remaining_s === undefined
      ? "no estimate yet (no completed scans)"
      : (eta.overrun ? "past estimate (est. total " + fmtDur(eta.estimated_total_s) + ")"
                     : "~" + fmtDur(eta.estimated_remaining_s) + " remaining") +
        " · estimate from " + eta.basis_scans + " past scans";
    box.appendChild(el("div", { class: "mon-now" }, [
      el("div", { class: "mon-now-head" }, [
        el("strong", { text: r.contract_name || "(name pending)" }),
        el("span", { text: "  " }),
        addrLink(r),
      ]),
      el("div", { class: "meta-grid" }, [
        meta("Compiler", r.compiler || "—"),
        meta("Source", (r.file_count ?? "—") + " files · " + (r.line_count ?? "—") + " lines"),
        meta("Elapsed", fmtDur(r.elapsed_s)),
        meta("ESTIMATED remaining", etaText),
      ]),
      steps,
    ]));
  }
}

function meta(label, value) {
  return el("div", { class: "storage-item" }, [
    el("span", { class: "label", text: label }), el("span", { class: "value", text: String(value) })]);
}

function renderScans(rows) {
  const body = document.getElementById("mon-scans");
  clearChildren(body);
  if (!rows.length) {
    body.appendChild(el("tr", { class: "empty-row" }, [el("td", { colspan: "10", text: "No monitor scans yet." })]));
    return;
  }
  for (const r of rows) {
    const btn = el("button", { class: "btn btn-link btn-sm", text: "Details" });
    btn.addEventListener("click", () => loadDetail(r.id));
    body.appendChild(el("tr", {}, [
      el("td", { text: r.contract_name || "—" }),
      el("td", {}, [addrLink(r)]),
      el("td", {}, [badge(r.status === "incomplete" ? "could not analyze" : r.status, r.status),
                    r.error && r.status !== "done" ? el("div", { class: "muted mon-reason", text: r.error.slice(0, 160) }) : el("span"),
                    r.status === "done" && r.analysis_complete === null ? el("div", { class: "muted mon-reason", text: "legacy: completion unverified" }) : el("span")]),
      el("td", {}, [el("span", { class: "mono", text: String(r.findings ?? "—") + " " }), sevChips(r.severity_counts),
                    r.suppressed_count ? el("div", { class: "muted mon-reason", text: r.suppressed_count + " suppressed" }) : el("span")]),
      el("td", { class: "mono", text: r.tvl_usd === null || r.tvl_usd === undefined ? "—" : fmtUsd(r.tvl_usd) }),
      el("td", {}, [el("span", { class: "mono mon-loss", text: r.est_max_loss_usd === null || r.est_max_loss_usd === undefined ? "—" : "~" + fmtUsd(r.est_max_loss_usd), title: "Heuristic estimate of potential impact; not proven loss or takeable funds" }),
                    r.user_funds_at_risk ? el("div", { class: "badge scam", text: "user funds at risk" }) : el("span")]),
      el("td", { class: "mono", text: String(r.line_count ?? "—") }),
      el("td", { class: "mono", text: fmtDur(r.duration_s) }),
      el("td", { text: fmtEpoch(r.finished_at) }),
      el("td", {}, [btn]),
    ]));
  }
}

function renderAlerts(d) {
  const box = document.getElementById("mon-alerts");
  clearChildren(box);
  setText("mon-alerts-total", d.alerts_total + " total");
  if (!d.recent_alerts.length) {
    box.appendChild(el("p", { class: "muted", text: "No alerts." }));
    return;
  }
  for (const a of d.recent_alerts) {
    box.appendChild(el("div", { class: "mon-alert" + (a.triage ? " suppressed" : "") }, [
      badge(a.severity),
      el("span", { class: "mon-alert-title", text: " " + (a.title || "") }),
      el("div", { class: "muted mono", text: shortAddr(a.address) + " · block " + a.block + " · " + fmtTime(a.ts) }),
      a.triage ? el("div", { class: "mon-triage" }, [
        el("span", { class: "badge triage", text: (a.triage.verdict === "disproved" ? "Tested path disproved under current state" : "False positive") +
          " — not active exposure" }),
        el("span", { class: "muted", text: " " + (a.triage.reason || "") + (a.triage.detail ? " — " + a.triage.detail : "") })]) : el("span"),
    ]));
  }
}

function riskSection(risk) {
  const pre = el("pre", { class: "mon-code mon-fix" });
  pre.textContent = risk.fix_pattern;
  return el("div", { class: "mon-risk" }, [
    el("h4", { text: "Risk & remediation — " + risk.label }),
    el("p", { class: "muted", text: "Heuristic: " + risk.heuristic_note }),
    el("div", { class: "meta-grid" }, [
      meta("Exploitability (heuristic)", risk.exploitability),
      meta("Time-to-exploit band (heuristic)", risk.time_to_exploit),
      meta("Time-to-fix band (heuristic)", risk.time_to_fix),
    ]),
    el("p", { text: "Attack class: " + risk.attack_class }),
    el("p", { text: "Remediation: " + risk.remediation }),
    pre,
  ]);
}

function estimateBlock(f) {
  const e = f.estimate;
  if (!e) return el("span");
  const band = "band " + fmtUsd(e.est_loss_low_usd) + " – " + fmtUsd(e.est_loss_high_usd);
  const parts = [
    el("strong", { text: "Potential impact estimate (heuristic): " + (e.est_loss_usd === null ? "unknown" : "~" + fmtUsd(e.est_loss_usd)) }),
    el("span", { class: "muted", text: "  " + band + " · exposure factor " + e.exposure_factor + " (" + e.model + ")" }),
  ];
  if (e.user_funds_at_risk) parts.push(el("div", { class: "mon-reason", text: "User funds at risk — bait balance " + fmtUsd(e.bait_balance_usd) }));
  if (e.owner_rug_exposure_usd !== null && e.owner_rug_exposure_usd !== undefined)
    parts.push(el("div", { class: "mon-reason", text: "Owner-rug exposure (privileged account could withdraw): " + fmtUsd(e.owner_rug_exposure_usd) }));
  const ul = el("ul", { class: "mon-evidence" });
  (e.assumptions || []).forEach((a) => ul.appendChild(el("li", { text: a })));
  parts.push(el("div", { class: "label", text: "Assumptions" }), ul);
  return el("div", { class: "mon-estimate" }, parts);
}

function triageBadge(f) {
  if (!f.triage) return el("span");
  const t = f.triage;
  const txt = f.suppressed ? (t.rule === "live-state-disproof" ? "Tested path disproved under current state: " + (t.detail || "")
    : "False positive: " + (f.dismissal_reason || t.reason)) : (t.action === "downgraded" || t.reason === "privileged-withdraw" || t.reason === "privileged-module-caller"
    ? "downgraded " + (t.original_severity || "") + "→INFORMATIONAL: " + t.reason : t.reason);
  return el("div", { class: "mon-triage" }, [el("span", { class: "badge triage", text: txt }),
    el("span", { class: "muted", text: " " + (t.rule || "") + (t.detail ? " — " + t.detail : "") })]);
}

function renderFinding(f) {
  const loc = f.location || {};
  const where = [loc.file, [loc.contract, loc.function].filter(Boolean).join("."),
                 loc.lines && loc.lines.length ? "L" + loc.lines.join(",") : ""].filter(Boolean).join(" · ");
  const ev = el("ul", { class: "mon-evidence" });
  for (const e of f.evidence || []) {
    ev.appendChild(el("li", { text: "[" + e.epistemic + "] " + e.source + "/" + e.artifact_type + ": " + (e.excerpt || "").slice(0, 300) }));
  }
  const exp = !!(f.confirmed_exploitable);
  const badges = [badge(f.severity), el("span", { text: " " }), badge(f.confidence)];
  if (exp) {
    badges.push(el("span", { text: " " }));
    badges.push(badge("EXPLOITABLE_REAL_MONEY", "exploitable-real-money"));
  }
  badges.push(el("strong", { text: " " + (f.title || "") }));
  return el("div", { class: "mon-finding" + (f.suppressed ? " suppressed" : "") + (exp ? " exploitable-row" : "") }, [
    el("div", {}, badges),
    el("div", { class: "muted", text: "Type: " + f.risk.label + (f.risk.detector ? " (" + f.risk.detector + ")" : "") + " · Location: " + (where || "—") }),
    el("div", { class: "muted", text: "Potential harm class: " + (f.impact_class || "unclassified")
      + " · evidence status: " + (f.impact_status || (exp ? "confirmed_exploitable" : "unresolved")) }),
    triageBadge(f),
    el("p", { text: f.description || "" }),
    estimateBlock(f),
    el("div", { class: "label", text: "Evidence" }), ev,
    panelBlock(f),
    riskSection(f.risk),
  ]);
}

const PANEL_LABELS = { ai_majority_suspected: "AI-majority suspected (needs fork reproduction)",
  ai_majority_likely_fp: "AI-majority likely false positive", inconclusive: "AI panel inconclusive" };

function panelBlock(f) {
  const box = el("div", { class: "mon-panel" });
  if (f.id == null) return box;
  api("/api/review-panel/finding/" + f.id).then((p) => {
    if (!p.reviewed) { box.appendChild(el("div", { class: "muted", text: "AI review panel: not reviewed" })); return; }
    const s = p.summary || {};
    box.appendChild(el("div", { class: "label", text: "AI review panel — " + (PANEL_LABELS[p.label] || p.label) +
      " (" + s.yes + " yes / " + s.no + " no / " + s.inconclusive + " inconclusive / " + s.failed + " failed; " + p.epistemic + ")" }));
    const ul = el("ul", { class: "mon-evidence" });
    for (const v of p.votes || []) {
      ul.appendChild(el("li", { text: v.role + " [" + v.model + ", " + v.prompt_version + ", " + v.created_at + "]: " +
        (v.verdict || ("FAILED: " + (v.error || "?"))) + (v.confidence != null ? " (conf " + v.confidence + ")" : "") +
        (v.loss_path ? " — " + v.loss_path.slice(0, 300) : "") }));
    }
    box.appendChild(ul);
  }).catch(() => box.appendChild(el("div", { class: "muted", text: "AI review panel: unavailable" })));
  return box;
}

async function loadDetail(rowId) {
  selectedRow = rowId;
  const d = await api("/api/monitor/scans/" + encodeURIComponent(rowId));
  document.getElementById("mon-detail").style.display = "";
  setText("mon-detail-title", (d.contract_name || "Contract") + " — " + d.address);
  document.getElementById("mon-source-link").href = "/monitor/source/" + rowId;
  const m = document.getElementById("mon-detail-meta");
  clearChildren(m);
  m.appendChild(meta("Compiler", d.compiler || "—"));
  m.appendChild(meta("Files / lines", (d.file_count ?? "—") + " / " + (d.line_count ?? "—")));
  m.appendChild(meta("Duration", fmtDur(d.duration_s)));
  m.appendChild(meta("Stages", (d.stages || []).map((s) => s.stage).join(" → ")));
  m.appendChild(meta("solc used", d.solc_version || "—"));
  const verdict = d.analysis_complete === 1 ? "COMPLETE"
    : d.analysis_complete === 0 ? "INCOMPLETE — could not analyze: " + (d.error || "unknown reason")
    : (d.status === "done" ? "UNVERIFIED (legacy row, re-scan needed)" : (d.error || d.status));
  m.appendChild(meta("Analysis", verdict));
  lastDetail = d;
  renderValue(d);
  renderDetailFindings();
  await loadSource(rowId, "");
}

function renderValue(d) {
  const box = document.getElementById("mon-detail-value");
  clearChildren(box);
  const v = d.value;
  if (!v || !v.value) {
    box.appendChild(el("p", { class: "muted", text: "Value at risk: not estimated for this scan." }));
    return;
  }
  const c = v.value, sm = v.summary || {};
  const tbl = el("table", { class: "data-table mon-holdings" });
  tbl.appendChild(el("thead", {}, [el("tr", {}, [el("th", { text: "Asset" }), el("th", { text: "Amount" }), el("th", { text: "USD (est.)" })])]));
  const tb = el("tbody");
  (c.holdings || []).forEach((h) => tb.appendChild(el("tr", {}, [
    el("td", { text: h.symbol }), el("td", { class: "mono", text: h.amount === null ? "unknown" : String(Number(h.amount).toLocaleString()) }),
    el("td", { class: "mono", text: fmtUsd(h.usd) })])));
  tbl.appendChild(tb);
  box.appendChild(el("div", { class: "mon-value" }, [
    el("h4", { text: "Holdings and potential impact estimates" }),
    el("div", { class: "meta-grid" }, [
      meta("Contract TVL (est.)", fmtUsd(sm.tvl_usd)),
      meta("Potential impact estimate (heuristic)", sm.est_max_loss_usd === null ? "unknown" : "~" + fmtUsd(sm.est_max_loss_usd)
           + " (band " + fmtUsd(sm.est_max_loss_low_usd) + " – " + fmtUsd(sm.est_max_loss_high_usd) + ")"),
      meta("Prices as of", c.price_as_of ? fmtEpoch(c.price_as_of) + " ET" + (c.price_stale ? " (stale cache)" : "") : "unavailable"),
      meta("Proxy", c.is_proxy ? "yes — proxy's own balance used" : "no"),
    ]),
    tbl,
    el("p", { class: "muted", text: "Holdings and modeled impact are estimates, not proven loss or funds an attacker can take. The model ignores funds in other contracts, future deposits and price impact. " + (c.notes || []).join(" · ") }),
  ]));
}

function renderDetailFindings() {
  const d = lastDetail;
  if (!d) return;
  const show = document.getElementById("mon-show-suppressed").checked;
  const n = d.suppressed_detail_count || 0;
  setText("mon-suppressed-count", n ? n + " suppressed finding(s) hidden by default" : "no suppressed findings");
  const fs = document.getElementById("mon-detail-findings");
  clearChildren(fs);
  const list = d.findings_detail.filter((f) => show || !f.suppressed);
  if (!list.length) fs.appendChild(el("p", { class: "muted", text: "No validated findings for this scan." }));
  list.forEach((f) => fs.appendChild(renderFinding(f)));
}

async function loadSource(rowId, file) {
  const v = await api("/api/monitor/source/" + encodeURIComponent(rowId) + (file ? "?file=" + encodeURIComponent(file) : ""));
  const wrap = document.getElementById("mon-source");
  const sel = document.getElementById("mon-source-file");
  clearChildren(sel);
  if (!v.files.length) { wrap.style.display = "none"; return; }
  v.files.forEach((f) => { const o = el("option", { value: f, text: f }); if (f === v.file) o.selected = true; sel.appendChild(o); });
  sel.onchange = () => loadSource(rowId, sel.value);
  document.getElementById("mon-source-code").textContent = v.content;  // escaped by textContent
  wrap.style.display = "";
}

async function tick() {
  try {
    const d = await api("/api/monitor/live?sort=" + encodeURIComponent(sortMode));
    renderDiskPressure(d);
    renderCounters(d);
    renderCurrent(d.current);
    renderScans(d.recent_scans);
    renderAlerts(d);
    setText("mon-updated", "Updated " + new Date().toLocaleTimeString("en-US", { timeZone: "America/Detroit" }) + " ET");
  } catch (err) {
    setText("mon-updated", "Update failed: " + err.message);
  }
}

document.getElementById("mon-sort").value = sortMode;
document.getElementById("mon-sort").addEventListener("change", (e) => { sortMode = e.target.value; tick(); });
document.getElementById("mon-show-suppressed").addEventListener("change", renderDetailFindings);
tick();
setInterval(tick, POLL_MS);
const deepRow = new URLSearchParams(window.location.search).get("row");
if (deepRow && /^\d+$/.test(deepRow)) loadDetail(deepRow).catch(() => {});


async function loadPanelSummary() {
  const box = document.getElementById("mon-panel-summary");
  if (!box) return;
  try {
    const s = await api("/api/review-panel/summary");
    if (!s.available) { box.textContent = "AI review panel: has not run yet"; return; }
    const lab = Object.entries(s.labels || {}).map(([k, v]) => (PANEL_LABELS[k] || k) + ": " + v).join(" · ") || "no outcomes";
    const q = Object.entries(s.queue || {}).map(([k, v]) => k + " " + v).join(", ") || "empty";
    box.textContent = "AI review panel — " + lab + " · queue: " + q + " · votes: " + s.votes +
      (s.avg_seconds_per_vote != null ? " · avg " + s.avg_seconds_per_vote + " s/vote" : "");
  } catch (e) { box.textContent = "AI review panel: unavailable (" + e + ")"; }
}
document.addEventListener("DOMContentLoaded", loadPanelSummary);
