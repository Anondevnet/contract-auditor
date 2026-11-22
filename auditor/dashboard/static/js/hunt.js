
function renderDiskPressure(d) {
  const dp = (d && d.disk_pressure) || {};
  let box = document.getElementById("disk-pressure-banner");
  if (!box) {
    box = document.createElement("div");
    box.id = "disk-pressure-banner";
    box.className = "banner";
    const host = document.getElementById("hunt-summary") || document.getElementById("counters") || document.body;
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

/* Phase 20 — Hunt page (read-only). DOM-only; no innerHTML. */
const SORTS = ["priority", "tvl", "recent", "loss"];
const urlSort = new URLSearchParams(window.location.search).get("sort");
let sortMode = SORTS.includes(urlSort) ? urlSort : "priority";
let lastDetail = null;

function el(tag, attrs, kids) {
  const n = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") n.textContent = v;
    else if (k === "class") n.className = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v != null) n.setAttribute(k, v);
  }
  for (const c of kids || []) if (c) n.appendChild(c);
  return n;
}
function fmtUsd(v) {
  if (v == null || v === "" || Number.isNaN(Number(v))) return "—";
  const n = Number(v);
  if (Math.abs(n) >= 1e6) return "$" + (n / 1e6).toFixed(2) + "M";
  if (Math.abs(n) >= 1e3) return "$" + (n / 1e3).toFixed(1) + "k";
  return "$" + n.toFixed(0);
}
async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

const LIVE_STAGES = ["discover", "retrieve_source", "verify_deployment", "prioritize", "security_analysis", "fork_validation"];
function workerTime(seconds) {
  if (!seconds) return "—";
  return new Date(Number(seconds) * 1000).toLocaleTimeString("en-US", {
    timeZone: "America/Detroit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }) + " ET";
}
function setLiveText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}
function renderLiveDiscovery(d) {
  const metrics = d.metrics || {};
  const children = d.children || {};
  const monitor = children.monitor || {};
  const hunt = children.hunt || {};
  const candidates = metrics.candidates || {};
  const candidateTotal = Object.values(candidates).reduce((sum, n) => sum + Number(n || 0), 0);
  const ready = Number(candidates.new || 0) + Number(candidates.measured || 0) + Number(candidates.ready || 0);
  const scanned = Number(candidates.scanned || 0);
  const queue = metrics.queue || {};
  const lastHunt = metrics.last_hunt || {};
  const heartbeat = Math.max(Number(d.heartbeat_at || 0), Number(monitor.heartbeat_at || 0), Number(hunt.heartbeat_at || 0));
  const active = ["starting", "running", "degraded", "stopping"].includes(d.status);
  const main = document.getElementById("live-discovery-status");
  if (main) {
    const huntText = hunt.stage ? " · hunt: " + String(hunt.stage).replaceAll("_", " ") : "";
    const monitorText = monitor.stage ? " · monitor: " + String(monitor.stage).replaceAll("_", " ") : "";
    const stream = monitor.stream ? " · " + String(monitor.stream).replaceAll("_", " ") : "";
    const pressure = metrics.disk_pressure || {};
    const deferred = (metrics.disk_deferred || []).filter(Boolean);
    const diskText = pressure.heavy_paused ? " · heavy work paused: " + (pressure.last_reason || "disk pressure")
      : deferred.length ? " · deferred: " + deferred.join(", ") : "";
    main.textContent = String(d.status || "unknown").toUpperCase() + " · " + (d.message || "Worker status unavailable")
      + monitorText + huntText + stream + diskText;
    main.dataset.state = d.status || "unknown";
  }
  setLiveText("live-block", metrics.last_block_indexed == null ? "—" : Number(metrics.last_block_indexed).toLocaleString());
  setLiveText("live-lag", metrics.block_lag == null ? "—" : Number(metrics.block_lag).toLocaleString());
  const snapshot = metrics.read_snapshot || {};
  setLiveText("live-snapshot", snapshot.block == null ? "—" : Number(snapshot.block).toLocaleString() + " · " + (snapshot.finality || "numbered"));
  setLiveText("live-queue", Number(queue.pending || 0).toLocaleString());
  setLiveText("live-candidates", candidateTotal.toLocaleString() + " / " + ready.toLocaleString() + " / " + scanned.toLocaleString());
  setLiveText("live-exact", metrics.exact_source_matches == null ? "—" : Number(metrics.exact_source_matches).toLocaleString());
  setLiveText("live-last-hunt", lastHunt.at
    ? workerTime(lastHunt.at) + " · " + Number(lastHunt.discovered || 0) + " / "
      + Number(lastHunt.measured || 0) + " / " + Number(lastHunt.scanned || 0)
    : "No completed hunt yet");
  setLiveText("live-heartbeat", workerTime(heartbeat));
  const start = document.getElementById("live-discovery-start");
  const stop = document.getElementById("live-discovery-stop");
  if (start) start.disabled = active;
  if (stop) stop.disabled = !active || d.status === "stopping";

  if (active) {
    const stage = LIVE_STAGES.includes(hunt.stage) ? hunt.stage
      : LIVE_STAGES.includes(d.stage) ? d.stage
        : LIVE_STAGES.includes(monitor.stage) ? monitor.stage : "discover";
    if (typeof renderDiscoveryStage === "function") renderDiscoveryStage(stage);
  }
  const events = document.getElementById("live-discovery-events");
  if (events) {
    const recent = (d.events || []).slice(-12).reverse();
    events.replaceChildren();
    if (!recent.length) events.appendChild(el("li", { class: "muted", text: "No worker events recorded." }));
    for (const item of recent) {
      const when = workerTime(item.at);
      const component = item.component ? String(item.component).toUpperCase() + " · " : "";
      events.appendChild(el("li", { text: when + " · " + component + (item.message || item.stage || "Worker update") }));
    }
  }
}
async function liveDiscoveryTick() {
  try { renderLiveDiscovery(await api("/api/discovery/live")); }
  catch (e) { setLiveText("live-discovery-status", "STATUS UNAVAILABLE · " + e.message); }
}
async function controlLiveDiscovery(action) {
  const button = document.getElementById(action === "start" ? "live-discovery-start" : "live-discovery-stop");
  if (button) button.disabled = true;
  try {
    const response = await fetch("/api/discovery/live/" + action, {
      method: "POST", headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    renderLiveDiscovery(await response.json());
    window.setTimeout(liveDiscoveryTick, 400);
    window.dispatchEvent(new CustomEvent("hunt:refresh"));
  } catch (e) {
    setLiveText("live-discovery-status", "Could not " + action + " live discovery · " + e.message);
    if (button) button.disabled = false;
  }
}
document.getElementById("live-discovery-start")?.addEventListener("click", () => controlLiveDiscovery("start"));
document.getElementById("live-discovery-stop")?.addEventListener("click", () => controlLiveDiscovery("stop"));
liveDiscoveryTick();
setInterval(liveDiscoveryTick, 3000);
function shortAddr(a) { return a ? a.slice(0, 6) + "…" + a.slice(-4) : "—"; }

function renderCounters(c) {
  setText("h-total", c.total ?? "—");
  setText("h-ready", c.ready ?? "—");
  setText("h-scanned", c.scanned ?? "—");
  setText("h-source-unverified", (c.source_unverified ?? "—") + " · " + (c.source_retry_due ?? "—"));
  setText("h-review", c.simulation_review ?? "—");
  setText("h-var", fmtUsd(c.hunted_value_scanned_today_usd));
  setText("h-tvl", fmtUsd(c.hunted_tvl_scanned_today_usd));
  const hc = document.getElementById("h-confirmed");
  if (hc) setText("h-confirmed", fmtUsd(c.confirmed_outsider_usd ?? c.value_at_risk_found_usd ?? 0));
  const hu = document.getElementById("h-unresolved");
  if (hu) setText("h-unresolved", fmtUsd(c.unresolved_suspicion_usd ?? 0));
  const hd = document.getElementById("h-disproved");
  if (hd) setText("h-disproved", fmtUsd(c.disproved_excluded_usd ?? 0));
  const mechanismNames = {
    withdrawal_or_liquidity: "withdrawal/liquidity", bad_debt_or_solvency: "bad debt/solvency",
    oracle_or_market_loss: "oracle/market", accounting_or_share_value: "accounting/share value",
    privileged_control_risk: "privileged control", direct_asset_loss: "direct asset loss",
    other_or_unclassified: "other",
  };
  const mechanisms = Object.entries(c.potential_impact_counts || {}).filter(([, n]) => Number(n) > 0)
    .map(([k, n]) => (mechanismNames[k] || k) + " " + n);
  setText("h-impact-classes", mechanisms.join(" · ") || "No open findings");
  document.getElementById("hunt-priority-note").textContent = c.priority_label || "";
  document.getElementById("h-var-note").textContent = "rough estimate · " + (c.priority_label || "");
}

function showDetail(row) {
  lastDetail = row;
  const box = document.getElementById("hunt-detail");
  box.style.display = "";
  document.getElementById("hunt-detail-title").textContent =
    (row.protocol || "Candidate") + " · " + shortAddr(row.address);
  const meta = document.getElementById("hunt-detail-meta");
  meta.replaceChildren();
  const pairs = [
    ["Address", row.address], ["Category", (row.category_group || "") + " / " + (row.category || "")],
    ["Source", row.source], ["Contract", row.contract_name || "—"],
    ["Role", row.holder_role || "—"],
    ["Verified", row.verified ? ("yes (" + (row.source_provider || "?") + ")") : "no"],
    ["Deployment match", (row.discovery || {}).source_verification?.identity_note || "not verified yet"],
    ["Exact bytecode match", (row.discovery || {}).source_verification?.identity_status || "not established"],
    ["Sourcify match", (row.discovery || {}).source_verification?.sourcify_match || "—"],
    ["Compiler", (row.discovery || {}).source_verification?.compiler || "—"],
    ["Optimizer / runs", ((row.discovery || {}).source_verification?.optimizer || "—") + " / " + ((row.discovery || {}).source_verification?.optimizer_runs || "—")],
    ["Blue chip", row.blue_chip ? "demoted" : "no"],
    ["Audits (DefiLlama)", row.audits || "0"], ["Status", row.status],
    ["Value held", fmtUsd(row.holder_value_usd)],
    ["On-chain TVL", fmtUsd(row.onchain_tvl_usd)], ["Llama TVL", fmtUsd(row.llama_tvl_usd)],
    ["Proxy", row.is_proxy ? ((row.proxy_kind || "proxy") + " → " + (row.implementation || "?")) : "no"],
    ["Findings", row.findings == null ? "—" : String(row.findings)],
    ["Potential impact estimate · heuristic", fmtUsd(row.est_max_loss_usd)],
    ["Fork simulation", row.sim_status || "not run"],
    ["Simulation fork block", (row.sim_summary || {}).fork_block ?? "—"],
    ["Discovery feeds", (row.sources || []).join(", ") || row.source || "—"],
    ["C4 public findings match", (row.discovery || {}).code4rena?.public_findings ?? "—"],
    ["Arkham label", ((row.discovery || {}).arkham?.name || (row.discovery || {}).arkham?.entity || (row.discovery || {}).arkham?.arkhamEntity || "—")],
    ["Invariant fuzz", (row.discovery || {}).invariant_fuzz?.status || "not run"],
    ["Fuzz note", (row.discovery || {}).invariant_fuzz?.label || (row.discovery || {}).invariant_fuzz?.reason || "—"],
  ];
  for (const [k, v] of pairs) {
    meta.appendChild(el("div", { class: "meta-item" }, [
      el("div", { class: "label", text: k }), el("div", { class: "value mono", text: String(v) })
    ]));
  }
  const score = document.getElementById("hunt-detail-score");
  score.replaceChildren(el("h4", { text: "Priority score " + (row.priority_score ?? "—") }),
    el("p", { class: "muted", text: row.priority_label || "" }));
  const ul = el("ul", { class: "hunt-reasons" });
  for (const r of (row.score_reasons || [])) ul.appendChild(el("li", { text: r }));
  score.appendChild(ul);
  const sig = document.getElementById("hunt-detail-signals");
  sig.replaceChildren();
  const s = row.signals_json || {};
  const keys = Array.isArray(s.signals) ? s.signals : Object.keys(s).filter((k) => s[k] && k !== "oz_fraction" && k !== "known_fork" && k !== "files" && k !== "contract_name" && k !== "signals");
  if (keys.length || s.oz_fraction != null || s.known_fork) {
    sig.appendChild(el("h4", { text: "Complexity signals (heuristic)" }));
    const bits = keys.slice();
    if (s.oz_fraction != null) bits.push("oz_fraction=" + s.oz_fraction);
    if (s.known_fork) bits.push("known_fork");
    sig.appendChild(el("p", { text: bits.join(", ") || "none" }));
  }
  const repos = (row.discovery || {}).github_repositories || [];
  if (repos.length) {
    sig.appendChild(el("h4", { text: "Official repository references" }));
    for (const url of repos) {
      sig.appendChild(el("p", {}, [el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: url })]));
    }
  }
  const link = document.getElementById("hunt-scan-link");
  if (row.last_scan_row) {
    link.href = "/monitor?row=" + row.last_scan_row;
    link.style.display = "";
  } else {
    link.style.display = "none";
  }
}

function renderRows(rows) {
  const tb = document.getElementById("hunt-rows");
  tb.replaceChildren();
  if (!rows.length) {
    tb.appendChild(el("tr", { class: "empty-row" }, [
      el("td", { colspan: "13", text: "No hunt candidates yet. Run Ethereum discovery above." })]));
    return;
  }
  for (const r of rows) {
    const held = (r.holder_value_usd != null) ? r.holder_value_usd
      : ((r.onchain_tvl_usd != null && r.onchain_tvl_usd > 0) ? r.onchain_tvl_usd : null);
    const tvl = (r.onchain_tvl_usd != null && r.onchain_tvl_usd > 0) ? r.onchain_tvl_usd : r.llama_tvl_usd;
    let proxyTxt = "—";
    if (r.is_proxy && r.implementation) {
      proxyTxt = (r.proxy_kind || "proxy") + " → " + shortAddr(r.implementation);
    } else if (r.implementation) {
      proxyTxt = shortAddr(r.implementation);
    }
    const tr = el("tr", { class: r.blue_chip ? "hunt-bluechip" : "" });
    const open = () => showDetail(r);
    for (const cell of [
      el("td", null, [el("button", { class: "linkish", text: r.protocol || "—", onclick: open })]),
      el("td", { class: "mono", text: shortAddr(r.address), title: r.address }),
      el("td", { text: (r.holder_role ? r.holder_role + " · " : "") + (r.category_group || r.category || "—") }),
      el("td", { text: fmtUsd(held), title: "Live holdings at this address (rough estimate)" }),
      el("td", { text: fmtUsd(tvl) }),
      el("td", { class: "mono", text: proxyTxt, title: r.implementation || "" }),
      el("td", null, [el("span", { class: "badge hunt-score", text: String(r.priority_score ?? "—") })]),
      el("td", { text: r.status || "—" }),
      el("td", { text: r.sim_status || "—" }),
      el("td", {}, [(r.discovery || {}).invariant_fuzz?.status
        ? badge((r.discovery || {}).invariant_fuzz.status)
        : el("span", { class: "muted", text: "not run" })]),
      el("td", { text: r.findings == null ? "—" : String(r.findings) }),
      el("td", { text: fmtUsd(r.est_max_loss_usd), title: "Heuristic model estimate; not proven loss or takeable funds" }),
      el("td", null, [el("button", { class: "btn btn-secondary btn-sm", text: "Detail", onclick: open })]),
    ]) tr.appendChild(cell);
    tb.appendChild(tr);
  }
}

async function tick() {
  try {
    const d = await api("/api/hunt/live?sort=" + encodeURIComponent(sortMode) + "&top=50");
    renderDiskPressure(d);
    renderCounters(d.counters || {});
    renderRows(d.candidates || []);
    document.getElementById("hunt-updated").textContent =
      "Updated " + new Date((d.generated_at || 0) * 1000).toLocaleTimeString("en-US", { timeZone: "America/Detroit" }) + " ET";
    if (lastDetail) {
      const again = (d.candidates || []).find((x) => x.address === lastDetail.address);
      if (again) showDetail(again);
    }
  } catch (e) {
    document.getElementById("hunt-updated").textContent = "error: " + e.message;
  }
}

document.getElementById("hunt-sort").value = sortMode;
document.getElementById("hunt-sort").addEventListener("change", (e) => {
  sortMode = e.target.value; tick();
});
tick();
setInterval(tick, 5000);
window.addEventListener("hunt:refresh", tick);

async function renderProviders() {
  const grid = document.getElementById("provider-grid");
  if (!grid) return;
  try {
    const data = await api("/api/discovery/providers");
    grid.replaceChildren();
    for (const provider of (data.providers || [])) {
      const state = provider.state || "unknown";
      let detail = provider.detail || "";
      const recent = provider.last_run;
      if (recent && recent.state === "ready") {
        detail += " Last run: " + (recent.pairs ?? 0) + " pair(s)" +
          (recent.profiles != null ? " from " + recent.profiles + " token profiles." : ".");
      } else if (recent && recent.state === "error") {
        detail += " Last run reported an upstream error.";
      }
      grid.appendChild(el("div", { class: "provider-card" }, [
        el("div", { class: "provider-card-head" }, [
          el("strong", { text: provider.name }),
          el("span", { class: "provider-state " + state, text: state.replaceAll("_", " ") }),
        ]),
        el("p", { text: detail }),
      ]));
    }
    document.getElementById("provider-updated").textContent =
      "Updated " + new Date((data.generated_at || 0) * 1000).toLocaleTimeString("en-US", { timeZone: "America/Detroit" }) + " ET";
  } catch (e) {
    document.getElementById("provider-updated").textContent = "Provider status unavailable";
  }
}
renderProviders();
setInterval(renderProviders, 30000);


async function renderSim() {
  try {
    const d = await api("/api/simulate/live?limit=10");
    document.getElementById("sim-note").textContent = (d.note || d.label || "")
      + " · " + Number(d.review_required_count || 0) + " lead(s) need review"
      + " · " + Number(d.confirmed_exploitable_count || 0) + " confirmed exploitable";
    const box = document.getElementById("sim-runs");
    box.replaceChildren();
    for (const run of (d.runs || [])) {
      const head = el("div", { class: "sim-run" }, [
        el("strong", { text: (run.protocol || "") + " " + shortAddr(run.address) }),
        el("span", { class: "muted", text: " · " + (run.status || "") +
          (run.fork_block != null ? (" · fork block " + Number(run.fork_block).toLocaleString()) : "") +
          (run.holder_value_usd != null ? (" · holdings context " + fmtUsd(run.holder_value_usd)) : "") }),
      ]);
      box.appendChild(head);
      const ul = el("ul", { class: "hunt-reasons" });
      for (const inv of (run.invariants || [])) {
        ul.appendChild(el("li", {
          text: "[" + inv.status + "] " + inv.name + ": " + (inv.detail || "")
            + (inv.exposure_usd != null ? (" · potential exposure estimate " + fmtUsd(inv.exposure_usd)) : "")
            + (inv.guidance && inv.status === "fail" ? (" — fix: " + inv.guidance) : "")
        }));
      }
      const ora = run.oracles || {};
      if (ora.kinds) {
        ul.appendChild(el("li", { text: "oracles: " + (ora.kinds || []).join(",")
          + " flags=" + (ora.flags || []).join(",") }));
      }
      box.appendChild(ul);
    }
    if (!(d.runs || []).length) {
      box.appendChild(el("p", { class: "muted", text: "No simulation runs yet." }));
    }
    if ((d.review_queue || []).length) {
      box.appendChild(el("h4", { text: "Actionable review leads · not confirmed vulnerabilities" }));
      const leads = el("ul", { class: "hunt-reasons" });
      for (const lead of d.review_queue.slice(0, 12)) {
        leads.appendChild(el("li", { text: (lead.protocol || "") + " " + shortAddr(lead.address)
          + " · block " + (lead.fork_block ?? "unknown") + " · " + lead.status + " · " + lead.name
          + (lead.exposure_estimate_usd != null ? (" · exposure context " + fmtUsd(lead.exposure_estimate_usd)) : "")
          + " · " + (lead.detail || "") }));
      }
      box.appendChild(leads);
    }
  } catch (e) {
    document.getElementById("sim-note").textContent = "sim error: " + e.message;
  }
}
const _tick = tick;
tick = async function() { await _tick(); await renderSim(); };


async function loadStrategies() {
  const box = document.getElementById("hunt-strategies");
  if (!box) return;
  try {
    const r = await fetch("/api/hunt/strategies"); const d = await r.json();
    const fd = d.fork_diff == null ? "unknown" : d.fork_diff.length + " recent fork-diff(s)" +
      (d.fork_diff.length ? " — e.g. " + d.fork_diff[0].address + " (" + d.fork_diff[0].family + "): " +
        (!d.fork_diff[0].conclusive ? "inconclusive (no corpus reference)" :
          (d.fork_diff[0].changed.join(", ") || "no changed functions")) : "");
    const kx = d.known_exploit_findings == null ? "unknown" :
      (Object.entries(d.known_exploit_findings).map(([k, v]) => k + " " + v).join(", ") || "none");
    const methods = d.methods || {};
    const mline = Object.keys(methods).length
      ? Object.entries(methods).map(([k, v]) => k + "=" + ((v && v.status) || "unknown")).join(" · ")
      : "methods unknown";
    box.textContent = "Strategy stages — " + mline + " | fork-diff: " + fd +
      " · known-exploit matches: " + kx +
      " · disclosure packages: " + d.disclosures + " · confirmed exploitable: " +
      (d.confirmed_exploitable == null ? "unknown" : d.confirmed_exploitable);
  } catch (e) { box.textContent = "Strategy stages: unavailable (" + e + ")"; }
}
document.addEventListener("DOMContentLoaded", loadStrategies);
