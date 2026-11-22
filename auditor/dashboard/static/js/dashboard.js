
/* ---- EXPLOITABLE_REAL_MONEY banner (every page) ---- */

async function loadExploitableBanner() {
  const banner = document.getElementById("exploitable-banner");
  const list = document.getElementById("exploitable-banner-list");
  if (!banner || !list) return;
  try {
    const data = await api("/api/exploitable");
    clearChildren(list);
    const items = (data && data.items) || [];
    if (!data || !data.visible || !items.length) {
      banner.hidden = true;
      return;
    }
    banner.hidden = false;
    items.forEach((it) => {
      const take =
        it.takeable_usd != null
          ? "$" + Number(it.takeable_usd).toLocaleString(undefined, { maximumFractionDigits: 0 })
          : "?";
      const when = it.verified_at ? fmtTime(it.verified_at) : "—";
      const label =
        (it.contract_name || "?") +
        " " +
        (it.short_address || it.address || "") +
        " — " +
        take +
        " — " +
        (it.finding_type || "?") +
        " — confirmed " +
        when;
      const a = el("a", { href: it.href || "/monitor", text: label });
      list.appendChild(el("li", {}, [a]));
    });
  } catch (e) {
    banner.hidden = true;
  }
}

/* Shared dashboard helpers + overview page. */

async function api(path, options) {
  const res = await fetch(path, options);
  let data = null;
  try {
    data = await res.json();
  } catch (e) {
    data = null;
  }
  if (!res.ok) {
    const detail =
      data && data.detail
        ? typeof data.detail === "string"
          ? data.detail
          : (data.detail.message
              ? data.detail.message + (data.detail.code ? " [" + data.detail.code + "]" : "")
              : JSON.stringify(data.detail))
        : res.statusText;
    throw new Error(`${res.status}: ${detail}`);
  }
  return data;
}

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v;
      else node.setAttribute(k, v);
    }
  }
  (children || []).forEach((c) => node.appendChild(c));
  return node;
}

function badge(text, extraClass) {
  const cls = (text || "UNKNOWN") + (extraClass ? " " + extraClass : "");
  return el("span", { class: "badge " + cls, text: text || "UNKNOWN" });
}

function shortId(id) {
  return id ? String(id).slice(0, 8) : "";
}

function fmtTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    // API timestamps carry an explicit offset; render in the user's zone.
    return isNaN(d) ? iso : d.toLocaleString("en-US", { timeZone: "America/Detroit" }) + " ET";
  } catch (e) {
    return iso;
  }
}

function clearChildren(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/* ---- page chrome ---- */

function setupChrome(activePage) {
  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }
  document.querySelectorAll(".nav-item").forEach((item) => {
    if (item.dataset.page === activePage) item.classList.add("active");
    item.addEventListener("click", () => sidebar && sidebar.classList.remove("open"));
  });

  const refresh = document.getElementById("refresh-btn");
  if (refresh) refresh.addEventListener("click", () => window.location.reload());

  loadExploitableBanner();
  startDashboardPulse();
  setupDiscoveryControls();

  // Health probe for the sidebar status light.
  fetch("/health")
    .then((r) => r.json())
    .then((d) => {
      const status = document.getElementById("health-status");
      if (!status) return;
      if (d.status === "healthy") {
        status.classList.remove("down");
        status.lastElementChild.textContent = "Healthy";
      } else {
        throw new Error("unhealthy");
      }
    })
    .catch(() => {
      const status = document.getElementById("health-status");
      if (!status) return;
      status.classList.add("down");
      status.lastElementChild.textContent = "Unreachable";
    });
}

const DISCOVERY_STAGES = ["discover", "retrieve_source", "verify_deployment", "prioritize", "security_analysis"];
const DISCOVERY_STAGE_LABELS = ["Discover deployments", "Retrieve verified source", "Verify deployed code", "Prioritize by exposure", "Run security analysis"];
function renderDiscoveryStage(stage) {
  const current = DISCOVERY_STAGES.indexOf(stage);
  document.querySelectorAll(".pipeline-node[data-stage], .audit-stage-node[data-stage]").forEach((node) => {
    const i = DISCOVERY_STAGES.indexOf(node.dataset.stage);
    node.classList.toggle("done", stage === "complete" || (current >= 0 && i < current));
    node.classList.toggle("active", current >= 0 && i === current);
    node.classList.toggle("failed", stage === "failed");
  });
}

function paintDiscoverySignal(state) {
  const panel = document.getElementById("audit-signal");
  if (!panel) return;
  const status = ["idle", "starting", "running", "completed", "failed"].includes(state.status)
    ? state.status : "unavailable";
  panel.dataset.runState = status;
  panel.setAttribute("aria-busy", String(status === "starting" || status === "running"));

  const stateText = {
    idle: "STANDBY", starting: "STARTING", running: "RUNNING · LIVE",
    completed: "CYCLE COMPLETE", failed: "RUN FAILED", unavailable: "STATUS LINK LOST",
  };
  const current = DISCOVERY_STAGES.indexOf(state.stage);
  const stageLabel = status === "starting" ? "Starting discovery"
    : current >= 0 ? DISCOVERY_STAGE_LABELS[current]
      : status === "completed" ? "Discovery cycle complete"
        : status === "failed" ? "Discovery needs attention"
          : status === "unavailable" ? "Status unavailable" : "Awaiting run";
  const phase = status === "completed" || state.stage === "complete" ? "05 / 05"
    : status === "failed" ? "ERR / 05"
      : current >= 0 ? `${String(current + 1).padStart(2, "0")} / 05` : "— / 05";
  const started = Number(state.started_at);
  const ended = Number(state.finished_at);
  const seconds = Number.isFinite(started) && started > 0
    ? Math.max(0, Math.floor(((status === "completed" || status === "failed") && Number.isFinite(ended) && ended > 0
      ? ended : Date.now() / 1000) - started)) : null;
  const elapsed = seconds == null ? "—"
    : `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
  const detail = status === "idle" ? "Press “Run Ethereum discovery + audit” to start the five-stage pass."
    : status === "unavailable" ? "The dashboard status endpoint cannot be reached. Check that the auditor server is available."
      : state.message || stageLabel;

  const set = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  set("audit-live-state", stateText[status]);
  set("audit-stage-label", stageLabel);
  set("audit-phase-count", phase);
  set("audit-elapsed", elapsed);
  set("scan-discovery-status", detail);
}

function setupDiscoveryControls() {
  const buttons = Array.from(document.querySelectorAll(".js-discovery-run"));
  if (!buttons.length) return;
  let timer = null;
  const paint = (state) => {
    renderDiscoveryStage(state.stage || "idle");
    paintDiscoverySignal(state);
    const active = state.status === "running" || state.status === "starting";
    buttons.forEach((button) => {
      button.dataset.idleLabel ||= button.textContent;
      button.disabled = active;
      button.textContent = active ? "Discovery running…" : button.dataset.idleLabel;
    });
    const targetIds = new Set(buttons.map((b) => b.dataset.statusId).filter(Boolean));
    targetIds.forEach((id) => {
      const node = document.getElementById(id);
      if (!node) return;
      node.textContent = id === "scan-discovery-status" && state.status === "idle"
        ? "Press “Run Ethereum discovery + audit” to start the five-stage pass."
        : state.message || "Ready";
      node.classList.toggle("error", state.status === "failed");
      node.classList.toggle("success", state.status === "completed");
    });
  };
  const poll = async () => {
    try {
      const state = await api("/api/hunt/run");
      paint(state);
      if (state.status === "completed") window.dispatchEvent(new CustomEvent("hunt:refresh"));
      if (["running", "starting"].includes(state.status) && !timer) {
        timer = window.setInterval(poll, 1500);
      } else if (timer && !["running", "starting"].includes(state.status)) {
        clearInterval(timer); timer = null;
      }
    } catch (e) {
      buttons.forEach((button) => { button.disabled = false; });
      paintDiscoverySignal({ status: "unavailable", message: e.message });
    }
  };
  buttons.forEach((button) => button.addEventListener("click", async () => {
    button.disabled = true;
    const statusId = button.dataset.statusId;
    const statusNode = statusId && document.getElementById(statusId);
    if (statusNode) statusNode.textContent = "Starting Ethereum discovery…";
    try {
      const state = await api("/api/hunt/run", { method: "POST" });
      paint(state);
      if (!timer) timer = window.setInterval(poll, 1500);
      poll();
    } catch (e) {
      button.disabled = false;
      if (statusNode) statusNode.textContent = "Could not start discovery: " + e.message;
      paintDiscoverySignal({ status: "unavailable", message: e.message });
    }
  }));
  poll();
}

let pulseTimer = null;
function startDashboardPulse() {
  if (!document.getElementById("network-pulse")) return;
  const updateClock = () => {
    const node = document.getElementById("pulse-clock");
    if (node) node.textContent = new Date().toLocaleTimeString("en-US", {
      timeZone: "America/Detroit", hour12: false,
    }) + " ET";
  };
  updateClock();
  if (!pulseTimer) pulseTimer = window.setInterval(updateClock, 1000);
  const update = async () => {
    try {
      const d = await api("/api/dashboard/pulse");
      setText("pulse-block", d.block == null ? "—" : Number(d.block).toLocaleString());
      setText("pulse-queue", Number(d.queue_pending || 0).toLocaleString());
      setText("pulse-scanned", Number(d.scanned || 0).toLocaleString());
      setText("pulse-ready", Number(d.ready || 0).toLocaleString());
      const root = document.getElementById("network-pulse");
      if (root) {
        root.classList.toggle("pulse-active", d.discovery_run && d.discovery_run.status === "running");
        root.classList.remove("pulse-stale");
      }
    } catch (e) {
      const root = document.getElementById("network-pulse");
      if (root) root.classList.add("pulse-stale");
    }
  };
  update();
  window.setInterval(update, 8000);
}

/* ---- overview page ---- */

async function loadOverview() {
  setupChrome("overview");
  try {
    const stats = await api("/api/overview");
    setText("total-scans", stats.total_scans);
    setText("completed-scans", stats.completed_scans);
    setText("failed-scans", stats.failed_scans);
    setText("total-findings", stats.total_findings);

    const counts = stats.findings_by_severity || {};
    const max = Math.max(1, ...Object.values(counts));
    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]) {
      const n = counts[sev] || 0;
      const countNode = document.getElementById("count-" + sev);
      if (countNode) setText("count-" + sev, n);
      const bar = document.querySelector(`.severity-bar[data-severity="${sev}"] .bar`);
      if (bar) bar.style.width = (n / max) * 100 + "%";
    }

    renderRecentScans(stats.recent_scans || []);
  } catch (err) {
    const body = document.getElementById("recent-scans-body");
    if (body) {
      clearChildren(body);
      body.appendChild(
        el("tr", { class: "empty-row" }, [
          el("td", { colspan: "5", text: "Failed to load overview: " + err.message }),
        ])
      );
    }
  }
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (!node) return;
  const next = String(value ?? "");
  const previous = node.textContent;
  if (previous === next) return;
  const match = (text) => String(text).match(/^([^0-9-]*)(-?[0-9][0-9,]*(?:\.[0-9]+)?)(.*)$/);
  const oldParts = match(previous);
  const newParts = match(next);
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduced && oldParts && newParts && oldParts[1] === newParts[1] && oldParts[3] === newParts[3]) {
    const start = Number(oldParts[2].replaceAll(",", ""));
    const end = Number(newParts[2].replaceAll(",", ""));
    const decimals = (newParts[2].split(".")[1] || "").length;
    if (Number.isFinite(start) && Number.isFinite(end) && start !== end) {
      if (node._metricFrame) cancelAnimationFrame(node._metricFrame);
      const began = performance.now();
      const draw = (now) => {
        const t = Math.min(1, (now - began) / 480);
        const eased = 1 - Math.pow(1 - t, 3);
        const n = start + (end - start) * eased;
        node.textContent = oldParts[1] + n.toLocaleString(undefined, {
          minimumFractionDigits: decimals, maximumFractionDigits: decimals,
        }) + oldParts[3];
        if (t < 1) node._metricFrame = requestAnimationFrame(draw);
        else { node._metricFrame = null; node.textContent = next; }
      };
      node._metricFrame = requestAnimationFrame(draw);
    } else node.textContent = next;
  } else node.textContent = next;
  node.classList.remove("value-flash");
  // Restart the transition whenever a backed metric changes.
  void node.offsetWidth;
  node.classList.add("value-flash");
  window.setTimeout(() => node.classList.remove("value-flash"), 650);
}

function renderRecentScans(scans) {
  const body = document.getElementById("recent-scans-body");
  if (!body) return;
  clearChildren(body);
  if (!scans.length) {
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "5", text: "No scans yet. Start one from New Scan." }),
      ])
    );
    return;
  }
  for (const s of scans) {
    const link = el("a", { href: "/scan/" + s.scan_id, class: "monospace", text: shortId(s.scan_id) });
    const idCell = el("td", {}, [link]);
    body.appendChild(
      el("tr", {}, [
        idCell,
        el("td", { class: "mono", text: s.source_path || "—" }),
        el("td", {}, [badge(s.status)]),
        el("td", { class: "mono", text: String(s.finding_count) }),
        el("td", { text: fmtTime(s.timestamp) }),
      ])
    );
  }
}
