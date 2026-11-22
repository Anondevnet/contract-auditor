/* Findings list: search, filter, sort, group, and one-click investigation. */

setupChrome("findings");

const FINDINGS_STATE_SLUG = {
  New: "state-New",
  "Needs Review": "state-NeedsReview",
  "Potential Vulnerability": "state-Potential",
  "Confirmed by Evidence": "state-Confirmed",
  "False Positive": "state-FP",
  Fixed: "state-Fixed",
  Retested: "state-Retested",
};

function stateBadge(state) {
  const slug = FINDINGS_STATE_SLUG[state] || "state-New";
  return el("span", { class: "badge state-badge " + slug, text: state || "New" });
}

const PAGE_SIZE = 200;
let pageOffset = 0;

function currentParams() {
  const q = document.getElementById("findings-q").value.trim();
  const sev = document.getElementById("findings-severity").value;
  const status = document.getElementById("findings-status").value;
  const state = document.getElementById("findings-state").value;
  const finrisk = document.getElementById("findings-finrisk").value;
  const sort = document.getElementById("findings-sort").value;
  const group = document.getElementById("findings-group").value;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (sev) params.set("severity", sev);
  if (status) params.set("status", status);
  if (state) params.set("state", state);
  if (finrisk) params.set("finrisk", finrisk);
  params.set("sort", sort);
  params.set("group", group);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(pageOffset));
  return params;
}

const FINRISK_BADGE = {
  validated_financial_risk: { cls: "state-Confirmed", label: "Finrisk: validated" },
  potential_financial_risk: { cls: "state-Potential", label: "Finrisk: potential" },
  disproved: { cls: "state-FP", label: "Finrisk: disproved" },
  inconclusive: { cls: "state-New", label: "Finrisk: inconclusive" },
  not_financially_exploitable: { cls: "state-Retested", label: "Finrisk: not exploitable" },
  pending: { cls: "state-New", label: "Finrisk: pending" },
  running: { cls: "state-New", label: "Finrisk: running" },
  retryable_error: { cls: "state-Fixed", label: "Finrisk: errored (retrying)" },
};

function finriskBadge(fr) {
  if (!fr) return null;
  const key = fr.verdict || fr.state || "";
  const meta = FINRISK_BADGE[key] || { cls: "state-New", label: "Finrisk: " + key };
  return el("span", { class: "badge state-badge " + meta.cls, text: meta.label });
}

function findingRow(f) {
  const locationBase = [f.affected_contract || "?", f.affected_function || "?"].join(".");
  const lineLabel =
    f.affected_lines && f.affected_lines.length
      ? linesLabel(f.affected_lines)
      : "—";

  const investigateBtn = el(
    "button",
    { class: "btn btn-primary btn-sm", type: "button", text: "Investigate" }
  );
  investigateBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    openInvestigation(f);
  });

  const tri = f.monitor_triage || null;
  const titleCell = el("td", { class: "finding-title" }, [
    el("div", { text: f.title || "Untitled" }),
  ]);
  if (tri) {
    titleCell.appendChild(el("div", {
      class: "triage-note",
      text: "Triaged " + tri.verdict + " — " + tri.reason + (tri.rule ? " [" + tri.rule + "]" : ""),
    }));
  }
  const frb = finriskBadge(f.finrisk);
  if (frb) titleCell.appendChild(frb);
  const row = el("tr", { class: "finding-row" + (tri ? " finding-triaged" : ""), tabindex: "0" }, [
    el("td", {}, [tri ? el("span", { class: "badge state-badge state-FP", text: "False positive" })
                      : badge(f.severity || "UNKNOWN")]),
    titleCell,
    el("td", { text: f.category || "—" }),
    el("td", {}, [badge(f.verification_status || "UNVERIFIED")]),
    el("td", {}, [stateBadge(tri && (!f.state || f.state === "New") ? "False Positive" : f.state)]),
    el("td", {
      class: "mono",
      text: locationBase + (lineLabel !== "—" ? ":" + lineLabel : ""),
    }),
    el("td", { text: f.tool || f.source || "—" }),
    el("td", { class: "mono", text: shortId(f.scan_id) }),
    el("td", {}, [investigateBtn]),
  ]);
  row.addEventListener("click", () => openInvestigation(f));
  row.addEventListener("keydown", (e) => {
    if (e.key === "Enter") openInvestigation(f);
  });
  return row;
}

function linesLabel(lines) {
  if (!lines || !lines.length) return "—";
  if (lines.length === 1) return String(lines[0]);
  return lines[0] + "–" + lines[lines.length - 1];
}

function openInvestigation(f) {
  const url =
    "/investigate/" +
    encodeURIComponent(f.scan_id) +
    "?fp=" +
    encodeURIComponent(f.fingerprint || "");
  window.location.href = url;
}

function renderTable(rows) {
  const table = el("table", { class: "data-table findings-table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", { text: "Severity" }),
        el("th", { text: "Title" }),
        el("th", { text: "Category" }),
        el("th", { text: "Status" }),
        el("th", { text: "State" }),
        el("th", { text: "Location" }),
        el("th", { text: "Scanner" }),
        el("th", { text: "Scan" }),
        el("th", { text: "Action" }),
      ]),
    ]),
  ]);
  const tbody = el("tbody", {});
  rows.forEach((f) => tbody.appendChild(findingRow(f)));
  table.appendChild(tbody);
  return table;
}

async function loadFindings() {
  const container = document.getElementById("findings-groups");
  const empty = document.getElementById("findings-empty");
  const counter = document.getElementById("findings-count");
  try {
    const data = await api("/api/findings?" + currentParams().toString());
    clearChildren(container);
    const from = data.total ? (data.offset || 0) + 1 : 0;
    const to = (data.offset || 0) + (data.returned != null ? data.returned : (data.findings || []).length);
    counter.textContent = data.total + " finding(s)" + (data.total > (data.limit || data.total) ? " — showing " + from + "–" + to : "");
    renderPager(data);

    if (!data.total) {
      empty.style.display = "";
      return;
    }
    empty.style.display = "none";

    if (data.groups) {
      for (const [key, rows] of Object.entries(data.groups)) {
        const card = el("div", { class: "card" }, [
          el("div", { class: "card-header" }, [
            el("h3", { text: key + " (" + rows.length + ")" }),
          ]),
        ]);
        const wrap = el("div", { class: "table-container" });
        wrap.appendChild(renderTable(rows));
        card.appendChild(wrap);
        container.appendChild(card);
      }
    } else {
      const card = el("div", { class: "card" }, [
        el("div", { class: "card-header" }, [el("h3", { text: "All findings" })]),
      ]);
      const wrap = el("div", { class: "table-container" });
      wrap.appendChild(renderTable(data.findings));
      card.appendChild(wrap);
      container.appendChild(card);
    }
  } catch (err) {
    clearChildren(container);
    counter.textContent = "Failed to load";
    container.appendChild(
      el("div", { class: "card" }, [
        el("div", { class: "card-body" }, [
          el("p", { class: "error-text", text: "Failed to load findings: " + err.message }),
        ]),
      ])
    );
  }
}

function renderPager(data) {
  let pager = document.getElementById("findings-pager");
  if (!pager) {
    pager = el("div", { id: "findings-pager", class: "pager" });
    const host = document.getElementById("findings-groups");
    host.parentNode.insertBefore(pager, host);
  }
  clearChildren(pager);
  if (!data.total || data.total <= (data.limit || data.total)) return;
  const prev = el("button", { class: "btn btn-secondary btn-sm", text: "‹ Prev" });
  const next = el("button", { class: "btn btn-secondary btn-sm", text: "Next ›" });
  prev.disabled = !(data.offset > 0);
  next.disabled = !data.has_more;
  prev.addEventListener("click", () => { pageOffset = Math.max(0, pageOffset - PAGE_SIZE); loadFindings(); });
  next.addEventListener("click", () => { pageOffset += PAGE_SIZE; loadFindings(); });
  pager.appendChild(prev);
  pager.appendChild(el("span", { class: "muted", text: " page " + (Math.floor(data.offset / PAGE_SIZE) + 1) + " of " + Math.ceil(data.total / PAGE_SIZE) + " " }));
  pager.appendChild(next);
}

function resetAndLoad() {
  pageOffset = 0;
  loadFindings();
}

function wireControls() {
  const ids = [
    "findings-severity",
    "findings-status",
    "findings-state",
    "findings-finrisk",
    "findings-sort",
    "findings-group",
  ];
  ids.forEach((id) =>
    document.getElementById(id).addEventListener("change", resetAndLoad)
  );

  let timer = null;
  document.getElementById("findings-q").addEventListener("input", () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(resetAndLoad, 300);
  });

  document.getElementById("findings-clear").addEventListener("click", () => {
    document.getElementById("findings-q").value = "";
    document.getElementById("findings-severity").value = "";
    document.getElementById("findings-status").value = "";
    document.getElementById("findings-state").value = "";
    document.getElementById("findings-finrisk").value = "";
    document.getElementById("findings-sort").value = "severity";
    document.getElementById("findings-group").value = "none";
    resetAndLoad();
  });
}

function fmtUsd(v) {
  if (v == null || isNaN(v)) return "—";
  if (v >= 1e9) return "$" + (v / 1e9).toFixed(2) + "B";
  if (v >= 1e6) return "$" + (v / 1e6).toFixed(2) + "M";
  if (v >= 1e3) return "$" + (v / 1e3).toFixed(1) + "K";
  return "$" + Number(v).toFixed(2);
}

async function loadFinriskCounters() {
  const card = document.getElementById("finrisk-counters");
  const body = document.getElementById("finrisk-counters-body");
  const at = document.getElementById("finrisk-counters-at");
  try {
    const s = await api("/api/finrisk/summary");
    if (!s || s.status === "empty") {
      card.style.display = "none";
      return;
    }
    card.style.display = "";
    at.textContent = "Persisted evidence only; no live calls";
    const q = s.queue || {};
    const v = s.verdicts || {};
    clearChildren(body);
    const chip = (label, value) => {
      const n = value == null ? 0 : value;
      return el("span", { class: "badge state-badge state-New", text: label + ": " + n });
    };
    const row = (container, items) => {
      const wrap = el("div", { style: "margin:4px 0;" }, []);
      items.forEach((i) => {
        if (i != null) wrap.appendChild(i);
        wrap.appendChild(document.createTextNode(" "));
      });
      container.appendChild(wrap);
    };
    row(body, [
      chip("pending", q.pending),
      chip("running", q.running),
      chip("errored (retrying)", q.retryable_error),
      chip("completed", q.completed),
    ]);
    row(body, [
      chip("validated", v.validated_financial_risk),
      chip("potential", v.potential_financial_risk),
      chip("disproved", v.disproved),
      chip("inconclusive", v.inconclusive),
      chip("not exploitable", v.not_financially_exploitable),
    ]);
    const roll = s.financial_rollup || null;
    if (roll) {
      body.appendChild(el("p", {
        class: "muted",
        text: "Exposure roll-up (persisted, per unique network+address): "
          + "confirmed outsider exposure " + fmtUsd(roll.confirmed_outsider_exposure_usd)
          + " over " + (roll.confirmed_addresses || 0) + " address(es); "
          + "potential/unverified " + fmtUsd(roll.potential_or_unverified_exposure_usd)
          + " over " + (roll.potential_addresses || 0) + " address(es); "
          + "modeled estimate " + fmtUsd(roll.modeled_impact_estimate_usd)
          + " (heuristic model, NOT confirmed funds at risk). "
          + "Disproved rows excluded from every total: " + (roll.disproved_excluded_rows || 0) + "."
      }));
      if (roll.validated_without_dollar_estimate) {
        body.appendChild(el("p", { class: "muted", text: "Validated rows without a reliable dollar figure: " + roll.validated_without_dollar_estimate }));
      }
    }
  } catch (err) {
    card.style.display = "none";
  }
}

wireControls();
loadFindings();
loadFinriskCounters();
