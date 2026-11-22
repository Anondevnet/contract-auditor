/* Scan detail page. */

setupChrome("detail");

const scanId = document.body.dataset.scanId ||
  window.location.pathname.split("/").pop();

const findingModal = document.getElementById("finding-modal");

document.getElementById("finding-modal-close").addEventListener("click", closeFindingModal);
document.getElementById("finding-modal-close-btn").addEventListener("click", closeFindingModal);

function closeFindingModal() {
  findingModal.classList.remove("open");
}

let scanDetail = null;

async function loadDetail() {
  const subtitle = document.getElementById("scan-subtitle");
  try {
    scanDetail = await api("/api/scans/" + encodeURIComponent(scanId));
  } catch (err) {
    subtitle.textContent = "Failed to load scan: " + err.message;
    return;
  }

  subtitle.textContent = scanDetail.source_path || scanDetail.scan_id;

  document.getElementById("detail-scan-id").textContent = scanDetail.scan_id;
  document.getElementById("detail-source").textContent = scanDetail.source_path || "—";
  document.getElementById("detail-hash").textContent = scanDetail.content_hash || "—";
  document.getElementById("detail-config").textContent = scanDetail.config_fingerprint || "—";

  const statusNode = document.getElementById("detail-status");
  clearChildren(statusNode);
  statusNode.appendChild(badge(scanDetail.status));
  document.getElementById("detail-time").textContent = fmtTime(scanDetail.timestamp);

  const counts = scanDetail.findings_by_severity || {};
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]) {
    const node = document.getElementById("count-" + sev);
    if (node) node.textContent = counts[sev] || 0;
  }

  renderToolStatus(scanDetail);
  renderFindings(scanDetail.findings || []);
  renderPrivilegedFunctions(scanDetail.findings || []);
}

function renderToolStatus(scan) {
  const warn = document.getElementById("detail-scan-warning");
  const body = document.getElementById("tool-status-body");
  const valNode = document.getElementById("detail-validation");
  clearChildren(body);
  clearChildren(valNode);

  const tools = scan.tool_runs || [];
  const complete = scan.scan_complete;
  const incomplete = scan.incomplete_reasons || [];

  if (complete === false) {
    warn.style.display = "";
    warn.className = "scan-warning danger";
    let text = "Incomplete scan — some tools did not complete. ";
    if (scan.finding_count === 0 && scan.zero_findings_note) {
      text = scan.zero_findings_note + " ";
    } else {
      text +=
        "No findings here must not be read as a clean result. ";
    }
    text += incomplete.length ? "Reasons: " + incomplete.join("; ") + "." : "";
    warn.textContent = text;
  } else if (complete === true && scan.finding_count === 0) {
    warn.style.display = "";
    warn.className = "scan-warning notice";
    warn.textContent =
      scan.zero_findings_note ||
      "No findings detected by the checks that completed.";
  } else {
    warn.style.display = "none";
    warn.textContent = "";
  }

  if (!tools.length) {
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", {
          colspan: "7",
          text: "Tool execution was not recorded for this scan (recorded before tool-status tracking).",
        }),
      ])
    );
    valNode.appendChild(
      el("p", { class: "muted", text: "Validation status not recorded for this scan." })
    );
    return;
  }

  tools.forEach((tool) => {
    const sev = Object.entries(tool.severity_counts || {})
      .map(([k, v]) => k + " " + v)
      .join(", ");
    const statusCell = el("td", {}, [badge(tool.status || "unknown")]);
    const message = tool.error || tool.message || "—";
    body.appendChild(
      el("tr", { class: "tool-row" }, [
        el("td", { text: tool.label || tool.key || "—" }),
        el("td", { text: tool.kind || "—" }),
        statusCell,
        el("td", { text: tool.finding_count == null ? "—" : String(tool.finding_count) }),
        el("td", { text: sev || "—" }),
        el("td", { text: tool.duration_seconds != null ? tool.duration_seconds + "s" : "—" }),
        el("td", { text: String(message) }),
      ])
    );
  });

  if (complete === null || complete === undefined) {
    valNode.appendChild(
      el("p", { class: "muted", text: "Completeness not recorded for this scan." })
    );
  } else if (scan.validation) {
    valNode.appendChild(
      el("p", {
        class: "muted",
        text: "Validation results are compilation/test evidence only — not evidence for or against vulnerabilities.",
      })
    );
  } else {
    valNode.appendChild(
      el("p", {
        class: "muted",
        text: "Build/test validation was not selected for this scan.",
      })
    );
  }
}


function parsePrivilegedMeta(f) {
  let meta = null;
  if (f && f.reasoning) {
    try { meta = JSON.parse(f.reasoning); } catch (e) { meta = null; }
  }
  if (meta && meta.status) return meta;
  // Fallback: parse description markers
  const desc = (f && f.description) || "";
  const m = desc.match(/category=(\w+)\s+status=(\w+)\s+guard=([^\s]+)\s+controller=([^\s.]+)/);
  if (m) {
    return { privileged_category: m[1], status: m[2], guard: m[3], controller: m[4] === "n/a" ? "" : m[4] };
  }
  return { privileged_category: (f && f.category) || "—", status: "—", guard: "—", controller: "" };
}

function renderPrivilegedFunctions(findings) {
  const body = document.getElementById("privileged-functions-body");
  const empty = document.getElementById("privileged-functions-empty");
  if (!body) return;
  clearChildren(body);
  const rows = (findings || []).filter((f) => {
    const tool = (f.tool || "").toLowerCase();
    const cat = (f.category || "").toLowerCase();
    return tool === "privileged_auth" || cat === "privileged_auth" ||
      (f.title || "").indexOf("privileged-auth-") === 0;
  });
  if (!rows.length) {
    if (empty) empty.style.display = "";
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "6", text: "No privileged-function authorization findings for this scan." }),
      ])
    );
    return;
  }
  if (empty) empty.style.display = "none";
  rows.forEach((f) => {
    const meta = parsePrivilegedMeta(f);
    const fnLabel = ((f.affected_contract || "") + "." + (f.affected_function || "")).replace(/^\./, "") || "—";
    const status = meta.status || "—";
    const statusClass =
      status === "UNPROTECTED" ? "severity-CRITICAL" :
      status === "WEAK" ? "severity-HIGH" :
      status === "PROTECTED" ? "severity-INFORMATIONAL" : "";
    body.appendChild(
      el("tr", {}, [
        el("td", { text: meta.privileged_category || "—" }),
        el("td", { class: "monospace", text: fnLabel }),
        el("td", {}, [el("span", { class: "badge " + statusClass, text: status })]),
        el("td", { text: meta.guard || "none" }),
        el("td", { text: meta.controller || "—" }),
        el("td", {}, [badge(f.severity || "—")]),
      ])
    );
  });
}

function renderFindings(findings) {
  const sevFilter = document.getElementById("severity-filter").value;
  const statusFilter = document.getElementById("status-filter").value;
  const body = document.getElementById("findings-body");
  clearChildren(body);

  const rows = findings.filter((f) => {
    if (sevFilter && (f.severity || "") !== sevFilter) return false;
    if (statusFilter) {
      const st = f.verification_status || f.status || "";
      if (st !== statusFilter) return false;
    }
    return true;
  });

  if (!rows.length) {
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "10", text: findings.length ? "No findings match the filters." : "No findings recorded for this scan." }),
      ])
    );
    return;
  }

  rows.forEach((f) => {
    const lines = (f.affected_lines || []).join(", ") || "—";
    const viewBtn = el("button", { class: "btn btn-link btn-sm", type: "button", text: "Details" });
    viewBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      openFinding(f);
    });

    const actions = el("td", { class: "row-actions" }, [viewBtn]);
    if (f.fingerprint) {
      const invBtn = el("button", {
        class: "btn btn-primary btn-sm investigate-btn",
        type: "button",
        text: "Investigate",
      });
      invBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        openInvestigation(f);
      });
      actions.appendChild(invBtn);
    }

    const row = el("tr", { class: "finding-row" }, [
      el("td", { class: "mono", text: shortId(f.finding_id || f.fingerprint) }),
      el("td", { text: f.title || "Untitled" }),
      el("td", {}, [badge(f.severity || "UNKNOWN")]),
      el("td", {}, [badge(f.confidence || "UNKNOWN", "low")]),
      el("td", {}, [badge(f.verification_status || f.status || "UNVERIFIED")]),
      el("td", { class: "mono", text: f.affected_contract || "—" }),
      el("td", { class: "mono", text: f.affected_function || "—" }),
      el("td", { class: "mono", text: lines }),
      el("td", { text: f.category || "—" }),
      actions,
    ]);
    if (f.fingerprint) {
      row.classList.add("clickable");
      row.addEventListener("click", () => openInvestigation(f));
    }
    body.appendChild(row);
  });
}

function openInvestigation(f) {
  window.location.href =
    "/investigate/" +
    encodeURIComponent(scanId) +
    "?fp=" +
    encodeURIComponent(f.fingerprint);
}

function openFinding(f) {
  document.getElementById("finding-modal-title").textContent = f.title || "Finding";
  const content = document.getElementById("finding-detail-content");
  clearChildren(content);

  const kv = el("dl", { class: "finding-kv" });
  const pairs = [
    ["ID", f.finding_id || f.fingerprint || "—"],
    ["Severity", f.severity || "—"],
    ["Confidence", f.confidence || "—"],
    ["Status", f.verification_status || f.status || "—"],
    ["Category", f.category || "—"],
    ["Contract", f.affected_contract || "—"],
    ["Function", f.affected_function || "—"],
    ["Lines", (f.affected_lines || []).join(", ") || "—"],
    ["Source", f.source || "—"],
    ["Tool", f.tool || "—"],
  ];
  for (const [k, v] of pairs) {
    kv.appendChild(el("dt", { text: k }));
    kv.appendChild(el("dd", { text: String(v) }));
  }
  content.appendChild(kv);

  if (f.description) {
    content.appendChild(el("h4", { text: "Description" }));
    content.appendChild(el("p", { text: f.description }));
  }
  if (f.remediation) {
    content.appendChild(el("h4", { text: "Remediation" }));
    content.appendChild(el("p", { text: f.remediation }));
  }

  const evidence = f.evidence || [];
  content.appendChild(el("h4", { text: "Evidence (" + evidence.length + ")" }));
  if (!evidence.length) {
    content.appendChild(el("p", { class: "muted", text: "No evidence attached." }));
  }
  for (const ev of evidence) {
    const item = el("div", { class: "evidence-item" });
    item.appendChild(
      el("div", {}, [
        el("span", { class: "epistemic " + ev.epistemic, text: ev.epistemic }),
        document.createTextNode(" · " + (ev.source || "") + " · " + (ev.artifact_type || "")),
      ])
    );
    item.appendChild(el("div", { text: (ev.excerpt || "").slice(0, 300) }));
    content.appendChild(item);
  }

  findingModal.classList.add("open");
}

document.getElementById("severity-filter").addEventListener("change", () => {
  if (scanDetail) renderFindings(scanDetail.findings || []);
});
document.getElementById("status-filter").addEventListener("change", () => {
  if (scanDetail) renderFindings(scanDetail.findings || []);
});

document.getElementById("export-btn").addEventListener("click", () => {
  const fmt = document.getElementById("export-format").value;
  window.location.href =
    "/api/scans/" + encodeURIComponent(scanId) + "/report?format=" + encodeURIComponent(fmt);
});

loadDetail();
