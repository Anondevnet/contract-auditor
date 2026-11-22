/* Two-sided investigation page: attacker / white-hat panels, lifecycle,
   retest, AI audit, bounty check, and OpenCode patch proposals. */

setupChrome("findings");

const scanId = window.location.pathname.split("/").pop();
const fingerprint = new URLSearchParams(window.location.search).get("fp") || "";

const STATE_SLUG = {
  New: "state-New",
  "Needs Review": "state-NeedsReview",
  "Potential Vulnerability": "state-Potential",
  "Confirmed by Evidence": "state-Confirmed",
  "False Positive": "state-FP",
  Fixed: "state-Fixed",
  Retested: "state-Retested",
};

let inv = null;
let currentProposal = null;
let pollTimer = null;
let activeJobId = null;

function msg(text, isError) {
  const node = document.getElementById("inv-message");
  node.style.display = "";
  node.textContent = text;
  node.classList.toggle("error-text", !!isError);
}

function clearMsg() {
  const node = document.getElementById("inv-message");
  node.style.display = "none";
  node.textContent = "";
}

function labeledLine(label, node) {
  const line = el("div", { class: "labeled-line" }, [
    el("span", { class: "labeled-key", text: label + ": " }),
    el("span", { text: node && node.value !== undefined ? String(node.value) : String(node || "") }),
  ]);
  if (node && node.origin) {
    line.appendChild(el("span", { class: "origin-tag", text: " (" + node.origin + ")" }));
  }
  if (node && node.basis) {
    line.appendChild(el("div", { class: "labeled-basis", text: "Basis: " + node.basis }));
  }
  return line;
}

function section(title, children) {
  return el("section", { class: "inv-section" }, [
    el("h4", { class: "inv-section-title", text: title }),
    ...children,
  ]);
}

function bulletList(items) {
  const list = el("ul", { class: "inv-list" });
  (items || []).forEach((item) =>
    list.appendChild(el("li", { html: escapeHtml(String(item)) }))
  );
  return list;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ---------- header + state control ---------- */

function renderHeader(data) {
  document.getElementById("inv-title").textContent = data.title || "Untitled finding";
  document.getElementById("inv-subtitle").textContent =
    "Scan " + scanId.slice(0, 8) + " — fingerprint " + (fingerprint || "").slice(0, 40);

  const badges = document.getElementById("inv-badges");
  clearChildren(badges);
  badges.appendChild(badge(data.severity || "UNKNOWN"));
  badges.appendChild(badge(data.confidence || "LOW"));
  badges.appendChild(badge(data.verification_status || "UNVERIFIED"));
  const state = (data.review && data.review.state) || "New";
  badges.appendChild(
    el("span", { class: "badge state-badge " + (STATE_SLUG[state] || "state-New"), text: state })
  );

  const select = document.getElementById("inv-state-select");
  clearChildren(select);
  const allowed = (data.review && data.review.allowed_transitions) || [];
  if (!allowed.length) {
    select.appendChild(el("option", { value: state, text: state }));
    select.disabled = true;
  } else {
    select.disabled = false;
    select.appendChild(el("option", { value: state, text: state + " (current)" }));
    allowed.forEach((s) => select.appendChild(el("option", { value: s, text: "→ " + s })));
  }

  document.getElementById("inv-export-json").href =
    "/api/findings/" + encodeURIComponent(scanId) + "/report?fp=" + encodeURIComponent(fingerprint) + "&format=json";
  document.getElementById("inv-export-md").href =
    "/api/findings/" + encodeURIComponent(scanId) + "/report?fp=" + encodeURIComponent(fingerprint) + "&format=markdown";
}

/* ---------- executive summary + protocol / financial ---------- */

function renderSummary(inv) {
  const box = document.getElementById("inv-summary");
  clearChildren(box);
  const s = inv.executive_summary || {};
  box.appendChild(el("p", { class: "inv-summary-headline", text: s.headline || "Not assessed" }));
  box.appendChild(labeledLine("What", s.what || "Not assessed"));
  box.appendChild(labeledLine("Recommended action", s.recommended_action || "Not assessed"));
  box.appendChild(labeledLine("Fix status", s.fix_status || "Not assessed"));
  box.appendChild(labeledLine("Financial status", s.financial_status || "Not assessed"));
  box.appendChild(labeledLine("Source classification", s.source_classification || "Not assessed"));
  box.appendChild(el("p", { class: "muted", text: "Origin: " + (s.origin || "unknown") }));
}

function labeledValue(node) {
  const wrap = el("span", {});
  wrap.appendChild(el("span", { text: node && node.value !== undefined ? String(node.value) : String(node || "") }));
  if (node && node.origin) wrap.appendChild(el("span", { class: "origin-tag", text: " " + node.origin }));
  return wrap;
}

function renderProtocol(inv) {
  const c = inv.classification || {};
  const classBox = document.getElementById("inv-classification");
  clearChildren(classBox);
  const cls =
    c.value === "test_fixture" ? "class-fixture"
      : c.value === "deployed_unverified" ? "class-deployed"
        : "class-local";
  const banner = el("div", { class: "class-banner " + cls }, [
    el("div", { class: "class-label", text: c.label || "Not assessed" }),
    el("div", { class: "class-basis", text: c.basis || "" }),
  ]);
  if (c.origin) banner.appendChild(el("span", { class: "origin-tag", text: c.origin }));
  classBox.appendChild(banner);

  const badgeBox = document.getElementById("inv-classification-badge");
  clearChildren(badgeBox);
  badgeBox.appendChild(el("span", { class: "origin-tag", text: c.value || "unknown" }));

  const pbox = document.getElementById("inv-protocol");
  clearChildren(pbox);
  const table = el("table", { class: "kv-table" });
  for (const [k, v] of Object.entries((inv.protocol && inv.protocol.fields) || {})) {
    table.appendChild(
      el("tr", {}, [
        el("th", { text: k.replace(/_/g, " ") }),
        el("td", {}, [labeledValue(v)]),
      ])
    );
  }
  pbox.appendChild(table);
  const asset = (inv.protocol && inv.protocol.asset) || {};
  if (asset.warning) pbox.appendChild(el("p", { class: "muted", text: asset.warning }));

  const fbox = document.getElementById("inv-financial");
  clearChildren(fbox);
  const f = inv.financial_impact || {};
  fbox.appendChild(
    el("p", { text: ((f.status || "unknown").toUpperCase()) + " — " + (f.summary || "Not assessed") })
  );
  const ftable = el("table", { class: "kv-table" });
  for (const [label, node] of [
    ["Theoretical maximum", f.theoretical_max],
    ["Realistically reachable", f.realistically_reachable],
    ["Confirmed loss", f.confirmed_loss],
    ["Contract balance", f.contract_balance],
    ["TVL", f.tvl],
    ["USD equivalent", f.usd_equivalent],
    ["Confidence", f.confidence ? { value: f.confidence, origin: "unknown" } : null],
  ]) {
    if (!node) continue;
    ftable.appendChild(
      el("tr", {}, [el("th", { text: label }), el("td", {}, [labeledValue(node)])])
    );
  }
  fbox.appendChild(ftable);
  if ((f.methodology || []).length) {
    fbox.appendChild(el("h4", { class: "inv-section-title", text: "Methodology" }));
    fbox.appendChild(bulletList(f.methodology));
  }
  if ((f.what_would_validate_these_numbers || []).length) {
    fbox.appendChild(el("h4", { class: "inv-section-title", text: "What would validate these numbers" }));
    fbox.appendChild(bulletList(f.what_would_validate_these_numbers));
  }
  if (f.warning) fbox.appendChild(el("p", { class: "muted", text: f.warning }));
}

/* ---------- severity provenance + duplicates ---------- */

function renderProvenance(inv) {
  const box = document.getElementById("inv-provenance");
  clearChildren(box);
  const p = inv.severity_provenance || {};
  const current = p.current || {};
  const scanner = p.scanner || {};
  const triage = p.triage || {};
  const ai = p.ai || {};
  const ev = p.evidence_backed_verification || {};
  const fp = p.false_positive_review || {};

  const table = el("table", { class: "kv-table" });
  const rows = [
    ["Severity (shown)", current.severity],
    ["Confidence (shown)", current.confidence],
    ["Verification status", current.verification_status],
    ["Scanner severity", scanner.severity + " / " + scanner.confidence + " (" + (scanner.tool || "unknown tool") + ")"],
    ["AI severity", ai.present ? ai.severity + " (opinion)" : "not present"],
    ["Triage state", triage.state + " — " + (triage.recorded_events || 0) + " recorded event(s)"],
    ["Evidence-backed verification", (ev.verification_supported ? "Yes — " : "No — ") + (ev.note || "")],
    ["False-positive review", (fp.recommended ? "Recommended — " : "Not required — ") + (fp.basis || "")],
  ];
  for (const [k, v] of rows) {
    table.appendChild(el("tr", {}, [el("th", { text: k }), el("td", { text: String(v === undefined || v === null ? "Unknown — not verified" : v) })]));
  }
  box.appendChild(table);
  if (p.note) box.appendChild(el("p", { class: "muted", text: p.note }));

  const dbox = document.getElementById("inv-duplicates");
  clearChildren(dbox);
  const d = inv.duplicates || {};
  dbox.appendChild(
    el("p", {
      text: (d.count || 0) + " same-title finding(s) in this scan — " + (d.note || ""),
    })
  );
  (d.members || []).forEach((m) => {
    dbox.appendChild(
      el("div", { class: "dup-row" }, [
        el("span", { class: "mono", text: String(m.fingerprint || "").slice(0, 12) + " " }),
        el("span", { text: m.title || "" }),
        badge(m.severity || "UNKNOWN"),
        el("span", { class: "muted", text: " " + (m.location || "") }),
      ])
    );
  });
}

/* ---------- panels ---------- */

function renderAttacker(a) {
  const box = document.getElementById("inv-attacker");
  clearChildren(box);

  box.appendChild(section("What this means (plain English)", [
    el("p", { text: a.plain_english || "Not assessed" }),
  ]));

  box.appendChild(section("Vulnerable operation", [
    labeledLine("Operation", a.vulnerable_operation),
  ]));

  box.appendChild(section("Call path (conceptual)", [bulletList(a.call_path)]));

  const path = section("Conceptual attack path", [
    el("p", { class: "muted", text: a.attack_path_label || "" }),
    bulletList(a.attack_path),
  ]);
  box.appendChild(path);

  box.appendChild(section("Preconditions", [bulletList(a.preconditions)]));
  box.appendChild(section("Reachability", [labeledLine("Verdict", a.reachability)]));
  box.appendChild(section("Privileges required", [labeledLine("Value", a.privileges_required)]));
  box.appendChild(section("External dependencies", [bulletList(a.external_dependencies)]));

  const vt = a.validation_time || {};
  box.appendChild(section("Validation time (estimate, not remediation)", [
    el("p", { text: vt.range || "Not assessed" }),
    vt.explanation ? el("p", { class: "muted", text: vt.explanation }) : el("span"),
    vt.label ? el("span", { class: "origin-tag", text: " (" + vt.label + ")" }) : el("span"),
    vt.separate_from ? el("p", { class: "muted", text: "Kept separate from: " + vt.separate_from }) : el("span"),
  ]));

  box.appendChild(section("Evidence still needed", [bulletList(a.evidence_needed)]));

  const caia = section("Impact (CIA + authenticity)", []);
  const table = el("table", { class: "kv-table" });
  for (const [k, v] of Object.entries(a.caia || {})) {
    table.appendChild(
      el("tr", {}, [
        el("th", { text: k }),
        el("td", { text: v }),
      ])
    );
  }
  caia.appendChild(table);
  box.appendChild(caia);

  const diff = a.difficulty || {};
  box.appendChild(section("Difficulty (estimate)", [
    el("p", { text: diff.value || "Not assessed" }),
    diff.explanation ? el("p", { class: "muted", text: diff.explanation }) : el("span"),
    diff.label ? el("span", { class: "origin-tag", text: " (" + diff.label + ")" }) : el("span"),
  ]));

  const exposure = section("Exposure model", []);
  exposure.appendChild(labeledLine("Theoretical maximum", a.exposure && a.exposure.theoretical_max));
  exposure.appendChild(labeledLine("Realistically reachable", a.exposure && a.exposure.realistically_reachable));
  exposure.appendChild(labeledLine("Confirmed loss", a.exposure && a.exposure.confirmed_loss));
  if (a.exposure && a.exposure.note) {
    exposure.appendChild(el("p", { class: "muted", text: a.exposure.note }));
  }
  box.appendChild(exposure);

  box.appendChild(section("Likelihood / impact", [
    labeledLine("Likelihood", a.likelihood),
    labeledLine("Impact", a.impact),
  ]));

  box.appendChild(section("Avoid these false conclusions", [bulletList(a.misconceptions)]));
}

function renderDefender(d) {
  const box = document.getElementById("inv-defender");
  clearChildren(box);

  const root = d.root_cause || {};
  const source = root.source || {};
  const snippet = el("pre", { class: "code-snippet" });
  if (source.lines && source.lines.length) {
    source.lines.forEach((l) => {
      snippet.appendChild(document.createTextNode(String(l.n).padStart(4, " ") + "  " + l.text + "\n"));
    });
  } else {
    snippet.textContent = "Source excerpt unavailable" +
      (source.read_error ? ": " + source.read_error : " (not located)");
  }
  box.appendChild(section("Root cause (from source)", [
    el("p", { text: root.summary || "Not assessed" }),
    el("p", { class: "muted", text: (source.file || "") + (source.line_range ? "  lines " + source.line_range[0] + "–" + source.line_range[1] : "") + (source.origin ? "  (" + source.origin + ")" : "") }),
    snippet,
  ]));

  const rem = d.remediation || {};
  box.appendChild(section("Remediation", [
    el("p", { text: rem.primary || "Not assessed" }),
    bulletList((rem.references || []).map((r) => "Reference: " + r)),
  ]));

  const fix = d.actionable_fix || {};
  if (fix.steps) {
    const fixSection = section("Actionable fix", []);
    const list = el("ol", { class: "fix-steps" });
    fix.steps.forEach((s) => list.appendChild(el("li", { text: s })));
    fixSection.appendChild(list);
    const fixEst = fix.estimated_fix_range || {};
    if (fixEst.range) {
      fixSection.appendChild(
        el("p", {
          class: "muted",
          text: "Estimated fix range: " + fixEst.range + " (" + (fixEst.label || "Approximate") + ")",
        })
      );
    }
    if (fix.grounding_note) fixSection.appendChild(el("p", { class: "muted", text: fix.grounding_note }));
    fixSection.appendChild(
      el("p", { class: "muted", text: "Nothing here is applied to your code automatically." })
    );
    box.appendChild(fixSection);
  }

  const patch = d.example_patch || {};
  const patchSection = section("Example patch (suggestion only)", []);
  if (patch.available) {
    patchSection.appendChild(el("p", { text: "Rule: " + (patch.rule || "") }));
    if (patch.reference) {
      patchSection.appendChild(el("p", { class: "muted", text: "Reference: " + patch.reference }));
    }
    const renderLines = (label, rows, cls) => {
      patchSection.appendChild(el("p", { class: "labeled-key", text: label }));
      const pre = el("pre", { class: "code-snippet patch-block" });
      (rows || []).forEach((r) => {
        pre.appendChild(
          el("span", { class: "patch-line " + cls, text: String(r.n).padStart(4, " ") + "  " + r.text + (r.note ? "  // " + r.note : "") + "\n" })
        );
      });
      patchSection.appendChild(pre);
    };
    renderLines("Before:", patch.before, "patch-before");
    renderLines("After (suggested order):", patch.after, "patch-after");
    patchSection.appendChild(
      el("p", {
        class: "muted",
        text: "Status: " + (patch.status || "suggested_not_applied") + " — " + (patch.apply_via || ""),
      })
    );
    patchSection.appendChild(bulletList((patch.caveats || []).map((c) => "Caveat: " + c)));
  } else {
    patchSection.appendChild(el("p", { text: "Unavailable: " + (patch.reason || "not derivable from the stored source.") }));
    if (patch.next_step) patchSection.appendChild(el("p", { class: "muted", text: "Next step: " + patch.next_step }));
  }
  box.appendChild(patchSection);

  box.appendChild(section("Benign explanation", [el("p", { text: d.benign_explanation || "Not assessed" })]));
  box.appendChild(section("False-positive considerations", [bulletList(d.false_positive_considerations)]));
  box.appendChild(section("Assumptions", [bulletList(d.assumptions)]));

  const est = d.estimates || {};
  const estSection = section("Effort estimates (approximate)", []);
  const estTable = el("table", { class: "data-table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", { text: "Group" }),
        el("th", { text: "Stage" }),
        el("th", { text: "Range" }),
        el("th", { text: "Label" }),
      ]),
    ]),
  ]);
  const tbody = el("tbody", {});
  ["validation", "remediation"].forEach((group) => {
    (est[group] || []).forEach((e) => {
      if (!e.stage) return;
      tbody.appendChild(
        el("tr", {}, [
          el("td", {}, [el("span", { class: "origin-tag", text: group })]),
          el("td", { text: e.stage }),
          el("td", { text: e.range }),
          el("td", {}, [el("span", { class: "origin-tag", text: e.label || "Approximate" })]),
        ])
      );
    });
  });
  estTable.appendChild(tbody);
  estSection.appendChild(estTable);
  if (est.note) estSection.appendChild(el("p", { class: "muted", text: est.note }));
  box.appendChild(estSection);

  const testPlan = section("Test plan", []);
  (d.test_plan || []).forEach((step) => {
    testPlan.appendChild(
      el("div", { class: "test-step" }, [
        el("strong", { text: step.step + ": " }),
        el("span", { text: step.detail }),
      ])
    );
  });
  box.appendChild(testPlan);
}

function renderEvidence(e) {
  const box = document.getElementById("inv-evidence");
  clearChildren(box);
  box.appendChild(
    el("p", {
      text:
        "FACT=" + (e.fact_count || 0) +
        ", INFERENCE=" + (e.inference_count || 0) +
        ", AI_OPINION=" + (e.ai_opinion_count || 0) +
        " — " + (e.label || ""),
    })
  );
  if (!e.items || !e.items.length) {
    box.appendChild(el("p", { class: "muted", text: "No evidence items recorded." }));
    return;
  }
  const table = el("table", { class: "data-table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", { text: "Epistemic" }),
        el("th", { text: "Source" }),
        el("th", { text: "Excerpt" }),
      ]),
    ]),
  ]);
  const tbody = el("tbody", {});
  e.items.forEach((item) => {
    tbody.appendChild(
      el("tr", {}, [
        el("td", {}, [badge(item.epistemic || "UNKNOWN")]),
        el("td", { text: item.source || "—" }),
        el("td", { class: "mono", text: item.excerpt || "" }),
      ])
    );
  });
  table.appendChild(tbody);
  box.appendChild(table);
}

function renderAi(ai) {
  const card = document.getElementById("inv-ai-card");
  if (!ai) {
    card.style.display = "none";
    return;
  }
  card.style.display = "";
  const box = document.getElementById("inv-ai");
  clearChildren(box);
  box.appendChild(el("p", { text: "Status: " + (ai.status || "unknown") + (ai.reason ? " — " + ai.reason : "") }));
  if (ai.risk_analysis) box.appendChild(el("p", { text: "Risk analysis: " + ai.risk_analysis }));
  if (ai.remediation) box.appendChild(el("p", { text: "Remediation: " + ai.remediation }));
  if (ai.uncertainty) box.appendChild(el("p", { class: "muted", text: "Uncertainty: " + ai.uncertainty }));
  box.appendChild(el("p", { class: "muted", text: "This block is model opinion, labeled generated_ai_analysis — not scanner evidence." }));
}

function renderUnknowns(items) {
  const box = document.getElementById("inv-unknowns");
  clearChildren(box);
  box.appendChild(bulletList(items));
}

function renderHistory(history) {
  const box = document.getElementById("inv-history");
  clearChildren(box);
  if (!history || !history.length) {
    box.appendChild(el("p", { class: "muted", text: "No state changes yet — starts at New." }));
    return;
  }
  history.forEach((h) => {
    box.appendChild(
      el("div", { class: "history-row" }, [
        el("span", { class: "muted", text: fmtTime(h.changed_at) }),
        el("span", { text: (h.from_state || "—") + " → " + h.to_state }),
        h.note ? el("span", { class: "muted", text: " — " + h.note }) : el("span"),
      ])
    );
  });
}

function renderGlossary(items) {
  const card = document.getElementById("inv-glossary-card");
  if (!items || !items.length) {
    card.style.display = "none";
    return;
  }
  card.style.display = "";
  const box = document.getElementById("inv-glossary");
  clearChildren(box);
  items.forEach((g) => {
    box.appendChild(
      el("div", { class: "glossary-row" }, [
        el("strong", { text: g.term + ": " }),
        el("span", { text: g.definition }),
      ])
    );
  });
}

function renderBounty(bounty) {
  const card = document.getElementById("inv-bounty-card");
  card.style.display = "";
  const box = document.getElementById("bounty-result");
  clearChildren(box);
  if (!bounty || bounty.status === "not_checked") {
    box.appendChild(el("p", { class: "muted", text: (bounty && bounty.reason) || "Not checked yet." }));
    if (bounty && bounty.reminder) box.appendChild(el("p", { class: "muted", text: bounty.reminder }));
    return;
  }
  if (bounty.status === "blocked" || bounty.status === "fetch_failed") {
    box.appendChild(el("p", { class: "error-text", text: "Status: " + bounty.status + " — no official source was fetched." }));
    if (bounty.eligibility_basis) box.appendChild(el("p", { class: "muted", text: bounty.eligibility_basis }));
    if (bounty.error) box.appendChild(el("p", { class: "error-text", text: bounty.error }));
    if (bounty.reminder) box.appendChild(el("p", { class: "muted", text: bounty.reminder }));
    return;
  }
  if (!bounty.official_source_fetched || !bounty.source_url) {
    box.appendChild(el("p", { class: "muted", text: "No official source was fetched — nothing to display." }));
    return;
  }
  box.appendChild(
    el("p", { text: "Signals read from an official source (eligibility NOT verified)." })
  );
  box.appendChild(el("p", { text: "Status: " + bounty.status + "  |  Eligibility: " + bounty.eligibility }));
  box.appendChild(
    el("p", {
      class: "muted",
      text: "Source: " + bounty.source_url + " (checked " + (bounty.checked_at || "?") + ", HTTP " + (bounty.http_status ?? "?") + ")",
    })
  );
  (bounty.evidence || []).forEach((e) => {
    box.appendChild(el("div", { class: "bounty-evidence" }, [
      el("span", { class: "origin-tag", text: e.keyword }),
      el("span", { class: "mono", text: " " + e.snippet }),
    ]));
  });
  if (bounty.reminder) box.appendChild(el("p", { class: "muted", text: bounty.reminder }));
  if (bounty.error) box.appendChild(el("p", { class: "error-text", text: bounty.error }));
}

/* ---------- load ---------- */

async function loadInvestigation() {
  if (!fingerprint) {
    msg("Missing fingerprint (fp) query parameter.", true);
    return;
  }
  try {
    inv = await api(
      "/api/findings/" + encodeURIComponent(scanId) + "/investigation?fp=" + encodeURIComponent(fingerprint)
    );
  } catch (err) {
    msg("Failed to load finding: " + err.message, true);
    return;
  }
  clearMsg();
  renderHeader(inv);
  renderSummary(inv);
  renderProtocol(inv);
  renderAttacker(inv.attacker || {});
  renderDefender(inv.defender || {});
  renderProvenance(inv);
  renderFinrisk(inv.financial_risk_review);
  renderEvidence(inv.evidence || {});
  renderAi(inv.ai_analysis);
  renderUnknowns(inv.unknowns || []);
  renderHistory((inv.review && inv.review.history) || inv.review_history || []);
  renderGlossary(inv.glossary || []);
  renderBounty(inv.bounty);
  const projectField = inv.protocol && inv.protocol.fields && inv.protocol.fields.project_name;
  if (projectField && projectField.value && projectField.value.indexOf("Unknown") !== 0) {
    document.getElementById("bounty-project").value = projectField.value;
  }
}

/* ---------- financial-risk review (second stage) ---------- */

const FINRISK_VERDICT_LABEL = {
  validated_financial_risk: "Validated financial risk",
  potential_financial_risk: "Potential financial risk",
  disproved: "Disproved",
  inconclusive: "Inconclusive",
  not_financially_exploitable: "Not financially exploitable",
};

function finriskTs(ts) {
  if (ts == null) return "—";
  const d = new Date(typeof ts === "number" ? ts * 1000 : ts);
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

function finriskNotation(v) {
  return v === null || v === undefined || v === "" ? "Unknown — not recorded" : String(v);
}

function renderFinrisk(block) {
  const box = document.getElementById("inv-finrisk");
  const stateLabel = document.getElementById("inv-finrisk-state-label");
  const reviewBtn = document.getElementById("inv-finrisk-review-btn");
  const rerunBtn = document.getElementById("inv-finrisk-rerun-btn");
  clearChildren(box);
  reviewBtn.style.display = "";
  rerunBtn.style.display = "none";
  if (!block || block.state === "not_queued") {
    stateLabel.textContent = "not reviewed yet";
    box.appendChild(el("p", { class: "muted", text: (block && block.note)
      || "No financial-risk review recorded yet." }));
    return;
  }
  reviewBtn.style.display = "none";
  rerunBtn.style.display = "";

  const rv = (block.review && typeof block.review === "object") ? block.review : {};
  const fin = rv.financial || {};
  const att = rv.attacker || {};
  const val = rv.validation || {};
  const exp = (att.exposure_model && typeof att.exposure_model === "object") ? att.exposure_model : {};
  const verdict = block.verdict || rv.verdict || null;
  stateLabel.textContent = (block.state || "?").replace(/_/g, " ")
    + (verdict ? " — " + (FINRISK_VERDICT_LABEL[verdict] || verdict) : "");

  /* verdict + rationale */
  box.appendChild(section("Verdict", [
    el("p", {
      class: "mono",
      text: "state: " + (block.state || "?")
        + (verdict ? " | verdict: " + (FINRISK_VERDICT_LABEL[verdict] || verdict) : "")
        + (rv.generated_at ? " | review generated: " + rv.generated_at : "")
        + (rv.tool_version ? " | engine: " + rv.tool_version : ""),
    }),
    ...(rv.verdict_rationale ? [el("p", { text: "Rationale: " + rv.verdict_rationale })] : []),
    ...(rv.retryable ? [el("p", { class: "error-text", text: "retryable: transient failure; the queue will retry automatically" })] : []),
    ...((rv.infra_failures || []).length ? [
      el("p", { class: "muted", text: "infrastructure failures (never evidence — they force inconclusive, not disproof): " + rv.infra_failures.join("; ") }),
    ] : []),
  ]));

  /* identity + queue timestamps */
  const idn = rv.identity || {};
  box.appendChild(section("Finding identity, chain & review queue", [
    el("p", { class: "mono", text: [
      "original severity: " + finriskNotation(block.severity),
      "category: " + finriskNotation(block.category),
      "network/chain: " + finriskNotation(block.network || idn.chain),
      "contract address: " + finriskNotation(block.address || idn.address),
      "function/location: " + finriskNotation(fingerprint),
      "scan source: " + finriskNotation(block.source_path),
    ].join("  |  ") }),
    el("p", { class: "mono", text: [
      "enqueued: " + finriskTs(block.enqueued_at),
      "started: " + finriskTs(block.started_at),
      "finished: " + finriskTs(block.finished_at),
      "attempts: " + finriskNotation(block.attempts == null ? 0 : block.attempts),
      "errors: " + finriskNotation(block.error_count == null ? 0 : block.error_count),
      ...(block.heartbeat_stage ? ["last stage: " + block.heartbeat_stage + " (" + finriskTs(block.heartbeat_at) + ")"] : []),
    ].join("  |  ") }),
    el("p", { class: "muted" }, [
      el("span", { text: "Links — " }),
      el("a", { href: "/scan/" + encodeURIComponent(scanId), text: "source scan record" }),
      el("span", { text: " (this finding) — current page; fingerprint above. " }),
      ...(rv.panel ? [el("a", { href: "/monitor", text: "AI review panel outcome (monitor view)" })] : []),
    ]),
  ]));

  /* prerequisites + access control */
  box.appendChild(section("Prerequisites & access control", [
    labeledLine("Impact class", finriskNotation(att.impact_class)),
    labeledLine("Privilege gate", att.privilege_gated === true ? "privilege required (not exploitable by an outside caller)"
      : att.privilege_gated === false ? "no privilege required by recorded triage" : "Unknown — not recorded"),
    labeledLine("Caller assumption", att.unprivileged_caller_assumption),
    labeledLine("Protective note", att.protective_note === true
      ? "yes (code note says the path is protected)" : att.protective_note === false
      ? "no" : "Unknown — not recorded"),
    bulletList(att.assumptions && att.assumptions.length ? att.assumptions : ["No stored assumption was supplied."]),
  ]));

  /* exploit path */
  box.appendChild(section("Exploit path (exposure model)", exp && exp.model ? [
    labeledLine("model", exp.model),
    labeledLine("vulnerability_class", exp.vulnerability_class),
    labeledLine("exposure_factor", finriskNotation(exp.exposure_factor)),
    labeledLine("assumption", exp.assumption),
    labeledLine("origin", att.exposure_model_origin),
  ] : [el("p", { class: "muted", text: "No exposure model was derivable for this finding shape; the exploit path stays unknown — not assumed exploitable." })]));

  /* assets + loss mechanism */
  const est = fin.stored_estimate || null;
  box.appendChild(section("Assets at stake & loss mechanism", [
    labeledLine("Priced holdings basis", (fin.assets && fin.assets.length)
      ? fin.assets.length + " asset(s)" + (fin.holdings_usd != null ? ", TVL basis $" + Number(fin.holdings_usd).toLocaleString() : "")
      : "no priced holdings recorded for the audited contract"),
    ...(fin.assets && fin.assets.length ? [el("ul", { class: "inv-list" },
      fin.assets.slice(0, 12).map((a) => el("li", { html: escapeHtml(((a && (a.symbol || a.asset)) || "asset")
        + " = " + (a && a.usd != null ? "$" + Number(a.usd).toLocaleString() : "unpriced")) })))] : []),
    labeledLine("price as of", fin.price_as_of),
    labeledLine("basis origin", fin.asset_basis_origin),
    labeledLine("user funds at risk", fin.user_funds_at_risk === true ? "yes (stored estimate flags user funds)" : "no"),
    labeledLine("methodology", fin.methodology),
    ...(est ? [
      el("p", { class: "mono", text: "modeled estimate (heuristic, not a prediction): "
        + JSON.stringify({ est_loss_usd: est.est_loss_usd, low: est.low, high: est.high }) + " — " + (est.label || "") }),
      el("p", { class: "muted", text: "stored estimate origin: " + finriskNotation(fin.stored_estimate_origin)
        + " | assumptions: " + finriskNotation(est.assumptions) }),
    ] : [el("p", { class: "muted", text: "No modeled estimate was stored for this finding." })]),
  ]));

  /* validation evidence */
  const stepLine = (s) => el("li", {
    html: escapeHtml((s.stage || "?") + " [" + (s.epistemic || s.status || "?") + "]: "
      + (s.status === "not_attempted" ? "NOT ATTEMPTED — " : "")
      + finriskNotation(s.detail).slice(0, 400)),
  });
  const steps = val.steps || [];
  box.appendChild(section("Validation evidence, simulation outcome & test refs", steps.length ? [
    el("ul", { class: "inv-list" }, steps.map(stepLine)),
    ...((val.test_refs || []).length ? [
      el("p", { class: "muted", text: "test refs: " + val.test_refs.join(", ") }),
    ] : [el("p", { class: "muted", text: "No test refs were produced by these validation steps." })]),
    ...(rv.ai_opinion_count != null ? [
      el("p", { class: "muted", text: "AI opinions in the evidence base: " + rv.ai_opinion_count
        + " (AI text is never used as the deciding evidence here)" }),
    ] : []),
  ] : [el("p", { class: "muted", text: "No validation step was recorded — the verdict did not rest on validation evidence." })]));

  /* what is unknown */
  box.appendChild(section("Reasons the estimate is unknown / missing evidence", (rv.missing_evidence || []).length || (rv.unavailable_evidence || []).length ? [
    bulletList(rv.missing_evidence || []),
    bulletList(rv.unavailable_evidence || []),
  ] : [el("p", { class: "muted", text: "No recorded missing evidence (but 'validated' still requires the pipeline lab outcome — absent evidence is not a positive result)." })]));

  box.appendChild(section("Assumptions", (rv.assumptions || []).length
    ? [bulletList(rv.assumptions)]
    : [el("p", { class: "muted", text: "No assumptions were recorded." })]));

  /* errors + history */
  box.appendChild(section("Errors & state history", [
    labeledLine("last error", block.last_error || "none"),
    ...((block.history || []).length ? [
      el("ul", { class: "inv-list" }, block.history.map((h) => el("li", {
        text: (h.from_state || "?") + " → " + (h.to_state || "?")
          + (h.verdict ? " [" + h.verdict + "]" : "") + " at " + finriskTs(h.at)
          + (h.note ? " — " + h.note : ""),
      }))),
    ] : [el("p", { class: "muted", text: "No transitions recorded yet." })]),
  ]));
}

async function runFinriskReview() {
  const reviewBtn = document.getElementById("inv-finrisk-review-btn");
  const rerunBtn = document.getElementById("inv-finrisk-rerun-btn");
  const original = reviewBtn.textContent;
  reviewBtn.disabled = rerunBtn.disabled = true;
  reviewBtn.textContent = "Reviewing…";
  msg("Financial-risk review running inline under the queue lock — evidence comes from the stored finding, the monitor pipeline and (if an RPC is configured) a read-only chain call.");
  try {
    const res = await api("/api/findings/" + encodeURIComponent(scanId) + "/finrisk/run"
      + "?fp=" + encodeURIComponent(fingerprint), { method: "POST" });
    renderFinrisk(res.review || null);
    document.getElementById("inv-finrisk-card").open = true;
    const v = res.review && res.review.verdict;
    msg("Financial-risk review complete: " + (v ? (FINRISK_VERDICT_LABEL[v] || v) : (res.review && res.review.state) || "no verdict") + ". "
      + "The row is stored in the finrisk queue; the Findings page filter reflects it.");
  } catch (err) {
    msg("Financial-risk review failed: " + err.message, true);
  } finally {
    reviewBtn.disabled = rerunBtn.disabled = false;
    reviewBtn.textContent = original;
  }
}


async function applyState() {
  const state = document.getElementById("inv-state-select").value;
  const note = document.getElementById("inv-state-note").value.trim();
  clearMsg();
  try {
    const res = await api("/api/findings/" + encodeURIComponent(scanId) + "/state", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fingerprint: fingerprint, state: state, note: note || null }),
    });
    msg("State updated: " + res.message);
    document.getElementById("inv-state-note").value = "";
    await loadInvestigation();
  } catch (err) {
    msg("State change rejected: " + err.message, true);
  }
}

/* ---------- job panel (retest / AI audit) ---------- */

function renderJob(job) {
  const card = document.getElementById("inv-job-card");
  card.style.display = "";
  document.getElementById("inv-job-message").textContent =
    job.message || job.status;
  document.getElementById("inv-job-elapsed").textContent =
    job.elapsed_seconds !== null && job.elapsed_seconds !== undefined
      ? job.elapsed_seconds + "s elapsed"
      : "";

  const stagesBox = document.getElementById("inv-job-stages");
  clearChildren(stagesBox);
  (job.stages || []).forEach((s) => {
    stagesBox.appendChild(
      el("li", { class: "stage stage-" + s.status }, [
        el("span", { class: "stage-name", text: s.name }),
        badge(s.status),
        el("span", { class: "stage-detail muted", text: s.detail || "" }),
        el("span", { class: "stage-time muted", text: s.elapsed_seconds != null ? s.elapsed_seconds + "s" : "" }),
      ])
    );
  });

  const logBox = document.getElementById("inv-job-log");
  logBox.textContent = (job.log || []).join("\n") || "(no log output)";

  const resultBox = document.getElementById("inv-job-result");
  if (job.status === "completed" || job.status === "failed") {
    resultBox.style.display = "";
    clearChildren(resultBox);
    if (job.status === "failed") {
      resultBox.appendChild(el("p", { class: "error-text", text: "Failed: " + (job.error || job.message) }));
    } else if (job.report && job.report.kind === "retest") {
      const r = job.report;
      resultBox.appendChild(
        el("p", {
          text: "Retest " + r.tested_at + ": " +
            (r.persisted ? "finding PERSISTED (still detected)" : "finding NOT reproduced in re-analysis") +
            (r.state_change ? "  |  state: " + r.state_change : ""),
        })
      );
      (r.notes || []).forEach((n) => resultBox.appendChild(el("p", { class: "muted", text: n })));
    } else if (job.report && job.report.kind === "ai_audit") {
      const r = job.report;
      resultBox.appendChild(
        el("p", {
          text: "AI audit recorded as scan " + (r.scan_id || "").slice(0, 8) +
            " — " + (r.conclusions || []).length + " conclusion(s); AI: " +
            ((r.ai_analysis && r.ai_analysis.status) || "n/a") + ".",
        })
      );
      const link = el("a", { class: "btn btn-sm btn-primary", href: "/investigate/" + encodeURIComponent(r.scan_id) + "?fp=" + encodeURIComponent(fingerprint), text: "Open AI Audit Finding →" });
      resultBox.appendChild(link);
      const scanLink = el("a", { class: "btn btn-sm btn-secondary", style: "margin-left:8px;", href: "/scan/" + encodeURIComponent(r.scan_id), text: "Full Scan Overview" });
      resultBox.appendChild(scanLink);
    } else {
      resultBox.appendChild(el("p", { text: job.message || "Completed." }));
    }
  } else {
    resultBox.style.display = "none";
  }
}

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
}

async function pollJob(jobId) {
  activeJobId = jobId;
  let job;
  try {
    job = await api("/api/jobs/" + encodeURIComponent(jobId));
  } catch (err) {
    msg("Job poll failed: " + err.message, true);
    const btn = document.getElementById("inv-ai-btn");
    if (btn) btn.disabled = false;
    return;
  }
  renderJob(job);
  if (job.status === "pending" || job.status === "running") {
    const btn = document.getElementById("inv-ai-btn");
    if (btn) btn.disabled = true;
    pollTimer = setTimeout(() => pollJob(jobId), 1000);
    return;
  }
  stopPolling();
  const btn = document.getElementById("inv-ai-btn");
  if (btn) btn.disabled = false;
  if (job.status === "completed") {
    await loadInvestigation();
  }
}

async function startRetest() {
  clearMsg();
  msg("Starting retest...");
  try {
    const job = await api("/api/findings/" + encodeURIComponent(scanId) + "/retest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, fingerprint: fingerprint }),
    });
    document.getElementById("inv-job-result").style.display = "none";
    pollJob(job.job_id);
  } catch (err) {
    msg("Retest failed to start: " + err.message, true);
  }
}

async function startAiAudit() {
  clearMsg();
  const sourcePath = await resolveSourcePath();
  if (!sourcePath) {
    msg("This scan has no recorded source path, so an AI audit cannot be started.", true);
    return;
  }
  const btn = document.getElementById("inv-ai-btn");
  if (btn) btn.disabled = true;
  msg("Starting AI audit...");
  try {
    const job = await api("/api/ai-audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: sourcePath, scan_id: scanId, use_ai: true, deep_tests: false }),
    });
    document.getElementById("inv-job-result").style.display = "none";
    pollJob(job.job_id);
  } catch (err) {
    msg("AI audit failed to start: " + err.message, true);
    if (btn) btn.disabled = false;
  }
}

async function resolveSourcePath() {
  try {
    const scan = await api("/api/scans/" + encodeURIComponent(scanId));
    return scan.source_path || null;
  } catch (e) {
    return null;
  }
}

async function cancelJob() {
  stopPolling();
  try {
    await api("/api/jobs/" + encodeURIComponent(currentJobId()), { method: "DELETE" });
    msg("Cancellation requested.");
  } catch (err) {
    msg("Cancel failed: " + err.message, true);
  }
}

function currentJobId() {
  return activeJobId;
}

/* ---------- bounty ---------- */

async function runBounty() {
  clearMsg();
  try {
    const result = await api("/api/scans/" + encodeURIComponent(scanId) + "/bounty", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project_name: document.getElementById("bounty-project").value.trim() || null,
        official_url: document.getElementById("bounty-url").value.trim() || null,
      }),
    });
    renderBounty(result);
    msg("Bounty check finished: " + result.status);
  } catch (err) {
    msg("Bounty check failed: " + err.message, true);
  }
}

/* ---------- OpenCode propose / apply ---------- */

async function checkOpencode() {
  try {
    const status = await api("/api/opencode");
    const btn = document.getElementById("inv-propose-btn");
    if (status.available) {
      btn.style.display = "";
      btn.title = "OpenCode " + (status.version || "");
    }
  } catch (e) {
    /* dashboard stays usable without OpenCode */
  }
}

async function proposePatch() {
  clearMsg();
  document.getElementById("inv-propose-card").style.display = "";
  document.getElementById("propose-status").textContent = "Asking OpenCode for a proposal...";
  document.getElementById("propose-diff").style.display = "none";
  try {
    const proposal = await api("/api/findings/" + encodeURIComponent(scanId) + "/propose", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, fingerprint: fingerprint }),
    });
    if (proposal.status === "proposed") {
      currentProposal = proposal;
      document.getElementById("propose-status").textContent =
        "Proposal ready for " + proposal.relative_path + " — review the diff below. Nothing has been written.";
      const diffBox = document.getElementById("propose-diff");
      diffBox.style.display = "";
      diffBox.textContent = proposal.diff;
      document.getElementById("inv-apply-btn").style.display = "";
    } else {
      currentProposal = null;
      document.getElementById("inv-apply-btn").style.display = "none";
      document.getElementById("propose-status").textContent =
        (proposal.status || "failed") + ": " + (proposal.reason || "no proposal produced");
    }
  } catch (err) {
    document.getElementById("propose-status").textContent = "Proposal failed: " + err.message;
  }
}

async function applyProposal() {
  if (!currentProposal) return;
  const confirmed = window.confirm(
    "Apply this patch to " + currentProposal.relative_path + "?\n\n" +
    "This writes to disk. The file is hash-checked immediately before writing."
  );
  if (!confirmed) return;
  clearMsg();
  try {
    const res = await api("/api/patches/" + encodeURIComponent(currentProposal.proposal_id) + "/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        approval: true,
        expected_before_hash: currentProposal.before_hash,
      }),
    });
    msg("Applied " + res.bytes_written + " bytes to " + res.target_file + ". " + (res.note || ""));
    document.getElementById("inv-apply-btn").style.display = "none";
  } catch (err) {
    msg("Apply rejected: " + err.message, true);
  }
}

/* ---------- wire up ---------- */

document.getElementById("inv-state-apply").addEventListener("click", applyState);
document.getElementById("inv-retest-btn").addEventListener("click", startRetest);
document.getElementById("inv-ai-btn").addEventListener("click", startAiAudit);
document.getElementById("inv-bounty-btn").addEventListener("click", runBounty);
document.getElementById("bounty-run").addEventListener("click", runBounty);
document.getElementById("inv-propose-btn").addEventListener("click", proposePatch);
document.getElementById("inv-apply-btn").addEventListener("click", applyProposal);
document.getElementById("inv-job-cancel").addEventListener("click", cancelJob);
document.getElementById("inv-finrisk-review-btn").addEventListener("click", runFinriskReview);
document.getElementById("inv-finrisk-rerun-btn").addEventListener("click", runFinriskReview);

loadInvestigation();
checkOpencode();
