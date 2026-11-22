/* Vulnerability detection benchmark page (Phase 14). */

setupChrome("benchmark");

function fmtMetric(v) {
  if (v === null || v === undefined) return "n/a";
  if (typeof v === "number") return v.toFixed(3);
  return String(v);
}

function showError(message) {
  document.getElementById("bench-empty").style.display = "none";
  document.getElementById("bench-content").style.display = "none";
  const box = document.getElementById("bench-error");
  box.style.display = "";
  setText("bench-error-text", message);
}

function renderRun(run) {
  document.getElementById("bench-error").style.display = "none";
  document.getElementById("bench-empty").style.display = "none";
  document.getElementById("bench-content").style.display = "";

  setText("bench-run-id", run.run_id || "-");
  clearChildren(document.getElementById("bench-status"));
  document.getElementById("bench-status").appendChild(badge(run.status || "unknown"));
  setText("bench-started", fmtTime(run.started_at));
  setText("bench-finished", fmtTime(run.finished_at));
  const totals = run.totals || {};
  setText(
    "bench-duration",
    totals.duration_seconds !== undefined ? totals.duration_seconds + "s" : "-"
  );
  const tc = run.toolchain || {};
  const tools = Object.keys(tc)
    .filter((k) => tc[k] && typeof tc[k] === "object")
    .map((k) => k + "=" + (tc[k].version || "unavailable"))
    .join(" | ");
  setText("bench-toolchain", tools || "-");
  setText("bench-store", run.store ? "store: " + run.store : "");
  setText(
    "bench-fixtures-count",
    totals.fixtures !== undefined ? totals.fixtures + " fixtures" : ""
  );

  const overall = (run.metrics || {}).overall || {};
  setText("bench-precision", fmtMetric(overall.precision));
  setText("bench-recall", fmtMetric(overall.recall));
  setText("bench-f1", fmtMetric(overall.f1));
  setText("bench-tp", String(overall.tp ?? "-"));
  setText("bench-fp", String(overall.fp ?? "-"));
  setText("bench-fn", String(overall.fn ?? "-"));
  setText("bench-tn", String(overall.tn ?? "-"));
  setText(
    "bench-excluded",
    "Excluded from scoring: blocked=" + (overall.blocked ?? 0) +
      " not_evaluable=" + (overall.not_evaluable ?? 0) +
      " skipped=" + (overall.skipped ?? 0) +
      " pipeline_failure=" + (overall.pipeline_failure ?? 0) +
      " harness_error=" + (overall.harness_error ?? 0) +
      " | observations: metadata_gaps=" + (overall.metadata_gaps ?? 0) +
      " evidence_insufficient=" + (overall.evidence_insufficient ?? 0) +
      " other_findings=" + (overall.other_findings ?? 0)
  );

  // Per-category
  const cats = document.getElementById("bench-categories");
  clearChildren(cats);
  const categories = (run.metrics || {}).categories || {};
  const catNames = Object.keys(categories).sort();
  if (!catNames.length) {
    cats.appendChild(
      el("tr", { class: "empty-row" }, [el("td", { colspan: "10", text: "No category data." })])
    );
  }
  for (const name of catNames) {
    const m = categories[name];
    cats.appendChild(
      el("tr", {}, [
        el("td", { class: "mono", text: name }),
        el("td", { text: String(m.fixtures ?? 0) }),
        el("td", { text: String(m.evaluable ?? 0) }),
        el("td", { text: String(m.tp ?? 0) }),
        el("td", { text: String(m.fp ?? 0) }),
        el("td", { text: String(m.fn ?? 0) }),
        el("td", { text: String(m.tn ?? 0) }),
        el("td", { class: "mono", text: fmtMetric(m.precision) }),
        el("td", { class: "mono", text: fmtMetric(m.recall) }),
        el("td", { class: "mono", text: fmtMetric(m.f1) }),
      ])
    );
  }

  // Fixture results
  const rows = document.getElementById("bench-results");
  clearChildren(rows);
  const results = run.results || [];
  if (!results.length) {
    rows.appendChild(
      el("tr", { class: "empty-row" }, [el("td", { colspan: "8", text: "No fixture results." })])
    );
  }
  for (const r of results) {
    const statusCell = el("td", {}, [badge(r.status || "unknown")]);
    const verdictCell = el("td", {}, [r.verdict ? badge(r.verdict) : el("span", { class: "muted", text: "-" })]);
    const note = r.reason || r.na_reason || "";
    rows.appendChild(
      el("tr", {}, [
        el("td", { class: "mono", text: r.fixture_id || "-" }),
        el("td", { class: "mono", text: r.category || "-" }),
        el("td", { text: r.expected_label || "-" }),
        statusCell,
        verdictCell,
        el("td", { class: "mono", text: r.matched_check || "-" }),
        el("td", { text: String((r.other_findings || []).length) }),
        el("td", { class: "muted", text: note }),
      ])
    );
  }
}

async function loadRun(runId) {
  try {
    const data = runId
      ? await api("/api/benchmark/runs/" + encodeURIComponent(runId))
      : await api("/api/benchmark/latest");
    if (!runId && data && data.status === "empty") {
      document.getElementById("bench-content").style.display = "none";
      document.getElementById("bench-error").style.display = "none";
      document.getElementById("bench-empty").style.display = "";
      return;
    }
    renderRun(data);
  } catch (err) {
    showError("Failed to load benchmark run: " + err.message);
  }
}

async function loadRuns() {
  const body = document.getElementById("bench-runs");
  clearChildren(body);
  body.appendChild(
    el("tr", { class: "loading-row" }, [el("td", { colspan: "7", text: "Loading..." })])
  );
  try {
    const data = await api("/api/benchmark/runs");
    clearChildren(body);
    const runs = data.runs || [];
    if (!runs.length) {
      body.appendChild(
        el("tr", { class: "empty-row" }, [
          el("td", { colspan: "7", text: "No benchmark runs recorded yet." }),
        ])
      );
      return;
    }
    for (const r of runs) {
      const link = el("a", { class: "mono", href: "#", text: r.run_id });
      link.addEventListener("click", (ev) => {
        ev.preventDefault();
        loadRun(r.run_id);
      });
      const t = r.totals || {};
      body.appendChild(
        el("tr", {}, [
          el("td", {}, [link]),
          el("td", { text: fmtTime(r.finished_at) }),
          el("td", {}, [badge(r.status || "unknown")]),
          el("td", { text: String(t.tp ?? "-") }),
          el("td", { text: String(t.fp ?? "-") }),
          el("td", { text: String(t.fn ?? "-") }),
          el("td", { text: String(t.tn ?? "-") }),
        ])
      );
    }
  } catch (err) {
    clearChildren(body);
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "7", text: "Failed to load run history: " + err.message }),
      ])
    );
  }
}

async function loadComparison() {
  const card = document.getElementById("bench-compare-card");
  const show = () => { card.style.display = ""; };
  const reset = () => {
    setText("bench-compare-baseline", "-");
    clearChildren(document.getElementById("bench-compare-comparable"));
    document.getElementById("bench-compare-comparable").appendChild(el("span", { class: "muted", text: "-" }));
    setText("bench-compare-dp", "-");
    setText("bench-compare-dr", "-");
    setText("bench-compare-df", "-");
    clearChildren(document.getElementById("bench-compare-regressions"));
    document.getElementById("bench-compare-regressions").appendChild(el("span", { class: "muted", text: "-" }));
    setText("bench-compare-note", "");
    setText("bench-compare-reason", "");
    clearChildren(document.getElementById("bench-compare-changes"));
  };
  reset();
  try {
    const data = await api("/api/benchmark/compare");
    if (data.status === "empty") {
      card.style.display = "none";
      return;
    }
    show();
    if (data.status === "no_baseline") {
      setText(
        "bench-compare-reason",
        "No baseline stored. Run `python3 audit.py benchmark --set-baseline` to record one (PROTOCOL §9.6)."
      );
      return;
    }
    const c = data.comparison || {};
    setText("bench-compare-baseline", c.baseline_run_id || "-");
    setText(
      "bench-compare-note",
      data.current_run_id ? "current: " + data.current_run_id : ""
    );
    const comparableCell = document.getElementById("bench-compare-comparable");
    clearChildren(comparableCell);
    comparableCell.appendChild(badge(c.comparable ? "comparable" : "not-comparable"));
    const d = c.metric_deltas || {};
    setText("bench-compare-dp", d.precision != null ? (d.precision >= 0 ? "+" : "") + d.precision.toFixed(4) : "n/a");
    setText("bench-compare-dr", d.recall != null ? (d.recall >= 0 ? "+" : "") + d.recall.toFixed(4) : "n/a");
    setText("bench-compare-df", d.f1 != null ? (d.f1 >= 0 ? "+" : "") + d.f1.toFixed(4) : "n/a");
    const regCell = document.getElementById("bench-compare-regressions");
    clearChildren(regCell);
    const regs = c.regressions || [];
    regCell.appendChild(badge(regs.length ? String(regs.length) : "0", regs.length ? "regression" : ""));
    if (!c.comparable) {
      setText(
        "bench-compare-reason",
        "Not like-for-like: " + (c.not_comparable_reason || "comparison unavailable") +
          " — verdict and metric judgments are suppressed (PROTOCOL §9.6)."
      );
      return;
    }
    const changes = c.verdict_changes || [];
    if (!changes.length) {
      setText("bench-compare-reason", "No verdict changes on common fixtures.");
    } else {
      setText("bench-compare-reason", changes.length + " verdict change(s) on common fixtures:");
    }
    const list = document.getElementById("bench-compare-changes");
    clearChildren(list);
    for (const ch of changes) {
      const mark = ch.regression ? " [REGRESSION]" : "";
      list.appendChild(
        el("li", { class: ch.regression ? "regression-line" : "", text: ch.fixture_id + ": " + ch.from + " -> " + ch.to + mark })
      );
    }
  } catch (err) {
    setText("bench-compare-reason", "Failed to load baseline comparison: " + err.message);
  }
}

loadRun(null);
loadRuns();
loadComparison();
