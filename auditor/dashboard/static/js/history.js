/* History page. */

setupChrome("history");

const limitSelect = document.getElementById("history-limit");

async function loadHistory() {
  const body = document.getElementById("history-body");
  clearChildren(body);
  body.appendChild(
    el("tr", { class: "loading-row" }, [el("td", { colspan: "8", text: "Loading..." })])
  );
  try {
    const limit = limitSelect.value;
    const data = await api("/api/scans?limit=" + encodeURIComponent(limit));
    renderRows(data.scans || []);
  } catch (err) {
    clearChildren(body);
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "8", text: "Failed to load history: " + err.message }),
      ])
    );
  }
}

function renderRows(scans) {
  const body = document.getElementById("history-body");
  clearChildren(body);
  if (!scans.length) {
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "8", text: "No scans recorded yet." }),
      ])
    );
    return;
  }
  for (const s of scans) {
    const exportJson = el("a", {
      class: "btn btn-link btn-sm",
      href: "/api/scans/" + s.scan_id + "/report?format=json",
      text: "JSON",
    });
    const exportMd = el("a", {
      class: "btn btn-link btn-sm",
      href: "/api/scans/" + s.scan_id + "/report?format=markdown",
      text: "MD",
    });
    const actions = el("td", {}, [
      el("a", { class: "btn btn-link btn-sm", href: "/scan/" + s.scan_id, text: "View" }),
      exportJson,
      exportMd,
    ]);
    body.appendChild(
      el("tr", {}, [
        el("td", {}, [
          el("a", {
            class: "mono",
            href: "/scan/" + s.scan_id,
            text: shortId(s.scan_id),
          }),
        ]),
        el("td", { class: "mono", text: s.source_path || "—" }),
        el("td", { text: scanType(s) }),
        el("td", {}, [badge(s.status)]),
        el("td", { class: "mono", text: String(s.finding_count) }),
        el("td", { class: "mono", text: shortId(s.content_hash) }),
        el("td", { text: fmtTime(s.timestamp) }),
        actions,
      ])
    );
  }
}

function scanType(s) {
  const fp = s.config_fingerprint || "";
  if (fp.includes("address")) return "address";
  if (fp.includes("local") || fp.includes("scan")) return "local";
  return "—";
}

limitSelect.addEventListener("change", loadHistory);
loadHistory();
