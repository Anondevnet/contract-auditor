/* Tool status page. */

setupChrome("tools");

async function loadTools() {
  const body = document.getElementById("tools-body");
  clearChildren(body);
  body.appendChild(
    el("tr", { class: "loading-row" }, [el("td", { colspan: "5", text: "Loading..." })])
  );

  try {
    const data = await api("/api/tools");
    renderTools(data.toolchain || {});
    renderOllama(data.ollama || {});
    renderStorage(data.storage || {});
  } catch (err) {
    clearChildren(body);
    body.appendChild(
      el("tr", { class: "empty-row" }, [
        el("td", { colspan: "5", text: "Failed to load tool status: " + err.message }),
      ])
    );
  }
}

function renderTools(toolchain) {
  const body = document.getElementById("tools-body");
  clearChildren(body);
  const tools = toolchain.tools || [];
  if (!tools.length) {
    body.appendChild(
      el("tr", { class: "empty-row" }, [el("td", { colspan: "5", text: "No tools detected." })])
    );
    return;
  }
  for (const t of tools) {
    const available = t.available ? "AVAILABLE" : "MISSING";
    body.appendChild(
      el("tr", {}, [
        el("td", { text: t.display_name || t.key || "—" }),
        el("td", {}, [badge(available)]),
        el("td", { class: "mono", text: t.version || "—" }),
        el("td", { class: "mono", text: t.path || "—" }),
        el("td", { class: "muted", text: (t.notes || []).join("; ") || (t.error || "") }),
      ])
    );
  }
}

function renderOllama(ollama) {
  setText("ollama-endpoint", ollama.endpoint || "—");

  const reachable = document.getElementById("ollama-reachable");
  clearChildren(reachable);
  reachable.appendChild(badge(ollama.reachable ? "AVAILABLE" : "MISSING"));

  const models = ollama.models || [];
  setText(
    "ollama-models",
    models.length ? models.map((m) => m.name).join(", ") : "none found"
  );
  setText("ollama-selected", ollama.selected_model || "—");
}

function renderStorage(storage) {
  const disk = storage.disk || {};
  setText("storage-total", disk.total_human || "—");
  setText("storage-free", disk.free_human || "—");
  const project = storage.project || {};
  setText("storage-project", project.human || "—");
}

document.getElementById("refresh-tools-btn").addEventListener("click", loadTools);
loadTools();
