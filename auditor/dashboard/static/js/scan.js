/* New scan page: tabs, submission, job progress polling. */

setupChrome("scan");

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

const modal = document.getElementById("job-modal");
const closeModal = document.getElementById("job-modal-close");
const closeBtn = document.getElementById("modal-close-btn");
const viewResultsBtn = document.getElementById("modal-view-results");

let pollTimer = null;
let currentJob = null;

function openModal() {
  modal.classList.add("open");
}
function hideModal() {
  modal.classList.remove("open");
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}
closeModal.addEventListener("click", hideModal);
closeBtn.addEventListener("click", hideModal);
viewResultsBtn.addEventListener("click", () => {
  if (currentJob && currentJob.result && currentJob.result.scan_id) {
    window.location.href = "/scan/" + currentJob.result.scan_id;
  }
});

function renderStages(job) {
  const list = document.getElementById("modal-job-stages");
  if (!list) return;
  clearChildren(list);
  const stages = (job && job.stages) || [];
  stages.forEach((stage) => {
    const li = el("li", { class: "job-stage" }, [
      badge(stage.status || "unknown"),
      el("span", { class: "stage-name", text: stage.name || "" }),
      el("span", { class: "stage-message", text: stage.message || "" }),
    ]);
    list.appendChild(li);
  });
}

function startPolling(jobId, jobType) {
  document.getElementById("modal-job-type").textContent = jobType;
  document.getElementById("modal-job-id").textContent = jobId;
  viewResultsBtn.style.display = "none";
  document.getElementById("job-output").textContent = "";
  renderStages({ stages: [] });
  openModal();

  pollTimer = setInterval(async () => {
    try {
      const job = await api("/api/jobs/" + jobId);
      currentJob = job;
      const pct = Math.round((job.progress || 0) * 100);
      document.getElementById("modal-progress-bar").style.width = pct + "%";
      document.getElementById("modal-progress-text").textContent = pct + "% — " + (job.message || "");
      const statusNode = document.getElementById("modal-job-status");
      clearChildren(statusNode);
      statusNode.appendChild(badge(job.status));
      renderStages(job);

      if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
        clearInterval(pollTimer);
        pollTimer = null;
        const out = document.getElementById("job-output");
        if (job.status === "failed") {
          out.textContent = "Error: " + (job.error || "unknown failure");
          out.style.color = "var(--danger)";
        } else if (job.result) {
          let text =
            "Scan " + (job.result.scan_id || "").slice(0, 8) +
            " — " + job.result.finding_count + " finding(s)";
          const tools = job.result.tool_runs || [];
          if (tools.length) {
            text += "\n" + tools
              .map((t) => (t.label || t.key) + ": " + t.status)
              .join("\n");
          }
          if (job.result.scan_complete === false) {
            text += "\nSome checks did not complete — see the scan's tool status.";
          }
          out.textContent = text;
          out.style.whiteSpace = "pre-line";
          out.style.color = job.result.scan_complete === false ? "var(--danger)" : "";
          viewResultsBtn.style.display = "";
        }
      }
    } catch (err) {
      clearInterval(pollTimer);
      pollTimer = null;
      const out = document.getElementById("job-output");
      out.textContent = "Failed to poll job: " + err.message;
      out.style.color = "var(--danger)";
    }
  }, 700);
}

async function submitScan(body, button, jobType) {
  button.disabled = true;
  try {
    const job = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    startPolling(job.job_id, jobType);
  } catch (err) {
    alert("Failed to start scan: " + err.message);
  } finally {
    button.disabled = false;
  }
}

document.getElementById("local-scan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const path = document.getElementById("local-path").value.trim();
  if (!path) return;
  submitScan(
    {
      scan_type: "local",
      local: {
        path: path,
        validate_project: document.getElementById("validate-project").checked,
        run_static_analysis: document.getElementById("run-static-analysis").checked,
        run_tests: document.getElementById("run-tests").checked,
      },
    },
    document.getElementById("local-scan-btn"),
    "Local Scan"
  );
});

const addressInput = document.getElementById("contract-address");
const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

document.getElementById("address-scan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const address = addressInput.value.trim();
  if (!ADDRESS_RE.test(address)) {
    addressInput.setCustomValidity("Enter a 0x-prefixed 40-hex-character address");
    addressInput.reportValidity();
    return;
  }
  addressInput.setCustomValidity("");
  submitScan(
    {
      scan_type: "address",
      address: { network: "ethereum", address: address },
    },
    document.getElementById("address-scan-btn"),
    "Address Scan"
  );
});

addressInput.addEventListener("input", () => addressInput.setCustomValidity(""));
