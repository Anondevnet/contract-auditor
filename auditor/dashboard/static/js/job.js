/* Job progress page. */

setupChrome("job");

const jobId = window.location.pathname.split("/").pop();
let jobPollTimer = null;

async function loadJob() {
  const subtitle = document.getElementById("job-subtitle");
  let job;
  try {
    job = await api("/api/jobs/" + encodeURIComponent(jobId));
  } catch (err) {
    subtitle.textContent = "Failed to load job: " + err.message;
    return;
  }

  subtitle.textContent = jobTypeLabel(job.scan_type) + " — " + job.message;
  document.getElementById("job-id").textContent = job.job_id;
  document.getElementById("job-type").textContent = jobTypeLabel(job.scan_type);

  const statusNode = document.getElementById("job-status");
  clearChildren(statusNode);
  statusNode.appendChild(badge(job.status));

  document.getElementById("job-created").textContent = fmtTime(job.created_at);
  document.getElementById("job-started").textContent = fmtTime(job.started_at);
  document.getElementById("job-completed").textContent = fmtTime(job.completed_at);

  const pct = Math.round((job.progress || 0) * 100);
  document.getElementById("job-progress-bar").style.width = pct + "%";
  document.getElementById("job-progress-text").textContent = pct + "%";
  document.getElementById("job-message").textContent = job.message || "";

  renderJobStages(job);

  document.getElementById("job-input").textContent = JSON.stringify(
    {
      scan_type: job.scan_type,
      local_path: job.local_path,
      address: job.address,
      network: job.network,
    },
    null,
    2
  );

  const outSection = document.getElementById("job-output-section");
  const errSection = document.getElementById("job-error-section");
  if (job.error) {
    errSection.style.display = "";
    document.getElementById("job-error").textContent = job.error;
  } else {
    errSection.style.display = "none";
  }

  if (job.result) {
    outSection.style.display = "";
    document.getElementById("job-output").textContent = JSON.stringify(
      {
        scan_id: job.result.scan_id,
        status: job.result.status,
        finding_count: job.result.finding_count,
        findings_by_severity: job.result.findings_by_severity,
      },
      null,
      2
    );
    const results = document.getElementById("results-section");
    results.style.display = "";
    const viewBtn = document.getElementById("view-results-btn");
    viewBtn.onclick = () => {
      window.location.href = "/scan/" + job.result.scan_id;
    };
  } else {
    outSection.style.display = "none";
  }

  if (job.status === "pending" || job.status === "running") {
    jobPollTimer = setTimeout(loadJob, 1000);
  }
}

function renderJobStages(job) {
  const section = document.getElementById("job-stages-section");
  const logSection = document.getElementById("job-log-section");
  if (!section) return;
  const stages = job.stages || [];
  const hasLog = (job.log || []).length > 0;

  section.style.display = stages.length ? "" : "none";
  if (stages.length) {
    document.getElementById("job-elapsed").textContent =
      job.elapsed_seconds !== null && job.elapsed_seconds !== undefined
        ? "(" + job.elapsed_seconds + "s)"
        : "";
    const list = document.getElementById("job-stages");
    clearChildren(list);
    stages.forEach((s) => {
      list.appendChild(
        el("li", { class: "stage stage-" + s.status }, [
          el("span", { class: "stage-name", text: s.name }),
          badge(s.status),
          el("span", { class: "stage-detail muted", text: s.detail || "" }),
          el("span", {
            class: "stage-time muted",
            text: s.elapsed_seconds != null ? s.elapsed_seconds + "s" : "",
          }),
        ])
      );
    });
  }

  logSection.style.display = hasLog ? "" : "none";
  if (hasLog) {
    document.getElementById("job-log").textContent = job.log.join("\n");
  }
}

function jobTypeLabel(t) {
  return t === "address" ? "Address Scan" : t === "local" ? "Local Scan" : t;
}

loadJob();
