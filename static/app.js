// Lynis Findings Dashboard - frontend logic

const state = {
  controls: [],
  findings: [],
  meta: {},
  view: "unresolved",
};

const LYNIS_CONTROL_BASE_URL = "https://cisofy.com/lynis/controls/";

const el = (id) => document.getElementById(id);

function severityBadgeClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s.includes("high")) return "bg-danger";
  if (s.includes("medium")) return "bg-warning text-dark";
  if (s.includes("informational")) return "bg-info text-dark";
  if (s.includes("low")) return "bg-secondary";
  return "bg-light text-dark border";
}

function kindBadgeClass(kind) {
  return kind === "warning" ? "bg-danger" : "bg-primary";
}

function buildLynisControlUrl(testId) {
  const cleanId = (testId || "").trim();
  if (!cleanId) return null;
  return `${LYNIS_CONTROL_BASE_URL}${encodeURIComponent(cleanId)}/`;
}

function showAlert(message, variant = "danger") {
  const area = el("alert-area");
  const wrapper = document.createElement("div");
  wrapper.className = `alert alert-${variant} alert-dismissible fade show`;
  wrapper.role = "alert";
  wrapper.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
  area.appendChild(wrapper);
}

async function fetchSystemInfo() {
  const elMetric = el("metric-lynis-installed");
  try {
    const res = await fetch("/api/system-info");
    const data = await res.json();
    if (data.installed) {
      elMetric.textContent = data.version || "Yes";
      elMetric.classList.remove("text-danger");
      elMetric.classList.add("text-success");
      elMetric.title = data.path ? `Found at ${data.path}` : "";
    } else {
      elMetric.textContent = "N/A";
      elMetric.classList.remove("text-success");
      elMetric.classList.add("text-danger");
      elMetric.title = "lynis was not found on PATH";
    }
  } catch (err) {
    elMetric.textContent = "?";
    elMetric.title = `Could not check: ${err}`;
  }
}

function updateMetrics() {
  const meta = state.meta || {};
  el("metric-hardening").textContent = meta.hardening_index ? `${meta.hardening_index}/100` : "–";
  el("metric-tests").textContent = meta.lynis_tests_done || "–";

  const total = state.findings.length;
  const exempted = state.findings.filter((f) => f.exempted).length;
  el("metric-open").textContent = total - exempted;
  el("metric-exempted").textContent = exempted;

  const scanMeta = el("scan-meta");
  const parts = [];
  if (meta.hostname) parts.push(meta.hostname);
  if (meta.os_fullname) parts.push(meta.os_fullname);
  if (meta.lynis_version) parts.push(`Lynis ${meta.lynis_version}`);
  if (meta.report_datetime_end) parts.push(`Scanned ${meta.report_datetime_end}`);
  scanMeta.textContent = parts.join(" · ");
}

function getVisibleControls() {
  if (state.view === "remediated") {
    return state.controls.filter((c) => c.control_status === "remediated");
  }
  if (state.view === "exempted") {
    return state.controls.filter((c) => c.exempted);
  }
  if (state.view === "all") {
    return state.controls;
  }
  return state.controls.filter((c) => c.control_status === "unresolved");
}

function isEnableMode() {
  return state.view === "exempted";
}

function updateActionModeUI() {
  const actionLabel = el("action-label");
  const button = el("btn-exempt");
  const reasonInput = el("reason-input");

  if (isEnableMode()) {
    actionLabel.textContent = "Enable Selected";
    button.classList.remove("btn-warning");
    button.classList.add("btn-success");
    reasonInput.disabled = true;
    reasonInput.placeholder = "Reason not required when enabling controls";
  } else {
    actionLabel.textContent = "Exempt Selected";
    button.classList.remove("btn-success");
    button.classList.add("btn-warning");
    reasonInput.disabled = false;
    reasonInput.placeholder = "Reason for accepting risk (optional)";
  }
}

function renderTable() {
  const tbody = el("findings-body");
  tbody.innerHTML = "";
  const visibleControls = getVisibleControls();

  if (visibleControls.length === 0) {
    const emptyMessage = state.view === "unresolved"
      ? "No unresolved findings parsed from the report."
      : (state.view === "remediated"
          ? "No remediated controls found in the current catalog."
          : (state.view === "exempted"
              ? "No exempted controls found."
              : "No controls available."));
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4">${emptyMessage}</td></tr>`;
    return;
  }

  for (const finding of visibleControls) {
    const tr = document.createElement("tr");
    if (finding.exempted) {
      tr.classList.add("table-secondary", "row-exempted");
    }
    const testUrl = buildLynisControlUrl(finding.test_id);

    const description = finding.descriptions && finding.descriptions.length
      ? finding.descriptions.join("; ")
      : "(no description available)";

    const statusHtml = finding.control_status === "remediated"
      ? `<span class="badge bg-success">remediated</span>`
      : (finding.control_status === "exempted"
          ? `<span class="badge bg-secondary" title="Exempted in custom.prf; this control may not be assessed during scans.">exempted</span>`
          : finding.exempted
      ? `
        <div class="form-check form-switch mb-0">
          <input class="form-check-input unexempt-toggle" type="checkbox" role="switch"
            data-test-id="${finding.test_id}" checked>
          <label class="form-check-label small text-success">Exempted</label>
        </div>`
      : (finding.partial_exemptions && finding.partial_exemptions.length
          ? `<span class="badge bg-info text-dark" title="${finding.partial_exemptions.join(', ')}">Partial exemption</span>`
          : `<span class="badge ${kindBadgeClass(finding.kind)}">${finding.kind}</span>`));

    const canSelectForExemption = isEnableMode()
      ? finding.exempted
      : (finding.control_status === "unresolved" && !finding.exempted);

    tr.innerHTML = `
      <td>
        <input type="checkbox" class="form-check-input row-check" data-test-id="${finding.test_id}"
          ${canSelectForExemption ? "" : "disabled"}>
      </td>
      <td>
        ${testUrl
          ? `<a href="${testUrl}" target="_blank" rel="noopener noreferrer" title="Open ${finding.test_id} at cisofy.com"><code>${finding.test_id}</code></a>`
          : `<code>${finding.test_id}</code>`}
      </td>
      <td>${finding.category}</td>
      <td>${description}</td>
      <td><span class="badge ${severityBadgeClass(finding.severity)}">${finding.severity}</span></td>
      <td class="small">${finding.impact}</td>
      <td class="small"><code class="text-wrap">${finding.remediation}</code></td>
      <td class="small">${finding.explanation}</td>
      <td>${statusHtml}</td>
    `;
    tbody.appendChild(tr);
  }

  document.querySelectorAll(".row-check").forEach((cb) => {
    cb.addEventListener("change", updateSelectionState);
  });

  document.querySelectorAll(".unexempt-toggle").forEach((toggle) => {
    toggle.addEventListener("change", onUnexemptToggle);
  });
}

async function onUnexemptToggle(e) {
  const toggle = e.target;
  const testId = toggle.dataset.testId;

  if (toggle.checked) {
    // Switches only start checked (exempted); re-checking is a no-op guard.
    return;
  }

  const confirmed = window.confirm(
    `Remove the exemption for ${testId}? It will be included in future Lynis scans again.`
  );
  if (!confirmed) {
    toggle.checked = true;
    return;
  }

  toggle.disabled = true;
  try {
    const res = await fetch("/api/unexempt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_ids: [testId] }),
    });
    const data = await res.json();
    if (!res.ok) {
      showAlert(data.error || "Failed to remove exemption.");
      toggle.checked = true;
      toggle.disabled = false;
      return;
    }
    showAlert(`Removed exemption for ${testId}. It will be scanned again next run.`, "success");
    await fetchFindings();
  } catch (err) {
    showAlert(`Could not reach the backend: ${err}`);
    toggle.checked = true;
    toggle.disabled = false;
  }
}

function updateSelectionState() {
  const checked = document.querySelectorAll(".row-check:checked");
  el("selected-count").textContent = checked.length;
  el("btn-exempt").disabled = checked.length === 0;
}

async function fetchFindings() {
  el("findings-body").innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4">Loading findings…</td></tr>`;
  try {
    const res = await fetch("/api/findings");
    const data = await res.json();
    if (!res.ok) {
      showAlert(data.error || "Failed to load findings.");
      el("findings-body").innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">${data.error || "Failed to load findings."}</td></tr>`;
      return;
    }
    state.findings = data.findings || [];
    state.controls = data.controls || state.findings;
    state.meta = data.meta || {};
    renderTable();
    updateMetrics();
    updateSelectionState();
  } catch (err) {
    showAlert(`Could not reach the backend: ${err}`);
  }
}

async function exemptSelected() {
  const checked = Array.from(document.querySelectorAll(".row-check:checked"));
  const testIds = checked.map((cb) => cb.dataset.testId);
  if (testIds.length === 0) return;

  if (isEnableMode()) {
    el("btn-exempt").disabled = true;
    try {
      const res = await fetch("/api/unexempt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_ids: testIds }),
      });
      const data = await res.json();
      if (!res.ok) {
        showAlert(data.error || "Failed to enable selected controls.");
        return;
      }
      const removedCount = (data.removed || []).length;
      showAlert(
        `Enabled ${removedCount} control(s); they will be included in future scans.` +
          (data.not_found && data.not_found.length
            ? ` (${data.not_found.length} were not currently exempted.)`
            : ""),
        "success"
      );
      await fetchFindings();
    } catch (err) {
      showAlert(`Could not reach the backend: ${err}`);
    }
    return;
  }

  const reason = el("reason-input").value || "Accepted risk";

  el("btn-exempt").disabled = true;
  try {
    const res = await fetch("/api/exempt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test_ids: testIds, reason }),
    });
    const data = await res.json();
    if (!res.ok) {
      showAlert(data.error || "Failed to update custom.prf.");
      return;
    }
    const addedCount = (data.added || []).length;
    showAlert(
      `Added ${addedCount} exemption(s) to ${data.custom_profile_path}.` +
        (data.already_exempt && data.already_exempt.length
          ? ` (${data.already_exempt.length} were already exempted.)`
          : ""),
      "success"
    );
    el("reason-input").value = "";
    await fetchFindings();
  } catch (err) {
    showAlert(`Could not reach the backend: ${err}`);
  }
}

el("chk-select-all").addEventListener("change", (e) => {
  document.querySelectorAll(".row-check:not(:disabled)").forEach((cb) => {
    cb.checked = e.target.checked;
  });
  updateSelectionState();
});

el("btn-exempt").addEventListener("click", exemptSelected);
el("btn-refresh").addEventListener("click", () => {
  fetchFindings();
  fetchSystemInfo();
});

el("view-filter").addEventListener("change", (e) => {
  state.view = e.target.value || "unresolved";
  el("chk-select-all").checked = false;
  updateActionModeUI();
  renderTable();
  updateSelectionState();
});

updateActionModeUI();
fetchSystemInfo();
fetchFindings();

