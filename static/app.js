// Lynis Findings Dashboard - frontend logic

const state = {
  findings: [],
  meta: {},
};

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

function showAlert(message, variant = "danger") {
  const area = el("alert-area");
  const wrapper = document.createElement("div");
  wrapper.className = `alert alert-${variant} alert-dismissible fade show`;
  wrapper.role = "alert";
  wrapper.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
  area.appendChild(wrapper);
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

function renderTable() {
  const tbody = el("findings-body");
  tbody.innerHTML = "";

  if (state.findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4">No findings parsed from the report.</td></tr>`;
    return;
  }

  for (const finding of state.findings) {
    const tr = document.createElement("tr");
    if (finding.exempted) {
      tr.classList.add("table-secondary", "row-exempted");
    }

    const description = finding.descriptions && finding.descriptions.length
      ? finding.descriptions.join("; ")
      : "(no description available)";

    const statusHtml = finding.exempted
      ? `
        <div class="form-check form-switch mb-0">
          <input class="form-check-input unexempt-toggle" type="checkbox" role="switch"
            data-test-id="${finding.test_id}" checked>
          <label class="form-check-label small text-success">Exempted</label>
        </div>`
      : (finding.partial_exemptions && finding.partial_exemptions.length
          ? `<span class="badge bg-info text-dark" title="${finding.partial_exemptions.join(', ')}">Partial exemption</span>`
          : `<span class="badge ${kindBadgeClass(finding.kind)}">${finding.kind}</span>`);

    tr.innerHTML = `
      <td>
        <input type="checkbox" class="form-check-input row-check" data-test-id="${finding.test_id}"
          ${finding.exempted ? "disabled" : ""}>
      </td>
      <td><code>${finding.test_id}</code></td>
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
el("btn-refresh").addEventListener("click", fetchFindings);

fetchFindings();
