let currentRows = [];

const $ = (id) => document.getElementById(id);

function setStatus(text) {
  $("statusBadge").textContent = text;
}

function renderBars(containerId, data) {
  const container = $(containerId);
  container.innerHTML = "";
  const max = Math.max(1, ...Object.values(data));
  Object.entries(data).forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-label">${label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div>
      <strong>${value}</strong>
    `;
    container.appendChild(row);
  });
}

function renderTable(rows) {
  const tbody = $("assetTable");
  tbody.innerHTML = "";
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.asset_id}</td>
      <td>${row.hostname}</td>
      <td><strong>${row.q_risk_score}</strong></td>
      <td><span class="level ${row.risk_level}">${row.risk_level}</span></td>
      <td>${row.public_key_algorithm || "unknown"}</td>
      <td>${row.exposure || ""}</td>
      <td>${row.action_due}</td>
    `;
    tr.addEventListener("click", () => renderDetail(row));
    tbody.appendChild(tr);
    if (index === 0) renderDetail(row);
  });
}

function renderDetail(row) {
  $("assetDetail").innerHTML = `
    <div class="detail-card">
      <div><strong>${row.asset_id} · ${row.hostname}</strong></div>
      <div>Score: <strong>${row.q_risk_score}</strong> / Level: <span class="level ${row.risk_level}">${row.risk_level}</span></div>
      <div>Algorithm: <code>${row.public_key_algorithm || "unknown"}</code> · TLS: <code>${row.tls_version || "n/a"}</code> · Expiry: <code>${row.days_to_expiry ?? "unknown"} days</code></div>
      <div>Reason codes: <code>${row.reason_codes || ""}</code></div>
      <div><strong>Recommendation</strong><br>${row.recommendation}</div>
      <div><strong>DoD</strong><br>${row.dod}</div>
    </div>
  `;
}

function renderPayload(payload) {
  currentRows = payload.rows || [];
  $("totalAssets").textContent = payload.summary.total_assets;
  $("criticalHigh").textContent = payload.summary.critical_high;
  $("avgScore").textContent = payload.summary.average_score;
  $("topAsset").textContent = payload.summary.top_asset || "-";
  renderBars("levelChart", payload.levels || {});
  renderBars("algorithmChart", payload.algorithms || {});
  renderTable(currentRows);
  setStatus("분석 완료");
}

async function runSample() {
  setStatus("분석 중");
  const res = await fetch("/api/sample");
  const payload = await res.json();
  renderPayload(payload);
}

$("runSample").addEventListener("click", runSample);

$("uploadForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("업로드 분석 중");
  const formData = new FormData(event.target);
  const res = await fetch("/api/analyze", { method: "POST", body: formData });
  const payload = await res.json();
  if (!res.ok) {
    setStatus("오류");
    alert(payload.error || "Analysis failed");
    return;
  }
  renderPayload(payload);
});

runSample().catch(() => setStatus("초기 분석 실패"));
