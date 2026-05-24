let currentRows = [];

const $ = (id) => document.getElementById(id);
const allowedLevels = new Set(["Critical", "High", "Medium", "Low"]);

// 위험등급 한국어 레이블
const levelLabels = {
  Critical: "심각",
  High: "높음",
  Medium: "보통",
  Low: "낮음",
};

function safeText(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

function levelClass(level) {
  return allowedLevels.has(level) ? level : "Low";
}

function levelLabel(level) {
  return levelLabels[level] || level || "낮음";
}

function setStatus(text) {
  $("statusBadge").textContent = text;
}

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function appendText(parent, tag, text, className) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = safeText(text);
  parent.appendChild(el);
  return el;
}

// 세미콜론으로 구분된 reason_codes 문자열을 개별 토큰 배열로 분리
function splitReasonCodes(raw) {
  return safeText(raw)
    .split(";")
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
}

// 막대 차트 렌더링. options.colorByLevel=true 이면 등급 색상 적용,
// options.labelMap 으로 라벨을 한국어로 치환할 수 있다.
function renderBars(containerId, data, options = {}) {
  const container = $(containerId);
  clearNode(container);
  const entries = Object.entries(data || {});
  const values = entries.map(([, value]) => Number(value));
  const max = Math.max(1, ...values);

  if (!entries.length) {
    appendText(container, "div", "표시할 데이터가 없습니다.", "muted");
    return;
  }

  entries.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "bar-row";

    const labelText = options.labelMap && options.labelMap[label] ? options.labelMap[label] : label;
    appendText(row, "div", labelText, "bar-label");

    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    if (options.colorByLevel && allowedLevels.has(label)) {
      fill.classList.add(`lvl-${label}`);
    }
    fill.style.width = `${(Number(value) / max) * 100}%`;
    track.appendChild(fill);
    row.appendChild(track);

    appendText(row, "strong", value, "bar-value");
    container.appendChild(row);
  });
}

function td(text, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = safeText(text);
  return cell;
}

function renderTable(rows) {
  const tbody = $("assetTable");
  clearNode(tbody);
  clearNode($("assetDetail"));
  $("assetDetail").className = "detail-empty muted";
  $("assetDetail").textContent = "자산 행을 선택하거나 샘플 분석을 실행하세요.";

  if (!rows.length) {
    const tr = document.createElement("tr");
    const cell = td("분석 결과가 없습니다.");
    cell.colSpan = 7;
    cell.style.textAlign = "center";
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return;
  }

  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    tr.appendChild(td(row.asset_id, "col-id"));
    tr.appendChild(td(row.hostname, "col-host"));

    const score = document.createElement("td");
    score.className = "col-score";
    appendText(score, "strong", row.q_risk_score);
    tr.appendChild(score);

    const levelCell = document.createElement("td");
    const badge = appendText(levelCell, "span", levelLabel(row.risk_level), `level lvl-${levelClass(row.risk_level)}`);
    badge.setAttribute("aria-label", `위험등급 ${levelLabel(row.risk_level)}`);
    tr.appendChild(levelCell);

    tr.appendChild(td(row.public_key_algorithm || "unknown"));
    tr.appendChild(td(row.exposure || ""));
    tr.appendChild(td(row.action_due));

    tr.addEventListener("click", () => {
      selectRow(tr);
      renderDetail(row);
    });
    tbody.appendChild(tr);
    if (index === 0) {
      selectRow(tr);
      renderDetail(row);
    }
  });
}

function selectRow(tr) {
  const tbody = $("assetTable");
  Array.from(tbody.querySelectorAll("tr.is-selected")).forEach((r) => r.classList.remove("is-selected"));
  tr.classList.add("is-selected");
}

function addMetric(grid, label, value) {
  const metric = document.createElement("div");
  metric.className = "metric";
  appendText(metric, "span", label, "metric-label");
  appendText(metric, "span", value, "metric-value");
  grid.appendChild(metric);
}

function renderDetail(row) {
  const root = $("assetDetail");
  root.className = "";
  clearNode(root);

  const card = document.createElement("div");
  card.className = "detail-card";

  // 헤더: 자산 ID · 호스트명 + 등급 배지
  const header = document.createElement("div");
  header.className = "detail-header";
  appendText(header, "span", `${safeText(row.asset_id)} · ${safeText(row.hostname)}`, "detail-host");
  appendText(header, "span", levelLabel(row.risk_level), `level lvl-${levelClass(row.risk_level)}`);
  card.appendChild(header);

  // 메트릭 타일: 점수 / 등급 / 알고리즘 / TLS버전 / 만료일 / Evidence ID
  const grid = document.createElement("div");
  grid.className = "metric-grid";
  addMetric(grid, "Q-Risk 점수", row.q_risk_score);
  addMetric(grid, "위험 등급", `${levelLabel(row.risk_level)} (${safeText(row.risk_level)})`);
  addMetric(grid, "공개키 알고리즘", row.public_key_algorithm || "unknown");
  addMetric(grid, "TLS 버전", row.tls_version || "n/a");
  addMetric(grid, "인증서 만료", row.days_to_expiry === null || row.days_to_expiry === undefined ? "unknown" : `${row.days_to_expiry}일`);
  addMetric(grid, "Evidence ID", row.evidence_id || "-");
  card.appendChild(grid);

  // 위험 코드 태그 칩
  const codes = splitReasonCodes(row.reason_codes);
  const codeBlock = document.createElement("div");
  codeBlock.className = "detail-block";
  appendText(codeBlock, "h3", "위험 코드");
  if (codes.length) {
    const chipRow = document.createElement("div");
    chipRow.className = "chip-row";
    codes.forEach((code) => appendText(chipRow, "span", code, "chip"));
    codeBlock.appendChild(chipRow);
  } else {
    appendText(codeBlock, "p", "식별된 위험 코드가 없습니다.", "muted");
  }
  card.appendChild(codeBlock);

  // 권고문
  const recBlock = document.createElement("div");
  recBlock.className = "detail-block";
  appendText(recBlock, "h3", "권고 사항");
  appendText(recBlock, "p", row.recommendation || "권고 사항이 없습니다.", "detail-text");
  card.appendChild(recBlock);

  // 완료 정의(DoD)
  const dodBlock = document.createElement("div");
  dodBlock.className = "detail-block";
  appendText(dodBlock, "h3", "완료 정의 (DoD)");
  appendText(dodBlock, "p", row.dod || "정의된 완료 기준이 없습니다.", "detail-text dod");
  card.appendChild(dodBlock);

  root.appendChild(card);
}

function renderPayload(payload) {
  currentRows = payload.rows || [];
  $("totalAssets").textContent = safeText(payload.summary.total_assets);
  $("criticalHigh").textContent = safeText(payload.summary.critical_high);
  $("avgScore").textContent = safeText(payload.summary.average_score);
  $("topAsset").textContent = safeText(payload.summary.top_asset || "-");
  renderBars("levelChart", payload.levels || {}, { colorByLevel: true, labelMap: levelLabels });
  renderBars("algorithmChart", payload.algorithms || {});
  renderTable(currentRows);
  setStatus("분석 완료");
}

async function runSample() {
  setStatus("분석 중");
  const res = await fetch("/api/sample");
  const payload = await res.json();
  if (!res.ok) {
    setStatus("오류");
    alert(payload.error || "분석에 실패했습니다.");
    return;
  }
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
    alert(payload.error || "분석에 실패했습니다.");
    return;
  }
  renderPayload(payload);
});

runSample().catch(() => setStatus("초기 분석 실패"));
