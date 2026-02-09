const API_BASE = "http://127.0.0.1:8000";

const toggleEl = document.getElementById("toggleExtension");
const TOGGLE_KEY = "extension_enabled";
const statusLabel = document.getElementById("statusLabel");

const urlInput = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const openSuspiciousBtn = document.getElementById("openSuspiciousBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const riskPill = document.getElementById("riskPill");
const finalUrlEl = document.getElementById("finalUrl");
const chainList = document.getElementById("chainList");
const addSuspiciousBtn = document.getElementById("addSuspiciousBtn");

let lastAnalysis = null;

chrome.storage.local.get([TOGGLE_KEY], (res) => {
  const enabled = res[TOGGLE_KEY] !== false; // default ON
  toggleEl.checked = enabled;
  setUIEnabled(enabled);
});

toggleEl.addEventListener("change", () => {
  const enabled = toggleEl.checked;
  chrome.storage.local.set({ [TOGGLE_KEY]: enabled });
  setUIEnabled(enabled);
});

function setUIEnabled(enabled) {
  analyzeBtn.disabled = !enabled;
  urlInput.disabled = !enabled;
  statusLabel.textContent = enabled ? "ON" : "OFF";
  statusLabel.className = enabled ? "status-text on" : "status-text off";
}

function setStatus(msg) {
  statusEl.textContent = msg;
}

function setRiskPill(level, score) {
  riskPill.className = "pill " + (level === "HIGH" ? "high" : level === "MEDIUM" ? "medium" : "low");
  const pct = Math.round((score || 0) * 100);
  riskPill.textContent = `Risk: ${level} (${pct}%)`;
}

function renderChain(chain) {
  chainList.innerHTML = "";
  (chain || []).forEach(item => {
    const li = document.createElement("li");
    li.textContent = `${item.status_code} → ${item.url}`;
    chainList.appendChild(li);
  });
}

async function analyzeUrl(url) {
  setStatus("Checking…");
  resultEl.classList.add("hidden");
  lastAnalysis = null;

  const resp = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

async function addToSuspicious(entry) {
  const key = "suspicious_list";
  const now = new Date().toISOString();

  const item = {
    saved_at: now,
    input_url: entry.input_url,
    final_url: entry.final_url,
    risk_level: entry.risk_level,
    risk_score: entry.risk_score,
    redirect_chain: entry.redirect_chain
  };

  const existing = await chrome.storage.local.get([key]);
  const list = existing[key] || [];
  list.unshift(item);
  await chrome.storage.local.set({ [key]: list });
}

analyzeBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) return setStatus("Please paste a URL.");

  try {
    const data = await analyzeUrl(url);
    lastAnalysis = data;

    setRiskPill(data.risk_level, data.risk_score);
    finalUrlEl.textContent = data.final_url;
    renderChain(data.redirect_chain);

    resultEl.classList.remove("hidden");
    setStatus(data.prediction === 1 ? "⚠️ Suspicious detected." : "✅ Looks safe (model).");

    // Auto-add to suspicious if predicted malicious
    if (data.prediction === 1) await addToSuspicious(data);
  } catch (e) {
    setStatus("Error: " + e.message);
  }
});

addSuspiciousBtn.addEventListener("click", async () => {
  if (!lastAnalysis) return setStatus("Nothing to add yet.");
  await addToSuspicious(lastAnalysis);
  setStatus("Added to suspicious list.");
});

openSuspiciousBtn.addEventListener("click", async () => {
  const url = chrome.runtime.getURL("suspicious.html");
  chrome.tabs.create({ url });
});
