const API_URL = "http://localhost:8000/api/scan/scan-light";

const urlEl = document.getElementById("url");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const scanBtn = document.getElementById("scanBtn");
const manualUrlEl = document.getElementById("manualUrl");

let currentUrl = "";

function setStatus(message) {
  statusEl.textContent = message;
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderResult(result) {
  const label = result?.label || "unknown";
  const confidence = typeof result?.confidence === "number" ? (result.confidence * 100).toFixed(2) : "n/a";
  const riskLevel = result?.risk_level || "unknown";
  const action = result?.recommended_action || "n/a";
  const reasons = Array.isArray(result?.reasons) ? result.reasons.slice(0, 4) : [];
  const labelClass = label === "phishing" ? "bad" : "good";

  resultEl.innerHTML = `
    <div><strong>Verdict:</strong> <span class="${labelClass}">${escapeHtml(label.toUpperCase())}</span></div>
    <div><strong>Confidence:</strong> ${escapeHtml(confidence)}%</div>
    <div><strong>Risk:</strong> ${escapeHtml(String(riskLevel).toUpperCase())}</div>
    <div><strong>Action:</strong> ${escapeHtml(action.replaceAll("_", " "))}</div>
    ${
      reasons.length
        ? `<ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
        : ""
    }
  `;
  resultEl.hidden = false;
}

async function getCurrentTabUrl() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !tab.url) {
    throw new Error("No active tab URL found");
  }
  return tab.url;
}

async function scanUrl(url) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    throw new Error(`Scan request failed (${response.status})`);
  }
  return response.json();
}

function normalizeUrl(raw) {
  const value = String(raw || "").trim();
  if (!value) return "";
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value)) {
    return `http://${value}`;
  }
  return value;
}

scanBtn.addEventListener("click", async () => {
  const manualValue = normalizeUrl(manualUrlEl.value);
  const targetUrl = manualValue || currentUrl;

  if (!targetUrl) {
    setStatus("No URL available to scan.");
    return;
  }

  setStatus("Scanning...");
  resultEl.hidden = true;
  scanBtn.disabled = true;

  try {
    const payload = await scanUrl(targetUrl);
    renderResult(payload?.result || {});
    setStatus("Scan completed.");
  } catch (error) {
    setStatus(`Error: ${error.message}. Is backend running on localhost:8000?`);
  } finally {
    scanBtn.disabled = false;
  }
});

(async function init() {
  try {
    currentUrl = await getCurrentTabUrl();
    urlEl.textContent = currentUrl;
    manualUrlEl.value = "";
    setStatus("Ready.");
  } catch (error) {
    urlEl.textContent = "Unable to read current tab URL.";
    setStatus(`Error: ${error.message}`);
  }
})();
