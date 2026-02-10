const authCard = document.getElementById("authCard");
const statusCard = document.getElementById("statusCard");
const authError = document.getElementById("authError");

const usernameEl = document.getElementById("username");
const passwordEl = document.getElementById("password");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");
const rescanBtn = document.getElementById("rescanBtn");
const blockToggle = document.getElementById("blockToggle");
const autoScanToggle = document.getElementById("autoScanToggle");

const urlLine = document.getElementById("urlLine");
const whyLine = document.getElementById("whyLine");
const riskPill = document.getElementById("riskPill");

function setPill(risk) {
  riskPill.classList.remove("pill-ok", "pill-mid", "pill-bad", "pill-unknown");
  if (risk === "High") {
    riskPill.classList.add("pill-bad");
    riskPill.textContent = "PHISHING";
    return;
  }
  if (risk === "Medium") {
    riskPill.classList.add("pill-mid");
    riskPill.textContent = "SUSPICIOUS";
    return;
  }
  if (risk === "Low") {
    riskPill.classList.add("pill-ok");
    riskPill.textContent = "SAFE";
    return;
  }
  riskPill.classList.add("pill-unknown");
  riskPill.textContent = "NO SCAN";
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function refreshUi() {
  const settings = await chrome.runtime.sendMessage({ type: "get_settings" });
  if (!settings.tokenPresent) {
    authCard.style.display = "block";
    statusCard.style.display = "none";
    return;
  }

  authCard.style.display = "none";
  statusCard.style.display = "block";
  blockToggle.checked = Boolean(settings.blockEnabled);
  autoScanToggle.checked = settings.autoScanEnabled !== false;

  const tab = await getActiveTab();
  const status = await chrome.runtime.sendMessage({ type: "get_status", tabId: tab.id });
  if (!status || status.status !== "ok") {
    urlLine.textContent = tab.url || "";
    if (status?.status === "not_authenticated") {
      whyLine.textContent = "Please login to start real-time phishing scanning.";
    } else if (status?.status === "network_error") {
      whyLine.textContent = "Unable to reach FinShield AI server. Check API or network.";
    } else if (status?.status === "api_error") {
      whyLine.textContent = "Scan failed due to API error. Click Rescan after fixing backend.";
    } else {
      whyLine.textContent = "No scan result yet for this page. Click Rescan.";
    }
    setPill(null);
    return;
  }

  urlLine.textContent = status.url;
  setPill(status.risk);
  const confPct = (status.prob_phishing * 100).toFixed(1);
  const top = (status.top_features || []).slice(0, 2);
  let baseText = "";
  if (status.risk === "High") {
    baseText = `High-Risk phishing detected (${confPct}% phishing confidence).`;
  } else if (status.risk === "Medium") {
    baseText = `Suspicious URL pattern (${confPct}% phishing confidence).`;
  } else {
    baseText = `No strong phishing patterns detected (${confPct}% phishing confidence).`;
  }
  if (top.length) {
    const signals = top.map(x => `${x.name}=${x.value}`).join(", ");
    whyLine.textContent = `${baseText} Top signals: ${signals}.`;
  } else {
    whyLine.textContent = baseText;
  }
}

loginBtn.addEventListener("click", async () => {
  authError.textContent = "";
  const username = usernameEl.value.trim();
  const password = passwordEl.value;
  const res = await chrome.runtime.sendMessage({ type: "login", username, password });
  if (!res.ok) {
    authError.textContent = "Login failed. Check username/password.";
    return;
  }
  await refreshUi();
});

logoutBtn.addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "logout" });
  await refreshUi();
});

rescanBtn.addEventListener("click", async () => {
  const tab = await getActiveTab();
  await chrome.runtime.sendMessage({ type: "scan_now", tabId: tab.id, url: tab.url, eventType: "popup_rescan" });
  await refreshUi();
});

blockToggle.addEventListener("change", async () => {
  await chrome.runtime.sendMessage({ type: "set_block", enabled: blockToggle.checked });
});

autoScanToggle.addEventListener("change", async () => {
  await chrome.runtime.sendMessage({ type: "set_auto_scan", enabled: autoScanToggle.checked });
});

refreshUi();
