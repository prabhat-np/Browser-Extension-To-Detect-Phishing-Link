function makeOverlay(payload) {
  const overlay = document.createElement("div");
  overlay.id = "__finshield_overlay__";
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.zIndex = "2147483647";
  overlay.style.background = "rgba(2, 6, 23, 0.92)";
  overlay.style.color = "#f8fafc";
  overlay.style.fontFamily = "Arial, sans-serif";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.padding = "24px";

  const card = document.createElement("div");
  card.style.maxWidth = "720px";
  card.style.width = "100%";
  card.style.background = "#0f172a";
  card.style.border = "1px solid rgba(148,163,184,0.25)";
  card.style.borderRadius = "12px";
  card.style.padding = "18px";

  const title = document.createElement("div");
  title.style.fontSize = "20px";
  title.style.fontWeight = "700";
  title.textContent = "FinShield AI Warning: High-Risk Phishing Detected";

  const meta = document.createElement("div");
  meta.style.marginTop = "10px";
  meta.style.fontSize = "14px";
  meta.style.lineHeight = "1.4";
  meta.innerHTML = `
    <div><strong>URL:</strong> ${payload.url}</div>
    <div><strong>Risk:</strong> ${payload.risk} &nbsp; <strong>Confidence:</strong> ${(payload.prob_phishing * 100).toFixed(1)}%</div>
  `;

  const list = document.createElement("div");
  list.style.marginTop = "12px";
  list.style.fontSize = "13px";
  const top = (payload.top_features || []).slice(0, 6);
  list.innerHTML = `<div style="font-weight:700;margin-bottom:6px;">Why this looks suspicious</div>` +
    top.map(f => `<div style="opacity:0.95;">• ${f.name}: <span style="opacity:0.9">${String(f.value)}</span></div>`).join("");

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "10px";
  actions.style.marginTop = "14px";

  const backBtn = document.createElement("button");
  backBtn.textContent = "Go Back";
  backBtn.style.padding = "10px 12px";
  backBtn.style.borderRadius = "8px";
  backBtn.style.border = "0";
  backBtn.style.background = "#ef4444";
  backBtn.style.color = "white";
  backBtn.style.cursor = "pointer";
  backBtn.addEventListener("click", () => history.back());

  const proceedBtn = document.createElement("button");
  proceedBtn.textContent = "Proceed Anyway (Not Recommended)";
  proceedBtn.style.padding = "10px 12px";
  proceedBtn.style.borderRadius = "8px";
  proceedBtn.style.border = "1px solid rgba(148,163,184,0.35)";
  proceedBtn.style.background = "transparent";
  proceedBtn.style.color = "white";
  proceedBtn.style.cursor = "pointer";
  proceedBtn.addEventListener("click", () => {
    overlay.remove();
  });

  actions.appendChild(backBtn);
  actions.appendChild(proceedBtn);

  card.appendChild(title);
  card.appendChild(meta);
  card.appendChild(list);
  card.appendChild(actions);
  overlay.appendChild(card);
  return overlay;
}

function showOverlay(payload) {
  if (document.getElementById("__finshield_overlay__")) return;
  document.documentElement.appendChild(makeOverlay(payload));
}

async function scanCurrentPage() {
  const result = await chrome.runtime.sendMessage({ type: "scan_now", url: location.href, eventType: "page_load" });
  if (result?.status === "ok" && result?.blockEnabled && result?.risk === "High") {
    showOverlay(result);
  }
}

function findAnchor(el) {
  while (el) {
    if (el.tagName && el.tagName.toLowerCase() === "a" && el.href) return el;
    el = el.parentElement;
  }
  return null;
}

document.addEventListener("click", async (e) => {
  const a = findAnchor(e.target);
  if (!a) return;
  const href = a.href;
  if (!href || !/^https?:/i.test(href)) return;
  const result = await chrome.runtime.sendMessage({ type: "scan_now", url: href, eventType: "link_click" });
  if (result?.status === "ok" && result?.blockEnabled && result?.risk === "High") {
    e.preventDefault();
    showOverlay({ ...result, url: href });
  }
}, true);

scanCurrentPage();

