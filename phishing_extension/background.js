const API_BASE = "http://127.0.0.1:8000";

const tabCache = new Map();

async function getToken() {
  const data = await chrome.storage.local.get(["finshield_token"]);
  return data.finshield_token || null;
}

async function getBlockEnabled() {
  const data = await chrome.storage.local.get(["finshield_block_enabled"]);
  return Boolean(data.finshield_block_enabled);
}

async function getAutoScanEnabled() {
  const data = await chrome.storage.local.get(["finshield_auto_scan_enabled"]);
  if (typeof data.finshield_auto_scan_enabled === "boolean") {
    return data.finshield_auto_scan_enabled;
  }
  return true;
}

function riskBadge(risk) {
  if (risk === "High") {
    return { text: "BAD", color: "#ef4444" };
  }
  if (risk === "Medium") {
    return { text: "MID", color: "#f59e0b" };
  }
  return { text: "OK", color: "#10b981" };
}

async function setBadge(tabId, risk) {
  const { text, color } = riskBadge(risk);
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function clearBadge(tabId) {
  await chrome.action.setBadgeText({ tabId, text: "" });
}

async function scanUrl(tabId, url, eventType) {
  const autoEnabled = await getAutoScanEnabled();
  const isManual = eventType === "popup_rescan" || eventType === "manual";
  if (!autoEnabled && !isManual) {
    await clearBadge(tabId);
    tabCache.set(tabId, { url, status: "auto_scan_disabled", ts: Date.now() });
    return tabCache.get(tabId);
  }

  const token = await getToken();
  if (!token) {
    await clearBadge(tabId);
    tabCache.set(tabId, { url, status: "not_authenticated", ts: Date.now() });
    return tabCache.get(tabId);
  }

  try {
    const res = await fetch(`${API_BASE}/api/v1/predict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({ url, source: "extension", event_type: eventType }),
    });

    if (!res.ok) {
      const body = await res.text();
      tabCache.set(tabId, { url, status: "api_error", error: body, ts: Date.now() });
      await clearBadge(tabId);
      return tabCache.get(tabId);
    }

    const data = await res.json();
    tabCache.set(tabId, { ...data, status: "ok", ts: Date.now() });
    await setBadge(tabId, data.risk);
    return tabCache.get(tabId);
  } catch (e) {
    tabCache.set(tabId, { url, status: "network_error", error: String(e), ts: Date.now() });
    await clearBadge(tabId);
    return tabCache.get(tabId);
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!tab || !tab.url) return;
  if (changeInfo.status !== "complete") return;
  if (!/^https?:/i.test(tab.url)) return;
  await scanUrl(tabId, tab.url, "page_load");
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url || !/^https?:/i.test(details.url)) return;
  await scanUrl(details.tabId, details.url, "navigation");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "get_status") {
      const tabId = message.tabId ?? sender?.tab?.id;
      if (tabId == null) return sendResponse({ status: "no_tab" });
      return sendResponse(tabCache.get(tabId) || { status: "empty" });
    }

    if (message?.type === "scan_now") {
      const tabId = message.tabId ?? sender?.tab?.id;
      const url = message.url ?? sender?.tab?.url;
      if (tabId == null || !url) return sendResponse({ status: "bad_request" });
      const result = await scanUrl(tabId, url, message.eventType || "manual");
      const blockEnabled = await getBlockEnabled();
      return sendResponse({ ...result, blockEnabled });
    }

    if (message?.type === "login") {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: message.username, password: message.password }),
      });
      if (!res.ok) return sendResponse({ ok: false, error: "Invalid credentials" });
      const data = await res.json();
      await chrome.storage.local.set({ finshield_token: data.token, finshield_user: data.username, finshield_role: data.role });
      return sendResponse({ ok: true, user: data.username, role: data.role });
    }

    if (message?.type === "logout") {
      const token = await getToken();
      await chrome.storage.local.remove(["finshield_token", "finshield_user", "finshield_role"]);
      if (token) {
        try {
          await fetch(`${API_BASE}/api/v1/auth/logout`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` },
          });
        } catch (_) {}
      }
      return sendResponse({ ok: true });
    }

    if (message?.type === "set_block") {
      await chrome.storage.local.set({ finshield_block_enabled: Boolean(message.enabled) });
      return sendResponse({ ok: true });
    }

    if (message?.type === "set_auto_scan") {
      await chrome.storage.local.set({ finshield_auto_scan_enabled: Boolean(message.enabled) });
      return sendResponse({ ok: true });
    }

    if (message?.type === "get_settings") {
      const token = await getToken();
      const blockEnabled = await getBlockEnabled();
      const autoScanEnabled = await getAutoScanEnabled();
      const data = await chrome.storage.local.get(["finshield_user", "finshield_role"]);
      return sendResponse({ tokenPresent: Boolean(token), blockEnabled, autoScanEnabled, user: data.finshield_user || null, role: data.finshield_role || null });
    }

    return sendResponse({ status: "unknown_message" });
  })();

  return true;
});
