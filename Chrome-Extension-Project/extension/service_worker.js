const API_BASE = "http://127.0.0.1:8000";
const PENDING_KEY = "pending_nav"; // stored in chrome.storage.session if available

async function analyzeUrl(url) {
  const resp = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ url })
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

async function savePending(tabId, pending) {
  // session storage is best (clears when browser closes)
  if (chrome.storage.session) {
    const all = await chrome.storage.session.get([PENDING_KEY]);
    const map = all[PENDING_KEY] || {};
    map[String(tabId)] = pending;
    await chrome.storage.session.set({ [PENDING_KEY]: map });
  } else {
    // fallback
    const all = await chrome.storage.local.get([PENDING_KEY]);
    const map = all[PENDING_KEY] || {};
    map[String(tabId)] = pending;
    await chrome.storage.local.set({ [PENDING_KEY]: map });
  }
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

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type !== "PRECLICK_ANALYZE") return;

  const tabId = sender.tab && sender.tab.id;
  if (!tabId) return;

  (async () => {
    const currentTab = await chrome.tabs.get(tabId);
    const previousUrl = currentTab.url;

    let data;
    try {
      data = await analyzeUrl(msg.url);
    } catch (e) {
      // If API fails, just allow navigation
      await chrome.tabs.update(tabId, { url: msg.url });
      return;
    }

    // If suspicious -> warn, else proceed
    if (data.prediction === 1) {
      await addToSuspicious(data);

      await savePending(tabId, {
        targetUrl: msg.url,
        previousUrl,
        analysis: data
      });

      const warnUrl = chrome.runtime.getURL(`warning.html?tabId=${tabId}`);
      await chrome.tabs.update(tabId, { url: warnUrl });
    } else {
      await chrome.tabs.update(tabId, { url: msg.url });
    }
  })();
});
