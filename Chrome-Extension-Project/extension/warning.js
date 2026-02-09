const PENDING_KEY = "pending_nav";

function getTabId() {
    const u = new URL(window.location.href);
    return u.searchParams.get("tabId");
}

async function loadPending(tabId) {
    if (chrome.storage.session) {
        const all = await chrome.storage.session.get([PENDING_KEY]);
        return (all[PENDING_KEY] || {})[String(tabId)];
    } else {
        const all = await chrome.storage.local.get([PENDING_KEY]);
        return (all[PENDING_KEY] || {})[String(tabId)];
    }
}

function setPill(level, score) {
    const pill = document.getElementById("pill");
    pill.className = "pill " + (level === "HIGH" ? "high" : level === "MEDIUM" ? "medium" : "low");
    const pct = Math.round((score || 0) * 100);
    pill.textContent = `Risk: ${level} (${pct}%)`;
}

function renderChain(chain) {
    const ul = document.getElementById("chain");
    ul.innerHTML = "";
    (chain || []).forEach(item => {
        const li = document.createElement("li");
        li.textContent = `${item.status_code} → ${item.url}`;
        ul.appendChild(li);
    });
}

(async () => {
    const tabId = getTabId();
    const pending = await loadPending(tabId);

    if (!pending) {
        document.body.innerHTML = "<p style='font-family:Arial'>No pending data found.</p>";
        return;
    }

    const analysis = pending.analysis;
    document.getElementById("finalUrl").textContent = analysis.final_url;
    setPill(analysis.risk_level, analysis.risk_score);
    renderChain(analysis.redirect_chain);

    document.getElementById("proceedBtn").addEventListener("click", async () => {
        chrome.tabs.update(Number(tabId), { url: pending.targetUrl });
    });

    document.getElementById("backBtn").addEventListener("click", async () => {
        // safest: go back to previousUrl stored
        chrome.tabs.update(Number(tabId), { url: pending.previousUrl || "chrome://newtab/" });
    });
})();
