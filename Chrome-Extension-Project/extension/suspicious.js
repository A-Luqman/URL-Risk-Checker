const KEY = "suspicious_list";

function pillClass(level) {
    return level === "HIGH" ? "high" : level === "MEDIUM" ? "medium" : "low";
}

function render(items) {
    const root = document.getElementById("list");
    root.innerHTML = "";

    if (!items.length) {
        root.innerHTML = "<p>No suspicious entries saved.</p>";
        return;
    }

    items.forEach(item => {
        const div = document.createElement("div");
        div.className = "card";

        div.innerHTML = `
      <div>
        <span class="pill ${pillClass(item.risk_level)}">${item.risk_level}</span>
        <span class="small"> saved_at: ${item.saved_at}</span>
      </div>
      <div class="small"><b>Input:</b></div>
      <div class="mono">${item.input_url}</div>
      <div class="small" style="margin-top:8px;"><b>Final:</b></div>
      <div class="mono">${item.final_url}</div>
      <div class="small" style="margin-top:8px;">
        <a href="${item.input_url}" target="_blank" rel="noreferrer">Open input URL</a>
      </div>
    `;
        root.appendChild(div);
    });
}

async function load() {
    const data = await chrome.storage.local.get([KEY]);
    return data[KEY] || [];
}

async function clearAll() {
    await chrome.storage.local.set({ [KEY]: [] });
}

document.getElementById("clearBtn").addEventListener("click", async () => {
    await clearAll();
    render([]);
});

(async () => {
    const items = await load();
    render(items);
})();
