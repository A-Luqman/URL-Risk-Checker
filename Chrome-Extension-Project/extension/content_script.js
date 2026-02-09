document.addEventListener("click", async (e) => {
  const res = await chrome.storage.local.get(["extension_enabled"]);
  const enabled = res.extension_enabled !== false;
  if (!enabled) return;

  const a = e.target.closest && e.target.closest("a[href]");
  if (!a) return;

  const href = a.href;
  if (!href || href.startsWith("javascript:") || href.startsWith("mailto:") || href.startsWith("tel:")) return;

  if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

  e.preventDefault();
  e.stopPropagation();

  chrome.runtime.sendMessage({
    type: "PRECLICK_ANALYZE",
    url: href
  });
}, true);
