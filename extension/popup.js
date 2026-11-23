const $ = id => document.getElementById(id);
async function render() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const s = await chrome.storage.local.get(["connected", "lastCode", "liveCount", "tab_" + tab.id]);
  $("conn").textContent = s.connected ? "Connected (live)" : "Offline - start the bank server";
  $("dot").style.background = s.connected ? "#16804a" : "#c62828"; $("live").textContent = s.connected ? `${s.liveCount || 0} live codes` : "";
  const t = s["tab_" + tab.id];
  if (t) { const g = t.verdict === "genuine"; $("v").className = "v " + (g ? "g" : "r");
    $("v").innerHTML = `<b>${g ? "Verified genuine bank website" : "FAKE / PHISHING WEBSITE"}</b><span>${t.name ? t.name + " - " : ""}${t.detail}</span>`; }
  if (s.lastCode) { $("code").textContent = s.lastCode.hash.slice(0, 32) + "... (" + s.lastCode.domain + ")";
    $("age").textContent = "received " + Math.round((Date.now() - s.lastCode.receivedAt) / 1000) + "s ago"; }
}
render(); setInterval(render, 1000);
