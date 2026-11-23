const q = new URLSearchParams(location.search), $ = id => document.getElementById(id);
$("host").textContent = q.get("host"); $("reason").textContent = q.get("reason");
if (q.get("kind") === "suspicious") $("title").textContent = "Suspicious look-alike website blocked";
$("back").onclick = () => chrome.tabs.getCurrent(t => chrome.tabs.update(t.id, { url: "chrome://newtab/" }));
$("go").onclick = () => chrome.runtime.sendMessage({ type: "allow", host: q.get("host").replace(/^www\./, "") }, () => { location.href = q.get("url"); });
