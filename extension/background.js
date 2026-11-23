// DSAT Bank Guard - service worker.
// Holds the private whitelist/blacklist and the live DSAT codes pushed by the bank server,
// checks every navigation BEFORE the page loads, and verifies the logo code on bank pages.
const SERVER = "http://127.0.0.1:5000";        // bank DSAT server
const KEY = "dsat-demo-pairing-key";            // pairing key: only a paired extension may read the lists / codes
const H = { "X-DSAT-Key": KEY };
const WINDOW_MS = 60000;                        // token validity window (paper Eq. 6)
let lists = null, codes = {}, connected = false, allowed = {};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const ready = chrome.storage.local.get(["lists", "codes"]).then(s => { lists = s.lists || null; codes = s.codes || {}; });

async function save(extra = {}) {
  const now = Date.now();
  for (const h in codes) if (now - codes[h].receivedAt > WINDOW_MS + 10000) delete codes[h];
  await chrome.storage.local.set({ codes, lists, connected, liveCount: Object.keys(codes).length, ...extra });
}
const addCode = (x, at) => { codes[x.hash] = { bank: x.bank, domain: x.domain, receivedAt: at }; };

async function refresh() {
  try {
    const [l, c] = await Promise.all([
      fetch(`${SERVER}/api/lists`, { headers: H }).then(r => r.ok ? r.json() : Promise.reject()),
      fetch(`${SERVER}/api/codes`, { headers: H }).then(r => r.ok ? r.json() : Promise.reject())]);
    lists = l; connected = true;
    for (const x of c) addCode(x, Date.now() - x.age * 1000);
  } catch (e) { connected = false; }
  await save(); return connected;
}

async function stream() {                       // live push of every new code
  await ready;
  for (;;) {
    try {
      const r = await fetch(`${SERVER}/api/stream`, { headers: H });
      if (!r.ok) throw 0;
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = "";
      connected = true; await save();
      for (;;) {
        const { value, done } = await rd.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const line = buf.slice(0, i).split("\n").find(l => l.startsWith("data:")); buf = buf.slice(i + 2);
          if (line) { const x = JSON.parse(line.slice(5)); addCode(x, Date.now()); await save({ lastCode: { ...x, receivedAt: Date.now() } }); }
        }
      }
    } catch (e) {}
    connected = false; await save(); await sleep(2000);
  }
}
stream();
chrome.alarms.create("keepalive", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(() => refresh());

function lev(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1])));
    prev = cur;
  }
  return prev[b.length];
}
const norm = h => h.replace(/rn/g, "m").replace(/0/g, "o").replace(/1/g, "l");

function classify(host) {
  host = host.replace(/^www\./, "");
  if (!lists) return { status: "unknown" };
  if (lists.whitelist[host]) return { status: "whitelist", ...lists.whitelist[host] };
  if (lists.blacklist[host]) return { status: "blacklist", reason: lists.blacklist[host].reason };
  for (const w of Object.keys(lists.whitelist)) {
    const brand = w.split(".")[0];
    if (lev(host, w) <= 2 || lev(norm(host), w) <= 2) return { status: "suspicious", reason: `Look-alike of the real bank site ${w}` };
    if (host.includes(brand)) return { status: "suspicious", reason: `Uses the name "${brand}" but is not the official ${w}` };
  }
  return { status: "unknown" };
}
const isAllowed = h => allowed[h] && allowed[h] > Date.now();

// ---- Check every typed / clicked URL before the page loads
chrome.webNavigation.onBeforeNavigate.addListener(async d => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const host = new URL(d.url).hostname;
  await ready; if (!lists) await refresh();
  const c = classify(host);
  if ((c.status === "blacklist" || c.status === "suspicious") && !isAllowed(host.replace(/^www\./, "")))
    chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL("blocked.html") + "?" + new URLSearchParams({ host, reason: c.reason, kind: c.status, url: d.url }) });
});

// ---- Omnibox: type "bank" + space + a bank name
chrome.omnibox.setDefaultSuggestion({ description: "Type a bank name, e.g. hdfc, indian, sbi, icici" });
const find = q => Object.entries((lists && lists.whitelist) || {}).filter(([h, b]) => h.includes(q) || b.name.toLowerCase().includes(q));
chrome.omnibox.onInputChanged.addListener(async (text, suggest) => {
  await ready; if (!lists) await refresh();
  suggest(find(text.trim().toLowerCase()).map(([h, b]) => ({ content: b.url, description: `${b.name} - verified bank (${h})` })));
});
chrome.omnibox.onInputEntered.addListener(async text => {
  await ready; const m = find(text.trim().toLowerCase())[0];
  const url = /^https?:/.test(text) ? text : m ? m[1].url : /\./.test(text) ? "http://" + text : "https://www.google.com/search?q=" + encodeURIComponent(text);
  chrome.tabs.update({ url });
});

async function handle(m, sender) {
  await ready;
  if (m.type === "check") { if (!lists) await refresh(); const c = classify(m.host); return { ...c, allowed: isAllowed(m.host.replace(/^www\./, "")) }; }
  if (m.type === "allow") { allowed[m.host] = Date.now() + 5 * 60000; return true; }
  if (m.type === "verify") {
    const isWl = !!(lists && lists.whitelist[m.host]);
    if (!m.blob) return isWl ? { ok: false, reason: "No hidden DSAT code found in the logo (hijacked or cloned page)" } : { ok: null };
    const hash = hex(await crypto.subtle.digest("SHA-256", new Uint8Array(m.blob)));
    let c = codes[hash], fresh = false;
    if (!c) { fresh = await refresh(); c = codes[hash]; }
    if (!c) return isWl ? { ok: false, hash, reason: fresh || connected ? "Logo code does not match any code issued by the bank server" : "Bank DSAT server unreachable - cannot verify" } : { ok: null };
    if (c.domain !== m.host) return { ok: false, fake: !isWl, hash, reason: `Logo carries a live code issued for ${c.domain}, not for this site (relayed / cloned logo)` };
    const age = Date.now() - c.receivedAt;
    if (age > WINDOW_MS) return { ok: false, hash, reason: "Code expired (stale or replayed logo)" };
    return { ok: true, hash, expiresIn: Math.round((WINDOW_MS - age) / 1000) };
  }
  if (m.type === "report" && sender.tab) {
    const good = m.verdict === "genuine";
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: good ? "OK" : m.verdict === "fake" ? "!" : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: good ? "#16804a" : "#c62828" });
    await chrome.storage.local.set({ ["tab_" + sender.tab.id]: { verdict: m.verdict, detail: m.detail, name: m.name || "", at: Date.now() } });
  }
  return null;
}
chrome.runtime.onMessage.addListener((m, sender, send) => { handle(m, sender).then(send); return true; });
