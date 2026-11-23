(async () => {
  const host = location.hostname.replace(/^www\./, "");
  const cls = await chrome.runtime.sendMessage({ type: "check", host });
  if (!cls) return;
  const report = (verdict, detail, name) => chrome.runtime.sendMessage({ type: "report", verdict, detail, name });
  const OK = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/></svg>';
  const BAD = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>';
  let root, minimized = false;
  function mount(css, html) {
    if (!root) { const h = document.createElement("div"); h.style.all = "initial"; document.documentElement.appendChild(h); root = h.attachShadow({ mode: "closed" }); }
    root.innerHTML = `<style>*{box-sizing:border-box;font-family:"Segoe UI",system-ui,sans-serif}${css}</style>${html}`;
  }
  const CARD_CSS = `.card{position:fixed;top:16px;right:16px;z-index:2147483647;width:350px;background:#fff;color:#1c2430;border-radius:14px;
    box-shadow:0 14px 44px #0005;padding:14px 16px;display:flex;gap:12px;align-items:flex-start;}.a{animation:in .35s ease}
    @keyframes in{from{transform:translateY(-20px);opacity:0}to{transform:none;opacity:1}}
    .ic{flex:none;width:44px;height:44px;border-radius:50%;display:grid;place-items:center}
    .t{font-size:15px;font-weight:700}.n{font-size:13px;color:#445}.d{font-size:12px;color:#667;margin-top:4px;line-height:1.4}
    code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:11.5px}
    .bar{height:4px;background:#e6ebf2;border-radius:2px;margin-top:9px;overflow:hidden}.bar i{display:block;height:100%;transition:width 1s linear}
    .x{margin-left:auto;border:0;background:none;font-size:20px;color:#889;cursor:pointer;line-height:1}
    .pill{position:fixed;top:16px;right:16px;z-index:2147483647;width:46px;height:46px;border-radius:50%;display:grid;place-items:center;cursor:pointer;box-shadow:0 6px 20px #0005}`;
  let lastKind = null;
  function card(kind, title, name, detail, pct) {
    const anim = lastKind !== kind ? " a" : ""; lastKind = kind;
    const col = { ok: "#16804a", wait: "#b7791f", bad: "#c62828" }[kind];
    if (minimized) return mount(CARD_CSS, `<div class=pill id=p style="background:${col}">${kind === "bad" ? BAD : OK}</div>`), root.getElementById("p").onclick = () => { minimized = false; card(kind, title, name, detail, pct); };
    mount(CARD_CSS, `<div class="card${anim}"><div class=ic style="background:${col}">${kind === "bad" ? BAD : OK}</div><div style="flex:1">
      <div class=t style="color:${col}">${title}</div><div class=n>${name}</div><div class=d>${detail}</div>
      ${pct != null ? `<div class=bar><i style="width:${pct}%;background:${col}"></i></div>` : ""}</div><button class=x id=x>&times;</button></div>`);
    root.getElementById("x").onclick = () => { minimized = true; card(kind, title, name, detail, pct); };
  }
  function block(reason) {
    mount(`.o{position:fixed;inset:0;z-index:2147483647;background:linear-gradient(135deg,#7f1010,#c62828);display:grid;place-items:center;color:#1c2430}
      .c{background:#fff;max-width:520px;border-radius:18px;padding:36px;text-align:center;box-shadow:0 20px 60px #0007}
      .ic{width:72px;height:72px;border-radius:50%;background:#c62828;display:grid;place-items:center;margin:0 auto 16px}h1{margin:0 0 10px;font-size:26px;color:#b71c1c}
      p{color:#445;line-height:1.5;margin:8px 0}.r{background:#fdecea;border-radius:8px;padding:10px;font-size:13px;color:#8a1c1c}
      button{margin:14px 6px 0;padding:11px 20px;border-radius:8px;font-size:15px;cursor:pointer;border:0}.a{background:#c62828;color:#fff}.b{background:#eef2f7;color:#445}`,
      `<div class=o><div class=c><div class=ic>${BAD.replace('width="24" height="24"', 'width="40" height="40"')}</div><h1>Fake website detected</h1>
       <p>This is <b>not</b> the genuine bank website. Do <b>not</b> enter your username, password or OTP.</p><div class=r>${reason}</div>
       <button class=a id=leave>Back to safety</button><button class=b id=stay>Show page anyway</button></div></div>`);
    root.getElementById("leave").onclick = () => { location.href = "about:blank"; };
    root.getElementById("stay").onclick = () => card("bad", "FAKE WEBSITE - do not enter credentials", "Unverified site", reason);
  }

  if (cls.status === "blacklist" || cls.status === "suspicious") {
    report("fake", cls.reason);
    return cls.allowed ? card("bad", "Phishing website - proceed at your own risk", "Blocked by DSAT Bank Guard", cls.reason) : block(cls.reason);
  }

  const unknown = cls.status === "unknown";
  let lastSrc = null, lastBlob = null, misses = 0, ticks = 0, timer;
  const findLogo = () => document.querySelector("img[data-bank-logo]") ||
    [...document.images].find(i => /logo/i.test(i.id + i.className + (i.alt || "") + i.src) && i.naturalWidth >= 64);

  async function tick() {
    ticks++;
    if (unknown && ticks > 5) return clearInterval(timer);       // unlisted site: only look for relayed bank logos
    const img = findLogo();
    if (!img || !img.complete || !img.naturalWidth) {
      if (unknown) return;
      if (++misses > 4) { clearInterval(timer); block("The page does not carry the bank's authentication logo"); report("fake", "No logo found", cls.name); }
      else card("wait", "Verifying website...", cls.name, "Reading the hidden code from the bank logo", null);
      return;
    }
    if (img.currentSrc !== lastSrc) {
      lastSrc = img.currentSrc;
      try {
        const c = document.createElement("canvas"); c.width = img.naturalWidth; c.height = img.naturalHeight;
        const x = c.getContext("2d", { willReadFrequently: true }); x.drawImage(img, 0, 0);
        lastBlob = Array.from(dsatExtract(x.getImageData(0, 0, c.width, c.height).data, c.width, c.height));
      } catch (e) { lastBlob = null; }
    }
    const r = await chrome.runtime.sendMessage({ type: "verify", host, blob: lastBlob });
    if (!r || r.ok === null) return;
    if (r.ok) {
      card("ok", "Verified genuine bank website", cls.name,
        `Hidden logo code <code>${r.hash.slice(0, 12)}</code> matches the live code from the bank server. It changes every 10 s and is re-checked automatically. You can continue safely.`,
        Math.round(r.expiresIn / 60 * 100));
      report("genuine", `Hidden code ${r.hash.slice(0, 12)}... matches the live server code`, cls.name);
    } else { clearInterval(timer); block(r.reason); report("fake", r.reason, cls.name); }
  }
  tick(); timer = setInterval(tick, 2000);
})();
