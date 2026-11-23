"""Demo server. Run: python app.py  ->  http://127.0.0.1:5000
Simulates the bank server (issues DSAT logos), a browser verifier (/api/verify)
and several attacker scenarios."""
import time, json, queue, os
from functools import wraps
import numpy as np
from flask import Flask, jsonify, request, Response
from dsat_core import DSATIssuer, REGISTRY, make_logo, to_png, from_png, embed, validate_url

app = Flask(__name__)
issuer = DSATIssuer()

# name -> (description, page URL the user sees, expected result)
SCENARIOS = {
    "genuine":   ("Genuine bank site, fresh token", "https://indianbank.in/login", True),
    "typosquat": ("Typosquat domain relaying the real logo", "https://indiianbank.in/login", False),
    "brand":     ("Look-alike domain, copied static logo", "https://indianbank-secure.com", False),
    "subdomain": ("indianbank.in.evil.com trick", "https://indianbank.in.evil.com", False),
    "hijack":    ("Correct URL (DNS hijack) but no token in logo", "https://indianbank.in/login", False),
    "replay":    ("Correct URL, token captured 2 minutes ago", "https://indianbank.in/login", False),
    "tampered":  ("Correct URL, token bits corrupted", "https://indianbank.in/login", False),
    "http":      ("Plain HTTP downgrade", "http://indianbank.in/login", False),
}

def scenario_logo(name):
    if name in ("genuine", "typosquat", "brand", "subdomain", "http"):
        return issuer.issue("indianbank")[0]
    if name == "hijack":
        return to_png(make_logo("indianbank"))
    if name == "replay":
        return issuer.issue("indianbank", ts=time.time() - 120)[0]
    if name == "tampered":
        a = from_png(issuer.issue("indianbank")[0]).copy()
        a.reshape(-1)[:3000] ^= 1
        return to_png(a)

@app.get("/api/scenarios")
def scenarios():
    return jsonify([dict(name=k, desc=v[0], url=v[1], expected_accept=v[2]) for k, v in SCENARIOS.items()])

@app.get("/api/logo/<name>")
def logo(name):
    if name not in SCENARIOS: return "unknown", 404
    return Response(scenario_logo(name), mimetype="image/png", headers={"Cache-Control": "no-store"})

@app.get("/bank/logo.png")          # what a real bank page would serve
def bank_logo():
    return Response(issuer.issue(request.args.get("bank", "indianbank"))[0],
                    mimetype="image/png", headers={"Cache-Control": "no-store"})

@app.post("/api/verify")
def verify():
    t = time.perf_counter()
    f = request.files.get("logo")
    res = issuer.verify(f.read() if f else b"", request.form.get("page_url", ""))
    res["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
    return jsonify(res)

@app.post("/api/check_url")
def check_url():
    return jsonify(validate_url(request.json.get("url", "")))

PAGE = """<!doctype html><meta charset=utf-8><title>DSAT demo</title>
<style>body{font:15px system-ui;max-width:900px;margin:30px auto;padding:0 16px;color:#222}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left}
img{width:56px;height:56px;border-radius:6px}.ok{color:#0a7d2c;font-weight:600}.bad{color:#c0392b;font-weight:600}
button{padding:5px 12px;cursor:pointer}input[type=text]{width:60%;padding:6px}code{background:#f2f2f2;padding:1px 4px}</style>
<h2>DSAT anti-phishing demo</h2>
<p>Each row simulates a page the user lands on. The verifier checks the URL, then extracts and validates the
token hidden in the logo (the logo is re-issued with a fresh token on every run).</p>
<p><button onclick=runAll()>Run all scenarios</button></p>
<table id=t><tr><th>Scenario<th>URL<th>Logo<th>Verdict<th>Reason<th>ms</tr></table>
<h3>Try your own</h3>
<p>URL: <input type=text id=u value="https://indianbank.in/login"> <input type=file id=f accept=image/png>
<button onclick=custom()>Verify</button> <span id=c></span></p>
<p><small>Tip: download <code>/bank/logo.png</code> and upload it with the URL above; wait &gt;60 s and it will be rejected as expired.</small></p>
<script>
let S=[];
async function run(i){const s=S[i];const b=await (await fetch('/api/logo/'+s.name)).blob();
 const fd=new FormData();fd.append('page_url',s.url);fd.append('logo',b,'logo.png');
 const r=await (await fetch('/api/verify',{method:'POST',body:fd})).json();
 const row=document.getElementById('r'+i);const good=r.accepted==s.expected_accept;
 row.cells[2].innerHTML='<img src="'+URL.createObjectURL(b)+'">';
 row.cells[3].innerHTML='<span class='+(r.accepted?'ok':'bad')+'>'+(r.accepted?'ACCEPT':'REJECT')+(good?' ✓':' ✗')+'</span>';
 row.cells[4].textContent=r.reason;row.cells[5].textContent=r.latency_ms;}
async function runAll(){for(let i=0;i<S.length;i++)await run(i)}
async function custom(){const fd=new FormData();fd.append('page_url',u.value);
 if(f.files[0])fd.append('logo',f.files[0]);
 const r=await (await fetch('/api/verify',{method:'POST',body:fd})).json();
 c.innerHTML='<span class='+(r.accepted?'ok':'bad')+'>'+(r.accepted?'ACCEPT':'REJECT')+'</span> — '+r.reason}
(async()=>{S=await (await fetch('/api/scenarios')).json();const t=document.getElementById('t');
 S.forEach((s,i)=>{const r=t.insertRow();r.id='r'+i;r.innerHTML='<td>'+s.desc+'<td><code>'+s.url+'</code><td><td><td><td>'});runAll()})();
</script>"""

@app.get("/scenarios")
def scenarios_page(): return PAGE

# ---------------- Live demo: private whitelist / blacklist + extension feed ----------------
# *.localhost resolves to 127.0.0.1 in Chrome, so each host in data/banks.json acts as its own website.
# The lists are INTERNAL: only the server and the paired extension (shared key) can read them.
KEY = os.environ.get("DSAT_KEY", "dsat-demo-pairing-key")
DATA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "banks.json"), encoding="utf-8"))
WHITELIST = {b["host"]: b for b in DATA["whitelist"]}
BLACKLIST = {b["host"]: b for b in DATA["blacklist"]}
BY_ID = {b["id"]: b for b in DATA["whitelist"]}
REGISTRY.update({b["id"]: b["host"] for b in DATA["whitelist"]})
subs = []

def internal(f):
    @wraps(f)
    def w(*a, **k):
        if request.headers.get("X-DSAT-Key") != KEY: return jsonify(error="forbidden"), 403
        return f(*a, **k)
    return w

def _push(h, bank, domain):
    msg = json.dumps(dict(hash=h, bank=bank, domain=domain, ts=time.time()))
    for q in list(subs): q.put(msg)
issuer.listeners.append(_push)

SITE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>%NAME% | Net Banking</title>
<style>:root{--c:%C%;--a:%A%}*{box-sizing:border-box}
body{margin:0;font:15px/1.5 "Segoe UI",system-ui,sans-serif;color:#1c2430;background:#f4f6fa}
header{background:var(--c);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:16px 56px}
header b{font-size:21px}header nav a{color:#fff;opacity:.85;margin-left:26px;font-size:14px}
.hero{display:grid;grid-template-columns:1.2fr 1fr;gap:56px;max-width:1080px;margin:60px auto;padding:0 24px;align-items:center}
h1{font-size:42px;line-height:1.15;margin:0 0 14px;color:var(--c)}.hero p{color:#566;font-size:17px;max-width:460px}
.pill{display:inline-block;background:#fff;border:1px solid #dde3ee;border-radius:20px;padding:6px 14px;margin:8px 8px 0 0;font-size:13px}
.card{background:#fff;border-radius:18px;padding:34px;box-shadow:0 12px 44px #1a2a5020;text-align:center}
.card img{width:112px;height:112px;border-radius:50%;border:3px solid var(--a)}.card h2{margin:12px 0 18px;font-size:20px}
input{width:100%;padding:12px 14px;margin:6px 0;border:1px solid #cfd7e6;border-radius:8px;font-size:15px}
button{width:100%;padding:13px;margin-top:12px;border:0;border-radius:8px;background:var(--c);color:#fff;font-size:16px;font-weight:600}
.l{font-size:13px;color:#667;margin-top:14px}footer{text-align:center;color:#889;font-size:12px;padding:30px}
@media(max-width:800px){.hero{grid-template-columns:1fr}}</style>
<header><b>%NAME%</b><nav><a>Personal</a><a>Business</a><a>Cards</a><a>Loans</a><a>Support</a></nav></header>
<section class=hero><div><h1>Banking that never<br>sleeps. Safely.</h1>
<p>Pay bills, transfer funds and manage your accounts with 24x7 net banking.</p>
<span class=pill>256-bit encryption</span><span class=pill>Instant transfers</span><span class=pill>24x7 support</span></div>
<div class=card><img id=logo data-bank-logo src="/logo.png" alt="%NAME% logo"><h2>Net Banking Login</h2>
<input placeholder="Customer ID / User ID"><input type=password placeholder="Password"><button>Login securely</button>
<div class=l>Forgot password? &middot; New user? Register</div></div></section>
<footer>&copy; 2026 %NAME%. Never share your OTP or password with anyone.</footer>
<script>setInterval(()=>{document.getElementById('logo').src='/logo.png?'+Date.now()},10000)</script>"""

def _host(): return request.host.split(":")[0].lower()
def _site(name, theme): return SITE.replace("%NAME%", name).replace("%C%", theme["color"]).replace("%A%", theme["accent"])

@app.get("/")
def index():
    h = _host()
    if h in WHITELIST: return _site(WHITELIST[h]["name"], WHITELIST[h])
    if h in BLACKLIST: b = BLACKLIST[h]; return _site(BY_ID[b["look"]]["name"], BY_ID[b["look"]])
    return ('<!doctype html><meta charset=utf-8><body style="font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0;background:#0f172a;color:#e2e8f0">'
            '<div style="text-align:center"><h2>DSAT Bank Server</h2><p>Running. Type a bank website address in the address bar; '
            'the DSAT Bank Guard extension will verify it.</p></div>')

@app.get("/logo.png")
def site_logo():
    h = _host()
    if h in WHITELIST: png = issuer.issue(WHITELIST[h]["id"])[0]            # fresh token on every request
    elif h in BLACKLIST:
        b = BLACKLIST[h]
        png = issuer.issue(b["look"])[0] if b["relay"] else to_png(make_logo(b["look"]))
    else: return "not a bank site", 404
    return Response(png, mimetype="image/png", headers={"Cache-Control": "no-store"})

@app.get("/api/lists")
@internal
def lists():
    port = request.host.split(":")[1] if ":" in request.host else "80"
    return jsonify(whitelist={h: dict(bank=b["id"], name=b["name"], url=f"http://{h}:{port}/") for h, b in WHITELIST.items()},
                   blacklist={h: dict(reason=b["reason"]) for h, b in BLACKLIST.items()})

@app.get("/api/codes")      # snapshot of currently valid codes (SHA-256 of each issued logo payload)
@internal
def codes():
    now = time.time()
    return jsonify([dict(hash=h, bank=v["bank"], domain=v["domain"], age=round(now - v["t"], 2))
                    for h, v in issuer.recent.items() if now - v["t"] <= 70])

@app.get("/api/stream")     # live push (Server-Sent Events): each new code is sent as it is issued
@internal
def stream():
    q = queue.Queue(); subs.append(q)
    def gen():
        try:
            yield ": connected\n\n"
            while True:
                try: yield "data: " + q.get(timeout=15) + "\n\n"
                except queue.Empty: yield ": ping\n\n"
        finally:
            if q in subs: subs.remove(q)
    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-store"})

if __name__ == "__main__":
    app.run(debug=False)
