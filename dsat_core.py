"""DSAT core: URL validation, token generation (HMAC + AES-256-GCM),
adaptive-LSB steganography and verification."""
import hashlib, hmac, io, json, os, time
from urllib.parse import urlparse
import numpy as np
from PIL import Image, ImageDraw
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

VALIDITY_WINDOW = 60   # seconds (paper Eq. 6)
TAU = 2                # Levenshtein threshold (paper Sec. IX-C)
REGISTRY = {           # bank id -> official domain
    "indianbank": "indianbank.in", "sbi": "onlinesbi.sbi",
    "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "axis": "axisbank.com", "canara": "canarabank.com",
}

# ---------------------------------------------------------------- URL layer
def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def _normalize(h):  # undo common look-alike tricks
    return h.replace("rn", "m").translate(str.maketrans("01", "ol"))

def validate_url(url, registry=REGISTRY, tau=TAU):
    """Returns dict(valid, verdict, reason, bank, domain, host)."""
    raw = url if "://" in url else "https://" + url
    p = urlparse(raw)
    host = (p.hostname or "").lower().rstrip(".")
    out = dict(valid=False, verdict="phishing", reason="", bank=None, domain=None, host=host)
    if not host:
        out["reason"] = "unparseable URL"; return out
    if p.username or p.password:
        out["reason"] = "credentials embedded in URL (@ trick)"; return out
    if p.scheme != "https":
        out["reason"] = "not HTTPS"; return out
    if any(l.startswith("xn--") for l in host.split(".")) or not host.isascii():
        out["reason"] = "punycode / non-ASCII homograph domain"; return out
    for bid, dom in registry.items():
        if host == dom or host == "www." + dom or host.endswith("." + dom):
            return dict(out, valid=True, verdict="legitimate", reason="exact official domain",
                        bank=bid, domain=dom)
    best = None
    for bid, dom in registry.items():
        d = min(levenshtein(host, dom), levenshtein(host.removeprefix("www."), dom),
                levenshtein(_normalize(host), dom))
        brand = dom.split(".")[0]
        near = d <= tau
        has_brand = brand in host or brand in _normalize(host)
        if near or has_brand:
            if best is None or d < best[0]:
                best = (d, bid, dom, "typosquat (edit distance %d)" % d if near
                        else "brand name inside unregistered domain")
    if best:
        out.update(verdict="suspicious", reason=best[3], bank=best[1], domain=best[2])
    else:
        out["reason"] = "domain not in registry"
    return out

# ----------------------------------------------------------- Steganography
def make_logo(bank="indianbank", size=256):
    """Procedurally generated logo (stand-in for the official bank logo); coloured per bank."""
    import colorsys
    from PIL import ImageFont
    seed = int(hashlib.sha256(bank.encode()).hexdigest()[:8], 16)
    rng = np.random.default_rng(seed)
    h = {"demo_indianbank": .60, "demo_hdfcbank": .58, "demo_sbibank": .55, "demo_icicibank": .04, "demo_axisbank": .92,
         "demo_kotakbank": .62, "demo_pnbindia": .0, "demo_bankofbaroda": .06, "demo_canarabank": .57, "demo_unionbank": .59,
         "demo_yesbank": .61, "demo_idfcfirstbank": .98}.get(bank, (seed % 360) / 360)
    c1 = np.array(colorsys.hsv_to_rgb(h, .8, .50)) * 255
    c2 = np.array(colorsys.hsv_to_rgb((h + .07) % 1, .65, .85)) * 255
    y, x = np.mgrid[0:size, 0:size]
    t = ((x + y) / (2 * size))[..., None]
    base = c1 * (1 - t) + c2 * t + rng.normal(0, 6, (size, size, 3))  # texture gives adaptive LSB room
    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))
    d, cx, W = ImageDraw.Draw(img), size // 2, (255, 255, 255)
    d.ellipse([16, 16, size - 16, size - 16], outline=W, width=6)
    d.polygon([(cx - 62, 104), (cx, 58), (cx + 62, 104)], fill=W)
    for i in range(4): d.rectangle([cx - 52 + i * 28, 112, cx - 40 + i * 28, 152], fill=W)
    d.rectangle([cx - 64, 158, cx + 64, 170], fill=W)
    label = bank.replace("demo_", "").upper()
    try: f = ImageFont.load_default(size=20)
    except TypeError: f = ImageFont.load_default()
    d.text((cx - d.textlength(label, font=f) / 2, 188), label, font=f, fill=W)
    return np.array(img)

def _k_map(arr):
    """Adaptive k per sample (Eq. 8). Computed from the upper nibble only (so the extractor
    sees the same map) and with exact integer maths (so the JS extension agrees bit-for-bit):
    k = smallest k in 1..4 with 4*sigma/sigma_max <= k."""
    hi = (arr & 0xF0).astype(np.int64)
    H, W, _ = hi.shape
    pad = np.pad(hi, ((1, 1), (1, 1), (0, 0)), mode="edge")
    wins = [pad[i:i + H, j:j + W] for i in range(3) for j in range(3)]
    s1, s2 = sum(wins), sum(w * w for w in wins)
    num = 9 * s2 - s1 * s1                      # = 81 * local variance
    nmax = int(num.max())
    k = np.full(num.shape, 4, dtype=np.uint8)
    for kk in (3, 2, 1):
        k[16 * num <= kk * kk * nmax] = kk
    return k.reshape(-1)

def embed(arr, payload: bytes):
    bits = format(len(payload), "032b") + "".join(format(b, "08b") for b in payload)
    flat, ks = arr.reshape(-1).copy(), _k_map(arr)
    p = 0
    for i in range(flat.size):
        if p >= len(bits): break
        k = int(ks[i])
        chunk = int(bits[p:p + k].ljust(k, "0"), 2); p += k
        flat[i] = (int(flat[i]) & (0xFF << k) & 0xFF) | chunk          # Eq. 7
    if p < len(bits): raise ValueError("logo too small for payload")
    return flat.reshape(arr.shape)

def extract(arr):
    flat, ks = arr.reshape(-1), _k_map(arr)
    bits, need = [], None
    for i in range(flat.size):
        k = int(ks[i]); bits.append(format(int(flat[i]) & ((1 << k) - 1), "0%db" % k))
        s = "".join(bits)
        if need is None and len(s) >= 32:
            n = int(s[:32], 2)
            if n > 4096: raise ValueError("no hidden payload")
            need = 32 + 8 * n
        if need and len(s) >= need:
            return bytes(int(s[32 + 8 * j:40 + 8 * j], 2) for j in range((need - 32) // 8))
    raise ValueError("no hidden payload")

def to_png(arr):
    b = io.BytesIO(); Image.fromarray(arr).save(b, "PNG"); return b.getvalue()

def from_png(data):
    return np.array(Image.open(io.BytesIO(data)).convert("RGB"))

def psnr(a, b):
    mse = np.mean((a.astype(float) - b.astype(float)) ** 2)
    return float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)

def ssim_global(a, b):
    a, b = a.astype(float), b.astype(float)
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    ma, mb, va, vb = a.mean(), b.mean(), a.var(), b.var()
    cov = ((a - ma) * (b - mb)).mean()
    return ((2 * ma * mb + c1) * (2 * cov + c2)) / ((ma ** 2 + mb ** 2 + c1) * (va + vb + c2))

# ------------------------------------------------------------- DSAT issuer
class DSATIssuer:
    def __init__(self, server_secret: bytes = None):
        self.Ks = server_secret or os.urandom(32)
        self.Ke = PBKDF2(self.Ks, b"dsat-v1-enc", 32, count=100_000, hmac_hash_module=SHA256)
        self.sessions = {}      # sid -> bank id
        self.logos = {}
        self.recent = {}        # sha256(blob) -> {bank, domain, t}
        self.listeners = []     # callbacks(hash, bank, domain)

    def _logo(self, bank):
        return self.logos.setdefault(bank, make_logo(bank))

    def dsat(self, bid, dom, ts, sid, nonce):   # Eq. 3, using HMAC-SHA256 keyed by Ks
        msg = "|".join([bid, dom, str(ts), sid, nonce]).encode()
        return hmac.new(self.Ks, msg, hashlib.sha256).hexdigest()

    def issue(self, bank="indianbank", ts=None):
        """Fresh token -> encrypted (AES-256-GCM) -> embedded in logo. Returns (png, sid)."""
        ts = int(ts if ts is not None else time.time())
        dom, sid, nonce = REGISTRY[bank], os.urandom(8).hex(), os.urandom(16).hex()  # 128-bit nonce
        body = json.dumps(dict(b=bank, d=dom, t=ts, s=sid, n=nonce,
                               m=self.dsat(bank, dom, ts, sid, nonce))).encode()
        c = AES.new(self.Ke, AES.MODE_GCM); ct, tag = c.encrypt_and_digest(body)
        self.sessions[sid] = bank
        blob = c.nonce + tag + ct
        h = hashlib.sha256(blob).hexdigest()
        self.recent[h] = dict(bank=bank, domain=dom, t=time.time())
        if len(self.recent) > 500:
            self.recent = {k: v for k, v in self.recent.items() if time.time() - v["t"] < 120}
        for cb in self.listeners: cb(h, bank, dom)
        return to_png(embed(self._logo(bank), blob)), sid

    def verify(self, png: bytes, page_url: str, now=None):
        """Two-layer check (Eq. 10: A = U AND Match). Returns dict."""
        now = now if now is not None else time.time()
        u = validate_url(page_url)
        res = dict(accepted=False, url=u, stage="url", reason=u["reason"])
        if not u["valid"]: return res
        res["stage"] = "token"
        try:
            blob = extract(from_png(png))
            nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
            tok = json.loads(AES.new(self.Ke, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag))
        except Exception:
            res["reason"] = "no valid DSAT in logo (missing, corrupted or forged)"; return res
        if tok["d"] != u["domain"]:
            res["reason"] = "token bound to a different domain"; return res
        if not (-2 <= now - tok["t"] <= VALIDITY_WINDOW):        # Eq. 6
            res["reason"] = "token expired (replay?)"; return res
        if tok["s"] not in self.sessions or not hmac.compare_digest(
                tok["m"], self.dsat(tok["b"], tok["d"], tok["t"], tok["s"], tok["n"])):
            res["reason"] = "token does not match server record"; return res
        return dict(res, accepted=True, stage="done", reason="URL valid and DSAT matches")
