"""Reproducible evaluation on a SYNTHETIC dataset (no internet / PhishTank needed).
Usage: python evaluate.py [N_per_class=300]"""
import random, sys, time, string
import numpy as np
from dsat_core import *

random.seed(1)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
I = DSATIssuer()
PLAIN = {b: to_png(make_logo(b)) for b in REGISTRY}

def typo(d):
    s, i = list(d), random.randrange(1, len(d) - 3)
    op = random.choice("ids t".replace(" ", ""))
    if op == "i": s.insert(i, s[i])
    elif op == "d": del s[i]
    elif op == "s": s[i] = random.choice(string.ascii_lowercase)
    else: s[i], s[i + 1] = s[i + 1], s[i]
    r = "".join(s)
    return r if r != d else typo(d)   # never return the original domain

def rand_dom(): return "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 12))) + random.choice([".com", ".xyz", ".in", ".net"])

cases = []  # (label_is_phishing, kind, url, png, now_offset)
for _ in range(N):
    b = random.choice(list(REGISTRY)); d = REGISTRY[b]; brand = d.split(".")[0]
    cases.append((0, "legit", f"https://{d}/login", I.issue(b)[0], 0))
    cases.append((1, "typosquat+relayed logo", f"https://{typo(d)}/", I.issue(b)[0], 0))
    cases.append((1, "brand-in-domain+copied logo", f"https://{brand}-secure-{rand_dom()}", PLAIN[b], 0))
    cases.append((1, "unrelated domain", f"https://{rand_dom()}/", PLAIN[b], 0))
    cases.append((1, "subdomain trick", f"https://{d}.{rand_dom()}/", I.issue(b)[0], 0))
    cases.append((1, "hijacked URL, no token", f"https://{d}/login", PLAIN[b], 0))
    cases.append((1, "replayed old token", f"https://{d}/login", I.issue(b, ts=time.time() - random.randint(90, 3600))[0], 0))

def metrics(rows, pred):
    tp = sum(1 for r, p in zip(rows, pred) if r[0] and p); fn = sum(1 for r, p in zip(rows, pred) if r[0] and not p)
    fp = sum(1 for r, p in zip(rows, pred) if not r[0] and p); tn = sum(1 for r, p in zip(rows, pred) if not r[0] and not p)
    pr, rc = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    return dict(acc=(tp + tn) / len(rows), prec=pr, rec=rc, f1=2 * pr * rc / max(pr + rc, 1e-9),
                fpr=fp / max(fp + tn, 1), fnr=fn / max(fn + tp, 1))

t0 = time.perf_counter()
full = [not I.verify(c[3], c[2])["accepted"] for c in cases]
lat = (time.perf_counter() - t0) / len(cases) * 1000
urlonly = [not validate_url(c[2])["valid"] for c in cases]

print(f"{len(cases)} synthetic cases ({N} legit, {len(cases)-N} phishing)\n")
for name, pred in [("URL validation only", urlonly), ("URL + DSAT (full)", full)]:
    m = metrics(cases, pred)
    print(f"{name:22s} acc={m['acc']:.3%} prec={m['prec']:.3%} rec={m['rec']:.3%} f1={m['f1']:.3%} FPR={m['fpr']:.2%} FNR={m['fnr']:.2%}")
print(f"\nMean verification latency: {lat:.1f} ms/case")
print("\nPer attack type (full pipeline, fraction blocked):")
for k in sorted({c[1] for c in cases if c[0]}):
    idx = [i for i, c in enumerate(cases) if c[1] == k]
    print(f"  {k:30s} {sum(full[i] for i in idx)/len(idx):.1%}")
ps, ss = [], []
for b in REGISTRY:
    a, s = make_logo(b), from_png(I.issue(b)[0]); ps.append(psnr(a, s)); ss.append(ssim_global(a, s))
print(f"\nImage quality: PSNR={np.mean(ps):.1f} dB  SSIM={np.mean(ss):.5f}")
