// Adaptive-LSB reader. Mirrors dsat_core.py (_k_map / extract) with exact integer maths.
function dsatKMap(d, W, H) {                       // d = RGBA bytes from canvas
  const n = W * H * 3, hi = new Int32Array(n);
  for (let p = 0; p < W * H; p++) for (let c = 0; c < 3; c++) hi[3 * p + c] = d[4 * p + c] & 0xF0;
  const num = new Int32Array(n); let nmax = 0;
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) for (let c = 0; c < 3; c++) {
    let s1 = 0, s2 = 0;
    for (let dy = -1; dy <= 1; dy++) {
      const yy = Math.min(H - 1, Math.max(0, y + dy));
      for (let dx = -1; dx <= 1; dx++) {
        const xx = Math.min(W - 1, Math.max(0, x + dx));
        const v = hi[3 * (yy * W + xx) + c]; s1 += v; s2 += v * v;
      }
    }
    const q = 9 * s2 - s1 * s1; num[3 * (y * W + x) + c] = q; if (q > nmax) nmax = q;
  }
  const k = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    let kk = 4; for (let t = 3; t >= 1; t--) if (16 * num[i] <= t * t * nmax) kk = t;
    k[i] = kk;
  }
  return k;
}
function dsatExtract(d, W, H) {                    // returns Uint8Array payload (encrypted DSAT blob)
  const ks = dsatKMap(d, W, H), parts = []; let len = 0, need = null;
  for (let i = 0; i < ks.length; i++) {
    const k = ks[i], v = d[4 * Math.floor(i / 3) + (i % 3)] & ((1 << k) - 1);
    parts.push(v.toString(2).padStart(k, "0")); len += k;
    if (need === null && len >= 32) {
      const n = parseInt(parts.join("").slice(0, 32), 2);
      if (n > 4096) throw new Error("no hidden code");
      need = 32 + 8 * n;
    }
    if (need !== null && len >= need) {
      const s = parts.join(""), out = new Uint8Array((need - 32) / 8);
      for (let j = 0; j < out.length; j++) out[j] = parseInt(s.slice(32 + 8 * j, 40 + 8 * j), 2);
      return out;
    }
  }
  throw new Error("no hidden code");
}
if (typeof module !== "undefined") module.exports = { dsatExtract };
