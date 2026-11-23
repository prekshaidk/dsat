# DSAT – Dynamic Steganographic Authentication Token (prototype)

## Run
    pip install -r requirements.txt
    python app.py          # demo UI at http://127.0.0.1:5000 (8 attack scenarios)
    python evaluate.py 300 # metrics on a synthetic dataset (300 legit + 1800 phishing)

## Files
- `dsat_core.py` – URL validation (Levenshtein, tau=2), DSAT generation (HMAC-SHA256),
  AES-256-GCM encryption (PBKDF2 key), adaptive-LSB embed/extract, PSNR/SSIM, verifier.
- `app.py` – Flask bank/verifier simulation + demo page.
- `evaluate.py` – accuracy/precision/recall/F1/FPR/FNR, latency, per-attack results.

## Deliberate changes from the paper (needed to make it actually secure/working)
1. **Unknown domains are rejected.** Eq. 2 marks a domain "legitimate" if d_lev > tau, which would pass any unrelated domain. Here only registry domains pass.
2. **Token is bound to the page's domain.** The verifier requires token.domain == domain of the URL the user is on, which defeats real-time relaying of the genuine logo.
3. **HMAC instead of plain SHA-256(... || Ks)**, and **AES-GCM** (authenticated) instead of bare AES.
4. **The verifier asks the server** (it needs Ks / Ke); a client cannot compare against "the server token" otherwise.
5. **k >= 1** in Eq. 8 (k = 0 would embed nothing), and k is derived from the upper 4 bits so the extractor recomputes the same map.
6. **PNG only.** LSB data does not survive JPEG compression or resizing.

## Chrome extension (extension/) - private whitelist / blacklist
The lists live in `data/banks.json`. They are INTERNAL: no web page shows them, and the API that serves them
(`/api/lists`, `/api/codes`, `/api/stream`) only answers a paired extension (header `X-DSAT-Key`, see `KEY` in app.py and background.js).

1. `python app.py` (leave it running).
2. Chrome -> `chrome://extensions` -> **Developer mode** -> **Load unpacked** -> select the `extension` folder
   (after any edit, press the reload icon on its card).
3. Type a bank address in the address bar:

   | Real banks (whitelist) | Fake banks (blacklist) |
   |---|---|
   | indianbank.localhost:5000 | indiianbank.localhost:5000 |
   | hdfcbank.localhost:5000 | indianbank-otp-verify.localhost:5000 |
   | sbibank.localhost:5000 | hdfc-secure-login.localhost:5000 |
   | icicibank.localhost:5000 | hdfcbank.account-verify.localhost:5000 |
   | axisbank.localhost:5000 | sbibank-verify.localhost:5000 |
   | kotakbank.localhost:5000 | sbibank.secure-login.localhost:5000 |
   | pnbindia.localhost:5000 | netbanking-sbi-offers.localhost:5000 |
   | bankofbaroda.localhost:5000 | icicibank-login.localhost:5000 |
   | canarabank.localhost:5000 | icicibank-prize.localhost:5000 |
   | unionbank.localhost:5000 | axisbamk.localhost:5000 |
   | yesbank.localhost:5000 | axis-bank-kyc-update.localhost:5000 |
   | idfcfirstbank.localhost:5000 | axisbank.loan-offer.localhost:5000 |
   |  | kotakbank-rewards.localhost:5000 |
   |  | kotak-mahindra-verify.localhost:5000 |
   |  | pnbindia-alert.localhost:5000 |
   |  | pnb1ndia.localhost:5000 |
   |  | bankofbaroda-netbanking.localhost:5000 |
   |  | bobbank-refund.localhost:5000 |
   |  | canarabank-support.localhost:5000 |
   |  | canara-bank-login.localhost:5000 |
   |  | unionbank-kyc.localhost:5000 |
   |  | yesbnk.localhost:5000 |
   |  | yesbank-cashback.localhost:5000 |
   |  | idfcfirst-login.localhost:5000 |

   Any unlisted look-alike (e.g. `hdfcbank-online.localhost:5000`) is blocked automatically as suspicious.
4. Shortcut: type `bank`, press Space, then a bank name (e.g. `bank hdfc`) to get verified bank suggestions.

What happens: every URL is checked BEFORE the page loads. Blacklisted/look-alike -> "Phishing website blocked" page.
Whitelisted -> page loads, then the extension reads the hidden code from the logo (the logo reloads every 10 s with a fresh code),
compares it with the live codes the server pushes to it, and shows "Verified genuine bank website" (or a fake-website error if
the code is missing, wrong, expired, or was issued for another domain).
