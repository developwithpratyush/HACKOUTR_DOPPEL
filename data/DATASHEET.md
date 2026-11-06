# Datasheet: Doppel data (P1)

**Owner:** Core side (built solo under decision 002). **Last built:** 2026-11-05.

Every dataset here can be rebuilt from scratch:

```bash
python scripts/data/fetch.py             # download into data/raw/ (gitignored), verify SHA-256 pins
python scripts/data/profile.py           # recompute every number below into data/STATS.json
python scripts/data/verify_registry.py --sources   # re-check the brand registry live
```

Raw files are **not committed** (≈117 MB). Small derived files are committed: `data/STATS.json`, `data/brands/registry.yaml`, `data/brands/verification.json`, `data/lookalikes/ascii_twins.yaml`.

**Safety:** domain lists are used as **names only**. No script here contacts a listed domain; `verify_registry.py` only contacts the brands' own genuine domains and our cited sources.

---

## 1. Raw datasets

| Name | What it is | Source (pinned) | Licence | Size | SHA-256 (prefix) |
|---|---|---|---|---|---|
| `phiusiil` | PhiUSIIL Phishing URL Dataset: 56 columns (URL, a few text fields such as Domain/TLD/Title, ~50 numeric features, label) | [UCI dataset 967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (static zip) | CC BY 4.0 | 15.4 MB zip | `0a639fd03aea6308` |
| `nrd7` | Newly registered domains, 7 days to yesterday (Stamus Labs data via hagezi) | [hagezi/nrd](https://github.com/hagezi/nrd) @ `b9bd225` (list version 2026.1104.0713.22) | GPL-3.0 (used as data, not code) | 38.9 MB | `00d5382963f2df5c` |
| `confusables` | Unicode UTS #39 confusables, version 18.0.0, dated 2026-08-06 | [unicode.org/Public/security/latest](https://www.unicode.org/Public/security/latest/confusables.txt) (no versioned URL for 18.0.0; the script checks the version line) | Unicode License v3 | 0.76 MB | `6ed3ee967c9dfdf6` |
| `cv_lookalikes`, `cv_sequences`, `cv_in_place` (+ `DATASET.md`, `SHA256SUMS`) | confusable-vision release 2026.09.26: glyph-outline look-alike measurements across 322 fonts | [paultendo/confusable-vision](https://github.com/paultendo/confusable-vision) @ `e5b74b3`, verified against the release's own SHA256SUMS | CC BY 4.0 (data) | 1.3 MB gz | per file in `scripts/data/fetch.py` |
| `codebox_homoglyph` | Homoglyph groups (one line of look-alike characters per group) | [codebox/homoglyph](https://github.com/codebox/homoglyph) @ `522d061` | MIT | 23 KB | `635f56f2eab035d0` |
| `life4_homoglyphs` | Confusables map from the `homoglyphs` library (archived repo) | [life4/homoglyphs](https://github.com/life4/homoglyphs) @ `8e5552d` | MIT | 0.42 MB | `6ca4f3c2df4fb151` |
| `majestic_million` | Top 1M domains by referring subnets (daily; added in P3 for hard negatives) | [majestic.com](https://majestic.com/reports/majestic-million) (no versioned URL; header checked, hash in MANIFEST) | CC BY 3.0 | 80 MB | see `MANIFEST.json` |

Full hashes, byte counts and fetch times: `data/raw/MANIFEST.json` and `data/STATS.json` → `sources`.

**Not used:** the whoisds free NRD file (0 `.in` domains, 70k cap); ShamFinder's SimChar (no licence, so learn only).

---

## 2. What the data looks like (measured by `profile.py`)

### PhiUSIIL

| | Legitimate | Phishing |
|---|---|---|
| Rows (235,795 total, 56 columns) | 134,850 | 100,945 |
| Label value | **1** | **0** (inverted from what people assume) |
| `URLSimilarityIndex` = 100 | **100.0%** | 0.78% |
| URL starts with `https://www.` | **100.0%** | 2.43% |
| IDN (`xn--`) hosts | **0** | 154 |
| Host on a PSL *private* suffix (free hosting: web.app, firebaseapp.com…) | 0.08% | **26.53%** |
| Distinct registrable domains | 132,186 | 65,206 |

Top free-hosting suffixes among phishing rows: web.app 5,754 · firebaseapp.com 5,594 · repl.co 2,882 · workers.dev 1,438 · square.site 1,199 · ipfs.dweb.link 958 · pantheonsite.io 900.

**What this means for us:**
- **`URLSimilarityIndex` is a near-giveaway** (100 on every legitimate row). It must be dropped, along with any column that P7's single-feature AUC audit flags.
- **Legitimate rows are all `https://www.<homepage>`.** A model learns "popular homepage vs. not", not "look-alike vs. genuine". P7 strips scheme, `www` and path and uses host-only features, split by registrable domain.
- **No legitimate IDNs**, so "has punycode" would look perfectly predictive. That's a dataset artifact, not a real signal.
- **Correction to `docs/ps08-prior-art.md`:** about 26.5% of phishing rows sit on a **PSL private suffix**, not ~57%. The earlier figure must have counted hosting platforms the PSL doesn't list (e.g. `weeblysite.com` isn't in the PSL). P2 needs a small extra free-hosting list for those.

### NRD 7-day snapshot (hagezi, list version 2026.1104.0713.22)

| | Count |
|---|---|
| Domains | 2,342,440 |
| IDN (`xn--`) | 16,308 |
| `.in` | 3,353 |
| `.co.in` | 533 |
| `.bank.in` | 3 (`batlagunducoopurban`, `madurantakamcub`, `sreenivasapadmavathi`: new co-operative banks, so the Family Verifier should mark them genuine *banks* but not one of our brands) |
| `.gov.in`, `.fin.in` | 0 |

Top TLDs: com 1,154,352 · top 124,335 · shop 69,754 · my 66,022 · org 62,097.

Raw **substring** hits for brand aliases (an upper bound with lots of noise, e.g. `sbi` inside `thanksbitcoin`): sbi 1,010 · google 376 · income_tax 27 · parivahan 22 · hdfc 8 · icici 8 · india_post 3 · paytm 2. Token-aware parsing (P4) will cut these down; the gap is the point of the `thanksbitcoin` gallery case.

### Homoglyph / confusable data

| | Count |
|---|---|
| Unicode confusables 18.0.0 mappings | 6,712 (2,269 map to pure ASCII) |
| confusable-vision look-alike pairs | 12,074 |
| confusable-vision character↔2-letter-sequence pairs | 719 |
| confusable-vision in-place verdicts | strict 646 · broad 358 · design 101 · no 1,950 |
| codebox homoglyph groups | 1,915 |
| life4 confusables entries | 9,601 |

confusable-vision confirms **m ↔ rn**, 0 ↔ o, 1 ↔ l and I ↔ l as `strict` in place. It does **not** cover cl ↔ d or vv ↔ w, so those are seeds in `data/lookalikes/ascii_twins.yaml` until P4 measures them with SSIM.

---

## 3. Data we created

### `data/brands/registry.yaml`: protected brands and their genuine families

8 brands (SBI, HDFC Bank, ICICI Bank, Paytm, India Post, Parivahan/e-Challan, Income Tax e-filing, Google), 25 genuine-family entries, 6 brand TLDs, 4 restricted registries, 97 shared lure words (85 English, 12 Hinglish) plus brand-specific lures.

**How each entry was verified (2026-11-05):**
1. Named or linked on the brand's own page, in an exchange filing (ICICI's NSE filing of 28 Oct 2025), or in the IANA root zone database (brand TLDs).
2. Resolves in DNS. Legacy addresses redirect to the new one: `www.hdfcbank.com` → `www.hdfc.bank.in`, `www.icicibank.com` → `www.icici.bank.in`, `onlinesbi.sbi` → `onlinesbi.sbi.bank.in`, and `sbi.co.in` / `bank.sbi` refresh to `sbi.bank.in`.
3. Two family names don't resolve today. `onlinesbi.com` is still linked by SBI, and RDAP shows it registered since 2000, locked, expiring 2031. `incometaxindiaefiling.gov.in` is under gov.in, so it can't be re-registered by outsiders. Both stay in the family with a note.

**User-content hosts.** Some brand-owned hosts let *anyone* publish (`forms.gle`, `docs.google.com`, `sites.google.com`, `script.google.com`, `drive.google.com`, `groups.google.com`). They're listed under `user_content_hosts`, and ownership of them must never make a page green. Phishers use Google Forms to collect bank logins.

**Still weak (honest list):**
- `paytm.com`'s source is Paytm's own page; a third-party anchor (NSE company page) is still to add.
- `gov.in`, `fin.in`, `nic.in` rules are cited from Wikipedia. The official registry.gov.in pages render by script and failed TLS verification from our client.
- `.hdfc` is still listed by IANA under HDFC Ltd (merged into HDFC Bank in 2023), so its row is `verified_on: null`.
- `fin.in` is announced, but we found no launch date and no names in use.
- Logos aren't collected yet (P8 needs them).

### `data/lookalikes/ascii_twins.yaml`

14 ASCII look-alike pairs (6 multi-character, 8 single-character), each marked `measured` (confusable-vision tier) or `seed` (to be measured in P4). Capital `I` → `l` is marked `domain_possible: false`, because DNS lowercases names, so it only fools inside message text.

---

### `data/pairs/pairs.csv`: look-alike pairs (deliverable 2, P3)

27,832 rows:
- 17,168 synthetic look-alikes across T1–T7, T11–T13
- 201 real PhiUSIIL phishing names that target our brands
- 65 genuine family names
- 398 hard negatives (popular domains that resemble a brand)
- 10,000 benign NRD names

ICICI and India Post are held out as unseen brands. Full datasheet, technique counts and splits: **[`data/pairs/README.md`](pairs/README.md)**, rendered from `data/pairs/SUMMARY.json`. Rebuild with `python -m doppel.generator.pairs`.

## 4. Known limitations

- **NRD is a 7-day window from one feed (Stamus Labs).** Stamus doesn't guarantee daily updates, and coverage of ccTLDs like `.in` is partial.
- **PhiUSIIL is generic phishing vs. popular homepages, not look-alike pairs.** Our own pairs (P3) carry the look-alike evaluation.
- **The registry reflects 2026-11-05.** Banks are mid-migration, and family lists change. Rerun `verify_registry.py` before each demo.
- **The lure lexicon is hand-built.** It has no measured precision yet; P4 measures it on NRD hits.
