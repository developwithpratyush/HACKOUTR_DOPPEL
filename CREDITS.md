# Credits

Append-only, by both sides. Every imported library, copied snippet, dataset and borrowed idea gets a line here (and in the commit message that introduced it). Rule: `docs/ps08-prior-art.md`. Learn from anything; copy only from licensed code; unlicensed code is read and reimplemented, never copied.

## Libraries (imported)

| Library | Licence | Used for | Since |
|---|---|---|---|
| [Typer](https://github.com/fastapi/typer) | MIT | CLI | P0 |
| [jsonschema](https://github.com/python-jsonschema/jsonschema) | MIT | contract validation | P0 |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | brand registry | P0 |
| [publicsuffixlist](https://github.com/ko-zu/psl) | MPL-2.0 (bundles the Public Suffix List, MPL-2.0) | real-owner parsing (declared in P0, used from P2) | P0 |
| [idna](https://github.com/kjd/idna) | BSD-3-Clause | IDNA2008 decoding (declared in P0, used from P2) | P0 |
| [pytest](https://github.com/pytest-dev/pytest) | MIT | tests | P0 |
| [dnstwist](https://github.com/elceef/dnstwist) | Apache-2.0 | Typo, homoglyph and bitsquat look-alike generation (P3), imported | P3 |
| [ail-typo-squatting](https://github.com/typosquatter/ail-typo-squatting) | BSD-2-Clause | Hyphen-insertion variants (P3), imported | P3 |
| [wordninja](https://github.com/keredson/wordninja) | MIT (code and its English word list) | Splitting glued names into words, with our brand and lure vocabulary added (P4 combosquat parser, P2 glued short brands) | P4 |
| [RapidFuzz](https://github.com/rapidfuzz/RapidFuzz) | MIT | Pre-filter before our visual DP; the Levenshtein baseline | P4 |
| [jellyfish](https://github.com/jamesturk/jellyfish) | MIT | Metaphone keys for soundsquat detection | P4 |
| [scikit-image](https://github.com/scikit-image/scikit-image) | BSD-3-Clause | SSIM for the glyph matrix and the SMS-view render | P4 |
| [Pillow](https://github.com/python-pillow/Pillow) | MIT-CMU (HPND) | Font rendering | P4 |
| [fontTools](https://github.com/fonttools/fonttools) | MIT | Which characters each font draws | P4 |
| [FastAPI](https://github.com/fastapi/fastapi) + [Starlette](https://github.com/encode/starlette), [Uvicorn](https://github.com/encode/uvicorn), [python-multipart](https://github.com/Kludex/python-multipart) | MIT / BSD-3-Clause / BSD-3-Clause / Apache-2.0 | The HTTP API around the brain; file uploads | P6 |
| [HTTPX](https://github.com/encode/httpx) | BSD-3-Clause | API tests (FastAPI's TestClient) | P6 |
| [React](https://github.com/facebook/react) | MIT | Analyst UI | P6 |
| [Vite](https://github.com/vitejs/vite) + @vitejs/plugin-react, [Vitest](https://github.com/vitest-dev/vitest), [TypeScript](https://github.com/microsoft/TypeScript) | MIT / MIT / Apache-2.0 | UI build, UI unit tests, types | P6 |
| [Tailwind CSS](https://github.com/tailwindlabs/tailwindcss) | MIT | UI layout utilities | P6 |
| [Fontsource](https://github.com/fontsource/fontsource) packages of Inter, JetBrains Mono, Roboto | SIL OFL 1.1 (as each package declares) | Fonts bundled into the UI so it needs no internet; Roboto is also the SMS-view font | P6 |
| [NumPy](https://numpy.org) | BSD-3-Clause | Arrays for SSIM and the calibration fit | P4 |
| [matplotlib](https://matplotlib.org) | PSF-based (matplotlib licence) | Arena heatmap (bench only) | P4 |
| [scikit-learn](https://github.com/scikit-learn/scikit-learn), [SciPy](https://scipy.org), [pandas](https://github.com/pandas-dev/pandas) | BSD-3-Clause | Risk Model training, leakage audit, calibration (training only: inference is our own pure Python) | P7 |
| [Playwright for Python](https://github.com/microsoft/playwright-python) (+ the Chromium build it downloads) | Apache-2.0 (Chromium: BSD-3-Clause and others) | Genuine-page snapshots, the Deep-stage sandboxed browser | P8 |
| [ImageHash](https://github.com/JohannesBuchner/imagehash) | BSD-2-Clause | pHash distance for the Page Inspector | P8 |
| [Google Gen AI SDK](https://github.com/googleapis/python-genai) (Gemini API) | Apache-2.0 (SDK); API under Google's terms | Vision AI brand claim (C12/C13) | P8 |
| [Groq Python SDK](https://github.com/groq/groq-python) (Groq API: `openai/gpt-oss-120b`, `qwen/qwen3.8-27b`, `openai/gpt-oss-20b`) | Apache-2.0 (SDK); API under Groq's terms; model weights under their own licences | Case-File Writer narration (EN/HI), validated sentence by sentence | P10 |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | BSD-3-Clause | Reading API keys from the gitignored `.env` | P8 |
| [websockets](https://github.com/python-websockets/websockets) | BSD-3-Clause | The Live Hunt collector's certstream connection (and the local fake stream in its tests) | P12 |
| [NetworkX](https://github.com/networkx/networkx) | BSD-3-Clause | Campaign Radar: connected components of the C18 link graph | P13 |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | Parsing X.509 certificates (SANs, Organisation, policy OIDs) for Certificate Forensics | P11 |

## Data

| Source | Licence | Used for | Since |
|---|---|---|---|
| PhiUSIIL Phishing URL Dataset, A. Prasad & S. Chandra, [UCI ML Repository #967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | CC BY 4.0 | Risk model training data (P7), dataset audit | P1 |
| Newly Registered Domains, [hagezi/nrd](https://github.com/hagezi/nrd) (base data: Stamus Labs) | GPL-3.0 (used as data) | Batch / speed / false-positive tests, hard negatives | P1 |
| Unicode confusables.txt 18.0.0, [UTS #39](https://www.unicode.org/reports/tr39/) | Unicode License v3 | UTS-39 skeleton (P2), homoglyph seeds | P1 |
| Unicode 18.0.0 Scripts.txt, ScriptExtensions.txt, PropertyValueAliases.txt ([UCD](https://www.unicode.org/Public/UCD/latest/ucd/)); vendored with confusables.txt in `doppel/address/unicode/` | Unicode License v3 | Mixed-script detection (P2) | P2 |
| Free-hosting platforms missing from the PSL, derived from PhiUSIIL (`doppel/address/free_hosting_extra.txt`) | derived from CC BY 4.0 data | Address Reader owner resolution (P2) | P2 |
| confusable-vision release 2026.09.26, Paul Wood FRSA (@paultendo), [github.com/paultendo/confusable-vision](https://github.com/paultendo/confusable-vision) | CC BY 4.0 | Ground truth that calibrates our SSIM → cost mapping (in-place verdicts + within-font survey), and Unicode candidate characters for the P4 glyph matrix; unchanged | P1 |
| [Roboto](https://github.com/googlefonts/roboto-classic) and [Noto Sans](https://github.com/notofonts/latin-greek-cyrillic), via [google/fonts](https://github.com/google/fonts) (pinned commits in `scripts/data/fetch.py`) | SIL OFL 1.1 (licence texts vendored next to the fonts) | Phone-font renders for the glyph matrix and the SMS view; vendored unmodified in `doppel/perception/fonts/` | P4 |
| PhiUSIIL `TLD` column counts → `doppel/tricks/tld_risk.json` | derived from CC BY 4.0 data | Weak ending-risk hint (C6) | P4 |
| Risk Model weights trained on PhiUSIIL hosts → `doppel/risk/model/` | derived from CC BY 4.0 data | ML risk (C8, weak) | P7 |
| Genuine page snapshots of our 8 brands (`data/snapshots/`, captured by `scripts/data/snapshot_genuine.py`) and 10 well-known sites for the VLM accuracy set (`data/snapshots/_vlm/`) | the brands' own content: used locally for comparison and evaluation only, **never committed or redistributed** (gitignored; only `MANIFEST.json` is committed) | Page Inspector references, local clone fixtures, Vision AI accuracy | P8 |
| [codebox/homoglyph](https://github.com/codebox/homoglyph) chars.txt | MIT | Homoglyph seed groups | P1 |
| [life4/homoglyphs](https://github.com/life4/homoglyphs) confusables.json | MIT | Homoglyph seed map | P1 |
| [IANA Root Zone Database](https://www.iana.org/domains/root/db) | public records | Brand-TLD ownership (registry) | P1 |
| [Majestic Million](https://majestic.com/reports/majestic-million) (daily list, fetched 2026-11-05) | CC BY 3.0 | Hard negatives: popular domains that resemble a brand (P3) | P3 |
| Brand pages, ICICI Bank's NSE filing (28 Oct 2025), Wikipedia ".in" | cited as sources | Genuine-family verification (`data/brands/registry.yaml`) | P1 |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) ACTIVE domains (392,178, downloaded 2026-11-06; the India-brand slice frozen in `bench/data/pdb_india_slice.txt`) | MIT | The no-degradation gate (`bench/regress.py`), the P11 eval | P11 |
| TLS certificates served by the brands' own proven sites (live reads, cached in `data/certs/tls/`) | public documents | Family auto-discovery (SAN links), legal names, the OV/EV coverage table | P11 |
| Certificate Transparency records via the [SSLMate CT Search API](https://sslmate.com/ct_search_api/) (certspotter) and [crt.sh](https://crt.sh) (cached in `data/certs/ct/`) | public CT logs; services under their terms | Certificate history of suspects (C17) and their validated organisation (C16); never a connection to a suspect | P11 |
| The public certstream feed (`wss://api.certstream.dev/`), names from public Certificate Transparency logs as they're logged; raw hours recorded locally for replay (`runs/live/recordings/`, gitignored) | public CT logs; service under its operator's terms | Live Hunt: every new certificate's names judged live (P12); names only, no suspect contacted | P12 |
| [hagezi/nrd](https://github.com/hagezi/nrd) `nrd7.txt`, fetched daily (unpinned, `main`), and [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) ACTIVE, polled hourly (both kept in gitignored `runs/live/`) | GPL-3.0 / MIT (used as data) | The sleeper watch list (P12) and the blocklist lead time (P12) | P12 |
| Google's IMAP/SMTP developer page ([developers.google.com](https://developers.google.com/workspace/gmail/imap/imap-smtp)), Wikipedia (NPCI) | cited as sources | `gmail.com` and `npci.org.in` registry entries | P11 |

## Code copied or adapted

| From | Licence | What | Where in our repo | Since |
|---|---|---|---|---|

## Ideas we built on (no code copied)

| Idea | Source |
|---|---|
| Evidence-first verdict with stage escalation and a decision trace | Our design (`docs/ps08-solution-direction.md`) |
| Visual edit distance for look-alike domains | Woodbridge et al. 2018, [arXiv:1805.09738](https://arxiv.org/abs/1805.09738) |
| Submitting fake credentials to expose a phishing kit | DynaPhish (USENIX Security '23) |
| Telegram bot-token pattern (detect + redact only; Telegram is never called) | woodpecker (no licence: the idea only, regex written by us) |
| Client-side kit exfil channels (Telegram bots, Discord webhooks, Google Forms) modelled in the P9 kit zoo | Cofense, Imperva, Group-IB public write-ups (ideas only; no kit code) |
| Combosquatting as the dominant look-alike form | Kintis et al., CCS 2017 |
| A certificate's SAN list as proof that one operator controls every name on it (the CA validates each name) | CA/Browser Forum Baseline Requirements §3.2.2.4–3.2.2.6 (our use: family auto-discovery) |
| Heuristic baseline scoring (suspicious TLDs, entropy, keyword weights, Levenshtein-1 to brand keywords) | [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher) (GPL-3): logic re-written in our own code in `bench/p4_arena.py` with our own keyword list; no code or data copied |
| dnstwist's ASCII glyph table as a list of multi-letter twin *candidates* (lb/b, dl/d, lh/h, lc/k), each re-measured by us | [dnstwist](https://github.com/elceef/dnstwist) (Apache-2.0), read through its API |
| Skeleton and mixed-script (resolved script set) algorithms | Unicode UTS #39 (§4 skeleton, §5.1 resolved script set), implemented from the spec in `doppel/address/unicode_data.py`; no code copied |
