# Contracts (v1.1.0)

**Owner:** Signature side drafts; **any change needs both sides to agree** (a decision file or an acknowledged status-file request). Accepted in `team/decisions/003-evidence-contract-v1.md`; v1.1.0 (checks C16–C18) in `004-evidence-contract-v1.1.md`.

| File | What it fixes |
|---|---|
| `evidence.schema.json` | One **evidence item** (what every tool returns), one **verdict** (what the brain outputs), and a **scan result** (a batch) |
| `registry.schema.json` | The format of `data/brands/registry.yaml` |
| `examples/*.json` | Mock verdicts, one per Deception Gallery case. UI, exporters and the case-file writer build against these. `meta.mock = true`: the numbers are illustrative, not measured |
| `examples/build_examples.py` | Generates the examples. Edit the cases there, then run it; it validates as it writes |

Check anything against the contract with `python -m doppel.cli validate <files>` (or `doppel validate` if the script is on PATH), or from code with `doppel.contract.validate_verdict(...)`.

---

## 1. Evidence item

Every tool returns a list of these. The brain sends `{tool, args}`; the tool answers with evidence.

| Field | Meaning |
|---|---|
| `evidence_id` | `E1`, `E2`, … unique within a verdict. The trace, the hard rule, the what-if and the report cite these |
| `tool` | `address_reader`, `family_verifier`, `trick_detector`, `human_eye_renderer`, `risk_model`, `page_probe`, `page_inspector`, `vision_ai`, `credential_tracker`; v1.1.0: `cert_forensics`, `ct_history`, `campaign_radar` (P13) |
| `stage` | `quick`, `standard`, `deep` |
| `criterion` | `C1`–`C15`, the fake-vs-real criteria in `docs/architecture.html` §5; v1.1.0 adds `C16` certificate identity, `C17` certificate history, `C18` campaign link |
| `finding` | snake_case name of what was found (vocabulary below) |
| `points_to` | `phishing`, `genuine` or `neutral` (a clean check, e.g. "no hidden letters") |
| `strength` | `strong` / `medium` / `weak`, the criterion's weight class |
| `score` | 0–1, how strongly the finding holds *in the `points_to` direction*. Neutral findings have score 0 |
| `target_brand` | `{id, name}` of the brand the finding is about, or `null` |
| `summary` | One plain line a human can check by eye |
| `details` | Tool-specific payload. Two shapes are fixed: `edits` (aligned character edits the UI highlights) and `artifacts` (screenshot / heatmap / render / HAR paths) |
| `duration_ms` | Optional: how long the call took |

**Implemented in P2** (`doppel/address`, `doppel/family`); detail keys their evidence carries:
- `owner_*`: `owner`, `public_suffix`, `private_suffix`, `subdomain_labels`, plus `embedded_domain` / `embedded_suffix` (owner_differs) or `platform` (free_hosting_owner).
- `mixed_script` / `whole_script_confusable`: `scripts`, `unicode`, `uts39_skeleton` (for comparison only, not for display: m→rn, so "paytm.com" becomes "paytrn.corn"), `edits`.
- `family_verifier`: `proofs_checked`, `proofs_matched`. `genuine_family` adds `family_entry`, `source`, `verified_on`, `verified`. Imitations add `imitated` and `matched_by` ∈ level_squat, trust_signal, skeleton, alias_token.

**Implemented in P4** (`doppel/tricks`, `doppel/perception`); detail keys:
- trick findings (C5) carry `genuine` (the family address imitated) plus: `edits` (homoglyph, twin_letters, typo, bitsquat), `folded` (homoglyph: the name with look-alike letters folded), `levenshtein` (twin_letters), `metaphone` (soundsquat), `tokens` / `brand_alias` / `lure_words` / `platform` (combosquat), `ending` (tld_swap).
- `brand_closeness` (C4): `closeness`, `genuine`, `compared` (the brand name aligned), `levenshtein_similarity`, `per_brand` (top 3), `edits`, `method` (visual, local, token, fold, sound, tld, level_squat, trust_signal, skeleton). `far_from_all_brands`: `per_brand`.
- `abused_tld` (C6, weak): `tld`, `risk`, `phishing`, `legitimate` (PhiUSIIL counts).
- `human_eye_renderer` (C7): `ssim`, `visual_edit_distance` or `matching_prefix_chars`, and an `artifacts` render (`runs/renders/<host>_sms.png`).
- New names (minor change): `bitsquat`, `soundsquat`, `sms_view_distinct`.

**Implemented in P5** (`doppel/brain`): `page_probe` reads only local fixtures (`demo/fixtures/sites.yaml`) and never contacts a real domain; any other name gets the neutral `not_probed` (new, minor). Details: `status`, `fixture`, `mock`, `has_login_form`, `asks_for`, `form_actions`, `title`. Verdicts from fixtures carry `meta.mock = true`. The Deep stage is always skipped until P8/P9, so H2–H4 can't fire yet.

**Implemented in P8** (`doppel/deep`): the Deep stage opens **local fixtures only** (`demo/fixtures/sites.yaml`; clones generated from saved genuine pages) in a sandboxed Chromium that resolves no hostname. `page_inspector` (C10/C11) details: `masked_ssim` (content-masked SSIM, the match score), `ssim`, `phash_distance`, `changed_share`, `regions` (`{x, y, w, h, share}` in 1280x800 screenshot pixels), `compared_with`, `ranking`, `threshold`, `artifacts` (heatmap + both screenshots), and on the first item `page_source`, `clone_of`, `kit_edits`, `sandbox`, `render_ms`; C11 items add `structure_similarity`, `genuine_actions`, `suspect_actions`, `suspect_action`, `genuine_action`, `added_inputs`, `added_script_hosts`, `added_iframes`. `vision_ai` (C12/C13) details: `claimed_brand`, `model`, `method` (gemini / cache / offline_text), `temperature`, `prompt_version`, `claim_evidence`, `page_type`, `confidence`, `instructions_seen`, `hidden_text_removed`, `injection_attempt`; C13 adds `asks_for`, `from_form_fields`, `from_vision`. New finding names (minor, additive): `claims_unprotected_brand` (vision_ai, neutral: the page claims a brand Doppel doesn't protect) and `no_genuine_snapshot` (page_inspector, neutral). H2–H4 fire from P9 on (below).

**Implemented in P9** (`doppel/deep/tracker.py`, sessions in `doppel/deep/sandbox.py`): `credential_tracker` types unique made-up values (canaries) into the page's credential form, submits it, and searches every request and WebSocket frame for them (plain, URL-decoded, base64). Fixture pages only; calls off the fixture are answered inside the sandbox, never sent. Details on the aggregated C14 item (or on the first item if only a direct channel was seen): `canaries` (`{field, value, traceable}`), `form` (`index, action, method, fields`), `submitted_by`, `destinations` (`{host, url, owner, relation ∈ same_origin/same_owner/third_party, channel ∈ telegram/discord/google_forms/relay/null, platform, in_brand_family, via, fields, method}`), `first_hop`, `requests_captured`, `attempts`, `confirm_only`, `dummy_credentials`, `sandbox` (`answered_locally`, `refused`, `resolver`, `contacted_outside`), `limitation`, `outcomes` (per session: `state` ∈ accepted/rejected/unknown/not_submitted, `why`, `bounce`), optional `basis: form_target_only` + `note`, `in_page_source`. Direct-exfil items: `channel`, `endpoint`, `url_redacted`, `fields`, `via`, `blocked_by_sandbox`, `token_redacted` (Telegram tokens are always `12345****:[REDACTED]`). `redirects_to_real_brand`: `redirect_to`. New finding names (minor, additive): `credentials_to_page_owner` (neutral: no brand to compare), `no_credentials_sent` (neutral), `rejects_wrong_credentials` (genuine, weak). **H2–H4 now fire** (`doppel/brain/fusion.py: hard_rules`); never on a proven family member, whose login leaving the family gives NEEDS REVIEW with no hard rule. H1's `evidence_ids` add `credentials_stay_in_family` when present.

**Implemented in P11** (`doppel/certs`, contract v1.1.0, decision 004):
- `cert_forensics` (Quick, C16) reads the family auto-discovery index (`data/brands/discovered.yaml`; no network). `certificate_san_link` (genuine, strong) details: `proof` (`certificate_san`), `matched_san`, `linked_to` (proven names on the same certificate), `family_entry`, `include_subdomains`, `seed_host`, `cert_sha256`, `issuer`, `validation` (EV/OV/IV/DV/unknown), `organisation`, `not_after`, `sans` (the full list), `source` (live_tls / ct_*), `seen_on`. `certificate_platform_only` (neutral): `platform`, `platform_brand`, `guard`. `no_certificate_link` (neutral): `index_size`, `index_generated`.
- `ct_history` (Standard, C16 + C17) searches CT logs for the owner domain (SSLMate, crt.sh; cached under `data/certs/ct/`; a live lookup only for `paste`/`api` investigations). C16: `certificate_organisation_match` (genuine, strong) / `certificate_organisation_other` (neutral): `organisation`, `country`, `validation`, `issuer`, `cert_sha256`, `brand_legal_names`. C17: `armed` (phishing, weak: first certificate within 90 days; score 1.0 within 30), `established_certificates` (neutral), `no_certificate_yet` (neutral), `ct_not_checked` (neutral): `domain`, `count`, `first_seen`, `last_seen`, `age_days`, `issuers`, `validation`, `recipes`, `subdomain_labels`, `sample`, `ct_source`, `fetched_at`, `truncated`.
- A certificate proof makes H1 fire (its `evidence_ids` cite it). It never applies to a user-content host or a free-hosting tenant.
- `trick_detector` adds `email_shaped_name` (neutral, P11 fix c): `email`, `tokens`. Combosquats found inside a gibberish free-hosting label (P11 fix a) carry `hidden_in`.
- `meta.checks_off` (optional): criteria switched off by the ablation switch (`--no-cert`: C16, C17).

**Risk-model convention:** `details.probability` is the model output *p*. If *p* ≥ 0.5, `points_to = phishing`, `score = p`; otherwise `points_to = genuine`, `score = 1 − p`.

**Implemented in P7** (`doppel/risk`): `ml_risk` is always `weak`. Within 0.1 of 0.5 the model has no opinion, so the item is `neutral` with score 0 (minor, additive). Details: `probability` (isotonic-calibrated on PhiUSIIL's held-out split), `raw_probability`, `model_input` (the host the model read: no `www.`, look-alike letters folded), `base_rate` (PhiUSIIL training phishing share, ~0.38: *not* a real-world rate), `model_version`, `top_features` (`{feature, kind ∈ ngram/tld/lexical, contribution}` in log-odds, biggest first). Fusion v1 scores it as `WEIGHT × (2·score − 1)` so it's continuous at *p* = 0.5.

**An `edit`:** `{op, candidate, genuine, candidate_span, genuine_span, cost, kind, codepoints?}`. Spans are `[start, end)` code-point offsets into the Unicode strings. `cost` 0 = indistinguishable to the eye. `kind` ∈ homoglyph, twin_letters, typo, keyboard, phonetic, bitflip, hyphen, other.

### Finding vocabulary (used by the examples; extend freely, and add new names here)

| Tool | Findings |
|---|---|
| address_reader | `owner_resolved`, `owner_differs`, `free_hosting_owner`, `ip_address_host`, `mixed_script`, `whole_script_confusable`, `single_script` |
| family_verifier | `genuine_family`, `brand_user_content_platform`, `restricted_registry_unlisted`, `restricted_registry_other_entity`, `imitates_trust_signal`, `not_in_family`, `no_brand_to_verify` |
| trick_detector | `brand_closeness`, `far_from_all_brands`, `in_family`, `homoglyph`, `twin_letters`, `typo`, `bitsquat`, `soundsquat`, `combosquat`, `level_squat`, `trust_signal_mimicry`, `tld_swap`, `abused_tld`, `substring_not_token`, `no_trick`, `email_shaped_name` |
| human_eye_renderer | `sms_view_identical`, `sms_view_near_identical`, `sms_view_prefix_match`, `sms_view_brand_prominent`, `sms_view_distinct` |
| risk_model | `ml_risk` |
| page_probe | `live_login_form`, `live_payment_form`, `live_no_credentials`, `parked`, `no_page`, `not_probed` |
| page_inspector | `visual_match`, `visual_mismatch`, `matches_genuine_snapshot`, `form_target_changed`, `fields_added` |
| vision_ai | `claimed_brand_mismatch`, `claimed_brand_matches_owner`, `no_brand_claim`, `asks_sensitive`, `asks_nothing_sensitive` |
| cert_forensics | `certificate_san_link`, `certificate_platform_only`, `no_certificate_link` |
| ct_history | `certificate_organisation_match`, `certificate_organisation_other`, `armed`, `established_certificates`, `no_certificate_yet`, `ct_not_checked` |
| campaign_radar (P13) | `campaign_member` (phishing, **weak**: score 1.0 when a certificate links the campaign, 0.6 for a naming template only; details `campaign_id`, `size`, `links`, `strength_of_link`, `template`, `peers`, `index`) |
| credential_tracker | `credentials_to_foreign_domain`, `credentials_stay_in_family`, `direct_exfil_telegram`, `direct_exfil_discord`, `direct_exfil_google_forms`, `accepts_any_credentials`, `redirects_to_real_brand`, `no_credential_form`, `credentials_to_page_owner`, `no_credentials_sent`, `rejects_wrong_credentials` |

## 2. Verdict

| Field | Meaning |
|---|---|
| `domain` | Lowercase ASCII host (punycode for IDNs). Goes into the blocklist |
| `input` | `raw` (what was submitted), `display` (Unicode, as a victim sees it), `source` |
| `owner` | The real owner from the Address Reader (registrable domain, or the full host on a free-hosting private suffix) |
| `target_brand`, `closeness` | Who it imitates (or whose it is), and the **name-level** closeness 0–1 to that brand's genuine family. Both `null` when there is no brand signal. A brand-less clone has a target from the page but low closeness |
| `risk_score` | 0–1, how likely it is a scam. Presented as a risk score with the base rate stated, not a calibrated probability |
| `confidence` | `high` / `medium` / `low` |
| `label` | **Final:** `genuine`, `phishing`, `sleeper`, `needs_review`, `benign` |
| `reason` | One plain-language line |
| `hard_rule` | The rule that decided the label, or `null` if the combiner decided. `also_fired` lists other phishing rules that fired |
| `counterfactual` | The what-if: which evidence was undone, and the label / risk it would get. `null` if none applies |
| `timings_ms` | `quick`, `standard`, `deep` (`null` when skipped), `total` |
| `stages` | Always three records, in order. Each has `status` (`completed` / `skipped` + `skip_reason`), the tools that ran, its evidence IDs and its **provisional verdict** (where `suspicious` is allowed) |
| `evidence` | Every evidence item |
| `trace` | The replayable decision trace (below) |
| `meta` | `generated_at`, `engine_version`, `mock` (true for examples and seeded data) |

There is **no mode field**: stages are automatic. Single investigations (`paste`, `api`, `fool_it`, `gallery`) run every stage; batch sources (`file`, `stdin`, `nrd_snapshot`, `ct_feed`) escalate per domain on evidence.

### Hard rules (priority order)

| id | forces | fires when |
|---|---|---|
| `H1_genuine_family` | genuine | ownership proven by the Family Verifier or, from v1.1.0, by a certificate (C16) (and, if a page exists, the login stays in the family) |
| `H2_brand_claim_foreign_credentials` | phishing | the page claims a brand, the owner isn't in its family, and credentials leave the family (C12 + C14) |
| `H3_accepts_any_credentials` | phishing | the page accepts made-up credentials (C15) |
| `H4_direct_exfil_channel` | phishing | data goes straight to Telegram / Discord / Google Forms |

### The trace (for the Decision Trace Explorer)

An ordered list of steps; replaying them in order rebuilds the investigation. `kind` is one of:

- `case_opened`: always first
- `policy`: the brain's decision ("brand signal found, so go to Standard")
- `tool`: `stage`, `tool`, `args`, `duration_ms`, `evidence_ids`, `risk_before` → `risk_after` (the score change)
- `provisional_verdict`: after a stage, with `label` and `risk_after`
- `hard_rule`: which rule fired, with its evidence
- `final_verdict`: always last; its `label` and `risk_after` equal the verdict's

`t_ms` is the step's start time since the case opened. Tools in the same stage may share a start time (they run in parallel); steps are still listed in order.

## 3. Invariants (checked by `doppel.contract`, beyond the JSON Schema)

1. Evidence IDs are unique, and every cited ID exists.
2. Stages are `quick, standard, deep`; quick always runs; once a stage is skipped, later stages are skipped too.
3. Each evidence item is listed under exactly one stage, the one it was produced in; a stage's `tools` are exactly the tools in its evidence.
4. A skipped stage has no tools, no evidence, no provisional verdict and a `null` timing.
5. `target_brand` and `closeness` are both null or both set.
6. A hard rule's `forces` equals the label; `genuine` requires `H1_genuine_family`; `hard_rule.id` is the highest-priority rule that fired.
7. A `sleeper` has the deep stage skipped.
8. A counterfactual must flip the label.
9. The trace is numbered 1..n, starts with `case_opened`, ends with `final_verdict`, never goes back in time, only calls tools in completed stages, and every evidence item appears in a tool step.
10. Neutral evidence has score 0.

## 4. Registry (`data/brands/registry.yaml`)

`restricted_registries` (suffix, who can register, source, verified_on), a shared `lure_words` lexicon (word, lang, category), and `brands`: `id`, `name`, `aliases` (tokens that name the brand), `brand_tlds`, `restricted_suffixes`, `genuine_family` (domain, `include_subdomains`, `proof` ∈ brand_tld / restricted_registry / official_list, `source`, `verified_on`), brand-specific `lure_words`, and a `logo` path.

`verified_on: null` means "still to verify": the entry is used, and the Family Verifier reports it as unverified. A verified entry must have a source URL.

**v1.2 (P11, additive):** an optional `legal_names` list per brand (`name`, optional `country`, `source`, `verified_on`): the Organisation field of the brand's OV/EV certificates, matched exactly (case-folded, never a substring).

**v1.1 (P1, additive):**
- `brand_tld_registry`: one row per closed brand TLD (`tld`, `brand`, `manager` as IANA lists it, `source`, `verified_on`). Every brand's `brand_tlds` entry must have a row.
- `user_content_hosts` per brand: brand-owned hosts where **anyone** can publish (`forms.gle`, `docs.google.com`, `sites.google.com`…). The Family Verifier must never fire `H1_genuine_family` for them, even when they sit under a family domain. It reports a "brand-owned user-content platform" finding instead (P2 picks the finding name and adds it to the vocabulary above).

Registry invariants checked by `validate_registry`:
- unique brand IDs
- restricted suffixes are declared
- `brand_tld` and `restricted_registry` proofs match the domain
- no domain belongs to two brands
- every brand TLD has an IANA row
- no host is both genuine family and user content
- no token is both a brand alias and a lure word, and no lure word is listed twice

## 5. Versioning

`schema_version` is `1.1.0` (v1.0.0 documents stay valid). Adding an optional field or a new finding name is a minor change (tell the other side in your status file). Renaming or removing a field, or changing an enum, is a major change and needs a decision file.
