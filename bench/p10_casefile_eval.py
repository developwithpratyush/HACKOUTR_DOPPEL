"""P10 evaluation: are the case files grounded, and does the validator catch what it should?

1. **Every real verdict** in ``ui/src/lib/testdata/real-verdicts.json`` (14 brain outputs, gallery + others) gets a
   case file in English and Hindi: which model wrote it, sentences kept / rejected (with the reasons), sections
   that fell back to the template, latency. Every kept sentence cites evidence by construction; the eval checks it.
2. **Adversarial validator set**: hand-written bad sentences (no citation, an unknown ID, calling a PHISHING page
   legitimate, an invented number, an invented domain, English in a Hindi file, another label outside a what-if),
   plus good ones that must pass. Caught / passed counts.
3. **Offline**: with the LLM unavailable, every verdict still gets a complete (template) case file.

Writes docs/eval/p10-casefile.json; ``--md`` also renders docs/eval/p10-casefile.md.
Run:  .venv/Scripts/python.exe bench/p10_casefile_eval.py --md     (online: ~28 Groq calls, cached afterwards)
"""

from __future__ import annotations

import json
import re
import statistics
import sys
import time

from doppel.casefile import llm
from doppel.casefile.report import render
from doppel.casefile.writer import facts, validate, write
from doppel.contract import REPO_ROOT

OUT = REPO_ROOT / "docs" / "eval" / "p10-casefile.json"
VERDICTS = REPO_ROOT / "ui" / "src" / "lib" / "testdata" / "real-verdicts.json"


def adversarial(v05: dict) -> list[dict]:
    """(sentence, lang, must_pass) cases against gallery 05 (PHISHING, kx72-secure.top)."""
    fs = {f["id"]: f["text"] for f in facts(v05)}
    cases = [
        ({"text": "The page copies State Bank of India's login page.", "cites": []}, "en", False, "no citation"),
        ({"text": "The page copies State Bank of India's login page.", "cites": ["E99"]}, "en", False, "unknown ID"),
        ({"text": "Overall the site looks legitimate.", "cites": ["V"]}, "en", False, "contradicts PHISHING"),
        ({"text": "This is not a phishing site.", "cites": ["V"]}, "en", False, "contradicts PHISHING"),
        ({"text": "The risk score is 0.42.", "cites": ["V"]}, "en", False, "invented number"),
        ({"text": "It copies the genuine page at 87%.", "cites": ["E8"]}, "en", False, "invented number"),
        ({"text": "The password also goes to sbi-secure-login.com.", "cites": ["E13"]}, "en", False, "invented domain"),
        ({"text": "The page sends the password to Telegram.", "cites": ["E12"]}, "hi", False, "English in a Hindi file"),
        ({"text": "Doppel marked it GENUINE.", "cites": ["V"]}, "en", False, "another label"),
        ({"text": "kx72-secure.top is PHISHING: it copies State Bank of India's page.", "cites": ["V", "E8"]}, "en", True, "good"),
        ({"text": "It copies the genuine page at 100%.", "cites": ["E8"]}, "en", True, "good (number grounded)"),
        ({"text": "Judged by the name alone it would be BENIGN.", "cites": ["V"]}, "en", True, "good (what-if)"),
        ({"text": "पेज पासवर्ड सीधे Telegram पर भेजता है।", "cites": ["E12"]}, "hi", True, "good (Hindi)"),
    ]
    out = []
    for s, lang, must_pass, kind in cases:
        why = validate(s, v05["label"], fs, lang)
        out.append({"sentence": s["text"], "cites": s["cites"], "lang": lang, "kind": kind, "must_pass": must_pass,
                    "verdict": "pass" if why is None else f"rejected: {why}", "correct": (why is None) == must_pass})
    return out


def main() -> None:
    verdicts = json.loads(VERDICTS.read_text(encoding="utf-8"))
    rows = []
    for v in verdicts:
        for lang in ("en", "hi"):
            t0 = time.perf_counter()
            cf = write(v, lang)
            html = render(cf)
            kept = [x for s in cf.sections for x in s.sentences if x.source == "llm"]
            rows.append({"domain": v["domain"], "label": v["label"], "lang": lang, "model": cf.narration["model"],
                         "method": cf.narration["method"], "accepted": cf.narration["accepted"],
                         "rejected": cf.narration["rejected"],
                         "reasons": [r["why"] for s in cf.sections for r in s.rejected],
                         "template_sections": [s.id for s in cf.sections if s.method == "template"],
                         "all_cited": all(x.cites for s in cf.sections for x in s.sentences),
                         "llm_sentences": len(kept), "error": cf.narration.get("error"),
                         "ms": round((time.perf_counter() - t0) * 1000), "html_kb": round(len(html) / 1024)})
            print(f"{v['domain']:42s} {lang} {rows[-1]['model']} kept {rows[-1]['accepted']} rejected {rows[-1]['rejected']} "
                  f"template {rows[-1]['template_sections']} {rows[-1]['ms']} ms")
    v05 = next(v for v in verdicts if v["domain"] == "kx72-secure.top")
    adv = adversarial(v05)
    import os
    os.environ["DOPPEL_TEXT_MODEL"] = "no-such-model-offline-check"   # forces a cache miss -> template
    os.environ["DOPPEL_OFFLINE"] = "1"
    offline = []
    for v in verdicts:
        cf = write(v, "en")
        offline.append(all(s.method == "template" and s.sentences for s in cf.sections) and bool(cf.actions))
    r = {"date": time.strftime("%Y-%m-%d"), "models": llm.DEFAULT_MODELS, "rows": rows, "adversarial": adv,
         "offline_complete": sum(offline), "offline_total": len(offline)}
    OUT.write_text(json.dumps(r, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT}")
    if "--md" in sys.argv:
        OUT.with_suffix(".md").write_bytes(render_md(r).encode("utf-8"))


def render_md(r: dict) -> str:
    rows = r["rows"]
    live = [x for x in rows if x["method"] in ("groq", "cache")]
    acc, rej = sum(x["accepted"] for x in rows), sum(x["rejected"] for x in rows)
    tmpl = sum(len(x["template_sections"]) for x in rows)
    reasons: dict[str, int] = {}
    for x in rows:
        for why in x["reasons"]:
            key = re.sub(r"^(domain|number) .* isn't in the (cited )?facts$", r"\1 not in the facts", why)
            key = re.sub(r"^cites unknown evidence .*", "unknown evidence ID", key)
            reasons[key] = reasons.get(key, 0) + 1
    models: dict[str, int] = {}
    for x in rows:
        models[x["model"] or "template"] = models.get(x["model"] or "template", 0) + 1
    adv = r["adversarial"]
    lines = [
        "# P10: Case-File Writer evaluation", "",
        f"Generated by `bench/p10_casefile_eval.py` on {r['date']}. Model chain: {', '.join(r['models'])} (temperature 0, "
        "JSON mode). Verdicts: the 14 real brain outputs in `ui/src/lib/testdata/real-verdicts.json`.", "",
        "## 1. Every verdict, in English and Hindi", "",
        f"- **{len(rows)} case files** ({len(rows) // 2} verdicts × 2 languages); narrated by the LLM: {len(live)}; "
        f"models used: {', '.join(f'{k} ×{n}' for k, n in models.items())}.",
        f"- Sentences kept: **{acc}**, rejected by the validator: **{rej}** "
        f"({rej / max(1, acc + rej):.1%}); sections that fell back to the template: {tmpl} of {3 * len(rows)}.",
        f"- Every kept sentence cites evidence: **{all(x['all_cited'] for x in rows)}**.",
        f"- Rejection reasons: {', '.join(f'{k} ×{n}' for k, n in sorted(reasons.items(), key=lambda kv: -kv[1])) or 'none'}.",
        f"- Time per case file (LLM call or cache + validation + HTML): median {statistics.median(x['ms'] for x in rows):.0f} ms, "
        f"max {max(x['ms'] for x in rows)} ms. HTML with embedded page images: up to {max(x['html_kb'] for x in rows)} KB.", "",
        "| Domain | Label | Lang | Model | Kept | Rejected | Template sections | ms |", "|---|---|---|---|---|---|---|---|"]
    for x in rows:
        lines.append(f"| `{x['domain']}` | {x['label']} | {x['lang']} | {x['model'] or 'template'} | {x['accepted']} | "
                     f"{x['rejected']} | {', '.join(x['template_sections']) or '–'} | {x['ms']} |")
    lines += ["", "## 2. The validator against bad sentences", "",
              f"**{sum(a['correct'] for a in adv)}/{len(adv)} judged correctly** "
              f"({sum(1 for a in adv if not a['must_pass'] and a['correct'])}/{sum(1 for a in adv if not a['must_pass'])} bad "
              f"sentences rejected, {sum(1 for a in adv if a['must_pass'] and a['correct'])}/{sum(1 for a in adv if a['must_pass'])} "
              "good ones kept). Verdict under test: gallery 05 (PHISHING).", "",
              "| Sentence | Cites | Lang | Case | Validator | Correct |", "|---|---|---|---|---|---|"]
    for a in adv:
        lines.append(f"| {a['sentence']} | {', '.join(a['cites']) or '–'} | {a['lang']} | {a['kind']} | {a['verdict']} | "
                     f"{'✅' if a['correct'] else '❌'} |")
    lines += ["", "## 3. Offline", "",
              f"With the LLM unavailable and nothing recorded, **{r['offline_complete']}/{r['offline_total']}** verdicts still get a "
              "complete case file (every section from the template, actions present).", "",
              "## 4. What the validator can't see", "",
              "- It checks citations, label contradictions, numbers, domains and the script, not meaning. A sentence can "
              "cite real evidence and still slightly mis-say it (seen in a manual read: \"the form posts to kx72-secure.top, "
              "outside the bank's family, indicating a brand claim mismatch\" ties C11 to C12 loosely). The cited chips let a "
              "reader check every sentence in one click, and the label, risk and actions never come from the LLM.",
              "- The Hindi files are checked for script and citations; their wording wasn't reviewed by a native speaker yet.",
              ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
