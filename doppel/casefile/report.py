"""The case file as one self-contained HTML page (printable to PDF from any browser).

Sections: header (domain as the victim sees it, label, risk, rule) · the narrated story (every sentence with its
evidence chips, linking to the appendix) · recommended actions · the page images (heatmap + sandbox screenshot,
embedded) · the evidence appendix (every item) · how this file was written (model, the validator's log of
rejected sentences, what is real and what is simulated). No external assets: it opens offline and prints.
"""

from __future__ import annotations

import base64
from html import escape

from doppel.casefile.writer import LABEL_WORD, CaseFile
from doppel.contract import REPO_ROOT

COLOR = {"phishing": "#c62f37", "genuine": "#1d8a4f", "sleeper": "#b87407", "needs_review": "#6b4fd8", "benign": "#6b7280"}
T = {
    "en": {"title": "Case file", "story": "What happened", "actions": "Recommended actions", "images": "The page",
           "evidence": "Evidence appendix", "how": "How this file was written", "risk": "Risk score", "rule": "Hard rule",
           "whatif": "What-if", "none": "none", "owner": "Real owner", "brand": "Imitates / belongs to",
           "conf": "Confidence", "summary": "In short", "name": "The name (Stage 1)",
           "page": "The page and the behaviour (Stages 2-3)"},
    "hi": {"title": "केस फ़ाइल", "story": "क्या हुआ", "actions": "सुझाए गए कदम", "images": "पेज",
           "evidence": "सबूत (परिशिष्ट)", "how": "यह फ़ाइल कैसे लिखी गई", "risk": "जोखिम स्कोर", "rule": "हार्ड नियम",
           "whatif": "अगर ऐसा होता", "none": "कोई नहीं", "owner": "असली मालिक", "brand": "ब्रांड", "conf": "भरोसा",
           "summary": "संक्षेप में", "name": "नाम (चरण 1)", "page": "पेज और व्यवहार (चरण 2-3)"},
}
CSS = """
*{box-sizing:border-box} body{font:14px/1.5 "Segoe UI",Roboto,"Noto Sans","Noto Sans Devanagari",Mangal,Arial,sans-serif;
color:#1d2433;margin:0;background:#f4f5f8} main{max-width:900px;margin:24px auto;background:#fff;padding:32px 40px;
border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.06)} h1{font-size:22px;margin:0 0 4px} h2{font-size:15px;
text-transform:uppercase;letter-spacing:.04em;color:#556;margin:26px 0 8px;border-bottom:1px solid #e5e7ef;padding-bottom:4px}
h3{font-size:14px;margin:14px 0 4px} .mono{font-family:Consolas,"JetBrains Mono",monospace}
.badge{display:inline-block;color:#fff;font-weight:800;padding:3px 12px;border-radius:999px;letter-spacing:.04em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-top:12px}
.grid div{background:#f6f7fb;border-radius:10px;padding:8px 10px} .grid small{display:block;color:#6b7280;font-size:11.5px}
.cite{display:inline-block;font:700 10.5px Consolas,monospace;background:#eef0f7;color:#445;border-radius:5px;padding:0 5px;
margin-left:3px;text-decoration:none} .cite.V{background:#1d2433;color:#fff}
.tpl{color:#6b7280;font-size:11.5px;margin-left:6px} ul{padding-left:20px} li{margin:4px 0}
table{width:100%;border-collapse:collapse;font-size:12.5px} th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef4;
vertical-align:top} th{color:#6b7280;font-size:11.5px} tr:target{background:#fff6d6}
.ph{color:#c62f37}.gn{color:#1d8a4f}.nt{color:#6b7280} figure{margin:8px 0} figure img{max-width:100%;border:1px solid #dde;
border-radius:8px} figcaption{color:#6b7280;font-size:12px} .figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px} .note{color:#556;font-size:12.5px}
.rej{color:#9a3b3b;font-size:12.5px} .rule{border:2px solid;border-radius:10px;padding:8px 12px;margin-top:10px}
@media print{body{background:#fff} main{box-shadow:none;margin:0;max-width:none;padding:0} a{color:inherit}
h2{break-after:avoid} tr,figure{break-inside:avoid}}
"""


def _img(path: str) -> str | None:
    p = REPO_ROOT / path
    if not p.exists() or p.stat().st_size > 3_000_000:
        return None
    return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode("ascii")


def _cites(ids: list[str]) -> str:
    return "".join(f'<a class="cite {"V" if i == "V" else ""}" href="#{"verdict" if i == "V" else escape(i)}">{escape(i)}</a>'
                   for i in ids)


def render(cf: CaseFile) -> str:
    v, t = cf.verdict, T[cf.lang]
    col = COLOR[v["label"]]
    hr, wf = v.get("hard_rule"), v.get("counterfactual")
    brand = (v.get("target_brand") or {}).get("name") or t["none"]
    h = [f'<!doctype html><html lang="{cf.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>Doppel {t['title']}: {escape(v['domain'])}</title><style>{CSS}</style></head><body><main>",
         f'<div class="note">Doppel · {t["title"]} · {escape(v["meta"]["generated_at"])} · engine {escape(v["meta"]["engine_version"])}</div>',
         f'<h1 id="verdict"><span class="mono">{escape(v["input"]["display"])}</span> '
         f'<span class="badge" style="background:{col}">{LABEL_WORD[v["label"]]}</span></h1>',
         f'<div class="note mono">{escape(v["domain"])}</div><p>{escape(v["reason"])} {_cites(["V"])}</p>',
         '<div class="grid">',
         f'<div><small>{t["risk"]}</small><b>{v["risk_score"]:.3f}</b></div>',
         f'<div><small>{t["conf"]}</small><b>{escape(v["confidence"])}</b></div>',
         f'<div><small>{t["owner"]}</small><b class="mono">{escape(v.get("owner") or "–")}</b></div>',
         f'<div><small>{t["brand"]}</small><b>{escape(brand)}</b></div></div>']
    if hr:
        also = f" Also fired: {escape(', '.join(hr['also_fired']))}." if hr.get("also_fired") else ""
        h.append(f'<div class="rule" style="border-color:{col}"><b>{t["rule"]}: {escape(hr["id"])}</b>. '
                 f'{escape(hr["description"])}{also} {_cites(hr["evidence_ids"])}</div>')
    if wf:
        h.append(f'<p class="note"><b>{t["whatif"]}:</b> {escape(wf["summary"])} {_cites(wf["undone_evidence_ids"][:6])}</p>')

    h.append(f'<h2>{t["story"]}</h2>')
    for s in cf.sections:
        tag = '' if s.method == "llm" else '<span class="tpl">(template: from the evidence summaries)</span>'
        h.append(f"<h3>{escape(t.get(s.id, s.title))}{tag}</h3><p>")
        h.append(" ".join(f"{escape(x.text)}{_cites(x.cites)}" for x in s.sentences))
        h.append("</p>")

    h.append(f'<h2>{t["actions"]}</h2><ul>')
    h += [f"<li>{escape(a['text'])} {_cites(a['cites'])}</li>" for a in cf.actions]
    h.append('</ul><p class="note">Actions are chosen by rules from the label and the evidence, not by the language model.</p>')

    figs = []
    for e in v["evidence"]:
        for a in e["details"].get("artifacts") or []:
            if a["kind"] in ("heatmap", "screenshot") and len(figs) < 2 and (src := _img(a["path"])):
                figs.append(f'<figure><img src="{src}" alt="{escape(a.get("caption", a["kind"]))}"><figcaption>'
                            f'{escape(a.get("caption", a["kind"]))} {_cites([e["evidence_id"]])}</figcaption></figure>')
    if figs:
        h.append(f'<h2>{t["images"]}</h2><div class="figs">' + "".join(figs) + "</div>")

    h.append(f'<h2>{t["evidence"]}</h2><table><tr><th>ID</th><th>Stage · tool · check</th><th>Finding</th><th>Points to</th><th>What was found</th></tr>')
    cls = {"phishing": "ph", "genuine": "gn", "neutral": "nt"}
    for e in v["evidence"]:
        summary = next((f["text"].split("] ", 1)[-1] for f in cf.facts if f["id"] == e["evidence_id"]), e["summary"])
        h.append(f'<tr id="{escape(e["evidence_id"])}"><td class="mono"><b>{escape(e["evidence_id"])}</b></td>'
                 f'<td>{escape(e["stage"])} · {escape(e["tool"])} · {escape(e["criterion"])}</td>'
                 f'<td class="mono">{escape(e["finding"])}</td><td class="{cls[e["points_to"]]}">{escape(e["points_to"])} '
                 f'({escape(e["strength"])}, {e["score"]:.2f})</td><td>{escape(summary)}</td></tr>')
    h.append("</table>")

    n = cf.narration
    h.append(f'<h2>{t["how"]}</h2><ul class="note">')
    if n["model"]:
        h.append(f"<li>Narration: {escape(n['model'])} ({'recorded answer' if n['method'] == 'cache' else 'live call'}), "
                 f"temperature 0, prompt {escape(n['prompt_version'])}. It saw only the facts in this file and may only "
                 f"word them: <b>{n['accepted']}</b> sentence(s) passed the citation validator, <b>{n['rejected']}</b> were "
                 "rejected (below). The label, risk and rule come from Doppel's deterministic brain.</li>")
    else:
        h.append(f"<li>Narration: none ({escape(n.get('error') or 'not requested')}); every sentence is a template built "
                 "from the evidence's own summaries.</li>")
    rejected = [(s.title, r) for s in cf.sections for r in s.rejected]
    for title, r in rejected:
        h.append(f'<li class="rej">Rejected ({escape(title)}): “{escape(r["text"])}”: {escape(r["why"])}.</li>')
    if v["meta"].get("mock"):
        h.append(f"<li>{escape(v['meta'].get('notes', 'Page evidence comes from local fixture pages.'))} Credentials "
                 "used anywhere are made up; kit servers in the fixtures are simulated; no request left the sandbox.</li>")
    h.append("<li>The risk score ranks cases; it is not a calibrated probability.</li></ul>")
    h.append("</main></body></html>")
    return "\n".join(h)


def case_file_html(verdict: dict, lang: str = "en", use_llm: bool = True) -> tuple[str, CaseFile]:
    from doppel.casefile.writer import write

    cf = write(verdict, lang, use_llm)
    return render(cf), cf
