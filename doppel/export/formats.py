"""Exporters (P5): one scan, four formats.

- ``json``      the contract's ``scan_result`` (every verdict in full, with evidence and trace)
- ``csv``       one row per verdict, for spreadsheets
- ``blocklist`` one domain per line: phishing and sleeper (``--include-review`` adds needs_review)
- ``html``      a self-contained, printable analyst report (ranked table + evidence + trace per domain)
"""

from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json
from pathlib import Path

from doppel import CONTRACT_VERSION

FORMATS = ("json", "csv", "blocklist", "html")
CSV_COLUMNS = ["domain", "display", "label", "risk_score", "confidence", "target_brand", "closeness", "tricks",
               "owner", "hard_rule", "reached_stage", "reason", "counterfactual", "source"]
BLOCK = ("phishing", "sleeper")
ORDER = {"phishing": 0, "sleeper": 1, "needs_review": 2, "benign": 3, "genuine": 4}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ranked(verdicts: list[dict]) -> list[dict]:
    return sorted(verdicts, key=lambda v: (ORDER[v["label"]], -v["risk_score"], v["domain"]))


def _tricks(v: dict) -> list[str]:
    return [e["finding"] for e in v["evidence"] if e["tool"] == "trick_detector" and e["criterion"] == "C5"
            and e["points_to"] == "phishing"]


def _reached(v: dict) -> str:
    return [s["stage"] for s in v["stages"] if s["status"] == "completed"][-1]


def scan_result(verdicts: list[dict], stats: dict) -> dict:
    """The contract's scan_result. Its summary describes the verdicts it contains (inputs that weren't
    domains, and verdicts a caller filtered out, are reported by the CLI, not counted here)."""
    from collections import Counter

    by_label = Counter(v["label"] for v in verdicts)
    reached = Counter(_reached(v) for v in verdicts)
    return {"schema_version": CONTRACT_VERSION, "generated_at": _now(), "verdicts": ranked(verdicts),
            "summary": {"total": len(verdicts), "by_label": dict(by_label), "reached_stage": dict(reached),
                        "elapsed_ms": stats["elapsed_ms"]}}


def to_json(verdicts: list[dict], stats: dict) -> str:
    return json.dumps(scan_result(verdicts, stats), indent=1, ensure_ascii=False) + "\n"


def to_csv(verdicts: list[dict], stats: dict | None = None) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    w.writeheader()
    for v in ranked(verdicts):
        w.writerow({
            "domain": v["domain"], "display": v["input"]["display"], "label": v["label"],
            "risk_score": v["risk_score"], "confidence": v["confidence"],
            "target_brand": (v["target_brand"] or {}).get("id", ""), "closeness": "" if v["closeness"] is None else v["closeness"],
            "tricks": " ".join(_tricks(v)), "owner": v["owner"] or "", "hard_rule": (v["hard_rule"] or {}).get("id", ""),
            "reached_stage": _reached(v), "reason": v["reason"],
            "counterfactual": (v["counterfactual"] or {}).get("summary", ""), "source": v["input"]["source"],
        })
    return buf.getvalue()


def to_blocklist(verdicts: list[dict], stats: dict | None = None, include_review: bool = False) -> str:
    labels = BLOCK + (("needs_review",) if include_review else ())
    hosts = sorted({v["domain"] for v in verdicts if v["label"] in labels})
    head = [f"# Doppel blocklist, {_now()}", f"# labels: {', '.join(labels)}; {len(hosts)} domains",
            "# Name-level verdicts never block a proven brand address (H1)."]
    return "\n".join(head + hosts) + "\n"


_CSS = """
:root{--bg:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;--card:#ffffff;
--phishing:#c0392b;--sleeper:#b36b00;--needs_review:#7a5af8;--benign:#2f7d32;--genuine:#1c5cab}
@media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;
--line:#2c2c2a;--card:#222220;--phishing:#ff7b6b;--sleeper:#f0b24a;--needs_review:#b6a4ff;--benign:#7ed07f;--genuine:#86b6ef}}
body{background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px 16px}
main{max-width:1100px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}p.sub{color:var(--ink2);margin:0 0 18px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}.tile{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:10px 14px;min-width:110px}.tile b{display:block;font-size:20px}.tile span{color:var(--ink2);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--ink2);font-weight:600;font-size:12px}
.lab{font-weight:700;white-space:nowrap}.lab::before{content:"";display:inline-block;width:9px;height:9px;border-radius:50%;
margin-right:6px;background:currentColor}td.num{font-variant-numeric:tabular-nums}
details{margin:4px 0 0}summary{cursor:pointer;color:var(--ink2)}ul{margin:6px 0 4px 18px;padding:0}li{margin:2px 0}
code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}.muted{color:var(--muted)}
@media (max-width:700px){table,thead,tbody,tr,td,th{display:block}thead{display:none}td{border:0;padding:4px 10px}tr{border-bottom:1px solid var(--line);padding:6px 0}}
@media print{details{display:block}details>*{display:block}body{padding:0}}
"""


def to_html(verdicts: list[dict], stats: dict, title: str = "Doppel scan report") -> str:
    e = html.escape
    rows = []
    for v in ranked(verdicts):
        lab = v["label"]
        ev = "".join(f"<li><code>{e(x['evidence_id'])}</code> {e(x['tool'])} · <b>{e(x['finding'])}</b> "
                     f"({e(x['points_to'])}, {e(x['strength'])}): {e(x['summary'])}</li>" for x in v["evidence"])
        tr = "".join(f"<li><span class='muted'>{s['t_ms']:.1f} ms</span> {e(s['message'])}"
                     + (f" <span class='muted'>risk {s['risk_before']:.2f} → {s['risk_after']:.2f}</span>"
                        if s["kind"] == "tool" else "") + "</li>" for s in v["trace"])
        cf = v["counterfactual"]
        rule = v["hard_rule"]
        close = "" if v["closeness"] is None else f"closeness {v['closeness']:.2f}"
        rows.append(
            f"<tr><td><code>{e(v['input']['display'])}</code><br><span class='muted'>owner {e(v['owner'] or '-')}</span></td>"
            f"<td class='lab' style='color:var(--{lab})'>{e(lab.replace('_', ' '))}</td>"
            f"<td class='num'>{v['risk_score']:.2f}<br><span class='muted'>{e(v['confidence'])}</span></td>"
            f"<td>{e((v['target_brand'] or {}).get('name', '-'))}<br><span class='muted'>{close}</span></td>"
            f"<td>{e(v['reason'])}"
            + (f"<br><span class='muted'>Hard rule: {e(rule['id'])}</span>" if rule else "")
            + (f"<br><span class='muted'>What-if: {e(cf['summary'])}</span>" if cf else "")
            + f"<details><summary>Evidence ({len(v['evidence'])})</summary><ul>{ev}</ul></details>"
              f"<details><summary>Decision trace ({len(v['trace'])} steps)</summary><ul>{tr}</ul></details></td></tr>")
    by = stats["by_label"]
    tiles = "".join(f"<div class='tile'><b style='color:var(--{k})'>{by.get(k, 0):,}</b><span>{k.replace('_', ' ')}</span></div>"
                    for k in ORDER)
    scanned = stats["total"] - stats.get("errors", 0)
    shown = "" if len(verdicts) == scanned else f" ({len(verdicts):,} shown)"
    skipped = f" · {stats['errors']:,} inputs weren't domains" if stats.get("errors") else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{_CSS}</style></head><body><main>
<h1>{e(title)}</h1><p class="sub">{scanned:,} domains{shown}{skipped} · {stats['elapsed_ms'] / 1000:.1f} s · generated {_now()} ·
risk is a score, not a calibrated probability</p><div class="tiles">{tiles}</div>
<table><thead><tr><th>Domain</th><th>Label</th><th>Risk</th><th>Target</th><th>Why</th></tr></thead><tbody>
{''.join(rows)}</tbody></table>
<p class="muted">Doppel never opens unknown domains: pages are checked only for local fixtures. A name alone never yields PHISHING.</p>
</main></body></html>
"""


WRITERS = {"json": to_json, "csv": to_csv, "blocklist": to_blocklist, "html": to_html}
EXT = {"json": "json", "csv": "csv", "blocklist": "txt", "html": "html"}


def write(fmt: str, verdicts: list[dict], stats: dict, path: Path, **kw) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(WRITERS[fmt](verdicts, stats, **kw), encoding="utf-8")
    return path
