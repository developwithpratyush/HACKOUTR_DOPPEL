"""The ablation diff (P11): one name judged with Certificate Forensics off, then on.

Used by ``doppel cert-diff`` and the API (``/api/investigate`` with ``certs: false``, then the UI's toggle). The diff
is the verdict line before and after, plus the evidence rows only the certificate checks added (C16/C17): on stage,
``google.co.in`` goes NEEDS REVIEW -> GENUINE with one new row, Google's certificate.
"""

from __future__ import annotations

CERT_TOOLS = ("cert_forensics", "ct_history")


def _line(v: dict) -> dict:
    return {"label": v["label"], "risk_score": v["risk_score"], "hard_rule": (v.get("hard_rule") or {}).get("id"),
            "target_brand": (v.get("target_brand") or {}).get("name"), "reason": v["reason"]}


def diff(off: dict, on: dict) -> dict:
    added = [e for e in on["evidence"] if e["tool"] in CERT_TOOLS]
    keys = []
    for e in added:
        d = e["details"]
        keys.append({"evidence_id": e["evidence_id"], "criterion": e["criterion"], "finding": e["finding"],
                     "points_to": e["points_to"], "summary": e["summary"],
                     **{k: d[k] for k in ("cert_sha256", "matched_san", "linked_to", "seed_host", "organisation",
                                          "platform", "first_seen", "count", "recipes") if k in d}})
    return {"domain": on["domain"], "off": _line(off), "on": _line(on), "label_changed": off["label"] != on["label"],
            "risk_change": round(on["risk_score"] - off["risk_score"], 3), "added_evidence": keys}


def render(d: dict) -> str:
    def lab(x):
        return x["label"].upper().replace("_", " ")

    arrow = "->" if d["label_changed"] else "=="
    out = [f"{d['domain']}",
           f"  certificates OFF: {lab(d['off']):13} risk {d['off']['risk_score']:.3f}  {d['off']['reason']}",
           f"  certificates ON : {lab(d['on']):13} risk {d['on']['risk_score']:.3f}  {d['on']['reason']}",
           f"  {lab(d['off'])} {arrow} {lab(d['on'])} (risk {d['risk_change']:+.3f})"]
    if d["added_evidence"]:
        out.append("  evidence only the certificate checks add:")
        for e in d["added_evidence"]:
            out.append(f"    + {e['evidence_id']} {e['criterion']} {e['finding']} ({e['points_to']}): {e['summary']}")
            if e.get("cert_sha256"):
                out.append(f"      certificate SHA-256 {e['cert_sha256']}")
    else:
        out.append("  (the certificate checks added nothing for this name)")
    return "\n".join(out)
