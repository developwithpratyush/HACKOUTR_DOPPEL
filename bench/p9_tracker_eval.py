"""P9 evaluation: what the Credential Tracker sees, measured.

1. **Kit zoo** (``doppel/deep/kits.py``): one page per exfiltration technique, judged as if it imitated SBI.
   Caught = every expected destination host was found carrying a canary (and the channel / C15 finding is the
   expected one). Two entries are expected misses, reported as such.
2. **Gallery fixtures** through the whole brain: label, hard rules, Deep time.
3. **Safety**: every request a session made was either a fixture page, a recorded asset, or answered/refused
   inside the sandbox; no token appears unredacted in any evidence.

Writes docs/eval/p9-credentials.json; ``--md`` also renders docs/eval/p9-credentials.md.
Run:  .venv/Scripts/python.exe bench/p9_tracker_eval.py --md      (~2 min, offline: DOPPEL_OFFLINE=1)
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path

os.environ.setdefault("DOPPEL_OFFLINE", "1")

from doppel.address import read_address                                 # noqa: E402
from doppel.brain.brain import Brain                                   # noqa: E402
from doppel.contract import REPO_ROOT, validate_verdict                 # noqa: E402
from doppel.deep import in_family_of                                    # noqa: E402
from doppel.deep.kits import zoo                                        # noqa: E402
from doppel.deep.pages import fake_telegram_token                       # noqa: E402
from doppel.deep.sandbox import sandbox                                 # noqa: E402
from doppel.deep.tracker import TELEGRAM_TOKEN, credential_tracker      # noqa: E402
from doppel.family import load_registry                                 # noqa: E402

OUT = REPO_ROOT / "docs" / "eval" / "p9-credentials.json"
GALLERY = [("https://pаytm.com/login", "01"), ("paytrn.com", "02"), ("https://echallan.parivahan.gov.in.pay-fine.icu/challan", "04"),
           ("kx72-secure.top", "05"), ("onlinesbi.sbi.bank.in", "06"), ("kyc-helpdesk.online", "injection page")]


def run_zoo(reg) -> list[dict]:
    sb = sandbox()
    sbi = next(b for b in reg.brands if b.id == "sbi")
    fam = lambda b, h: in_family_of(reg, b, h)                          # noqa: E731
    rows = []
    for k in zoo():
        t0 = time.perf_counter()
        s = sb.track_html(k["host"], k["html"], k["backend"], attempts=2)
        summary, items = credential_tracker(s, k["host"], read_address(k["host"]).owner, sbi, False, fam)
        found = sorted({d["host"] for d in summary["destinations"] if d["via"] != ["form target only"]})
        findings = [i["finding"] for i in items]
        exp = set(k["expect_hosts"])
        hosts_ok = exp <= set(found) if exp else not found
        chan_ok = k["expect_channel"] is None or f"direct_exfil_{k['expect_channel']}" in findings
        c15 = ("accepted" if "accepts_any_credentials" in findings else
               "rejected" if "rejects_wrong_credentials" in findings else None)
        c15_ok = k["expect_c15"] is None or c15 == k["expect_c15"]
        redir_ok = not k["expect_redirect"] or "redirects_to_real_brand" in findings
        caught = hosts_ok and chan_ok and c15_ok and redir_ok
        if not exp and k["name"] == "no_form":
            caught = findings == ["no_credential_form"]
        leaked = [m.group(0) for i in items for m in TELEGRAM_TOKEN.finditer(json.dumps(i))]
        rows.append({"kit": k["name"], "technique": k["technique"], "expected": sorted(exp), "found": found,
                     "findings": findings, "caught": caught, "expected_miss": bool(k["miss"]), "miss_reason": k["miss"],
                     "real_route": k["real_route"].replace("{host}", k["host"]) if k["real_route"] else None,
                     "sessions": len(s["attempts"]), "ms": round((time.perf_counter() - t0) * 1000),
                     "requests": sum(len(a.get("requests", [])) for a in s["attempts"]),
                     "answered_locally": sum(a.get("sunk", 0) for a in s["attempts"]),
                     "refused": sum(a.get("refused", 0) for a in s["attempts"]), "unredacted_tokens": len(leaked)})
        print(f"{'OK  ' if caught else 'MISS'} {k['name']:20s} {rows[-1]['ms']:5d} ms  found={found} {findings}")
    return rows


def run_gallery() -> list[dict]:
    brain = Brain()
    rows = []
    for raw, case in GALLERY:
        t0 = time.perf_counter()
        v = brain.investigate(raw, "gallery")
        tr = [e for e in v["evidence"] if e["tool"] == "credential_tracker"]
        rows.append({"case": case, "domain": v["domain"], "label": v["label"], "risk": v["risk_score"],
                     "hard_rule": v["hard_rule"]["id"] if v["hard_rule"] else None,
                     "also_fired": (v["hard_rule"] or {}).get("also_fired", []),
                     "tracker": [e["finding"] for e in tr], "tracker_ms": round(tr[0]["duration_ms"]) if tr else None,
                     "deep_ms": round(v["timings_ms"]["deep"]) if v["timings_ms"]["deep"] else None,
                     "total_ms": round((time.perf_counter() - t0) * 1000), "valid": validate_verdict(v) == [],
                     "unredacted_tokens": len(TELEGRAM_TOKEN.findall(json.dumps(v, ensure_ascii=False))),
                     "reason": v["reason"]})
        print(f"{case:15s} {v['label']:12s} {rows[-1]['hard_rule']} {rows[-1]['also_fired']} {rows[-1]['tracker']}")
    return rows


def render_md(r: dict) -> str:
    z = r["zoo"]
    measured = [k for k in z if not k["expected_miss"] and k["kit"] != "no_form"]
    caught = sum(k["caught"] for k in measured)
    misses = [k for k in z if k["expected_miss"]]
    lines = [
        "# P9: Credential Tracker evaluation",
        "",
        f"Generated by `bench/p9_tracker_eval.py` on {r['date']} (offline; sandboxed Chromium, no DNS). "
        "All pages are ours: the kit zoo (`doppel/deep/kits.py`) and the gallery fixtures (`demo/fixtures/sites.yaml`).",
        "",
        "## 1. Kit zoo: which exfiltration techniques the tracker sees",
        "",
        f"**{caught}/{len(measured)} client-side techniques caught** (every expected destination found carrying a "
        "canary, with the right channel / C15 finding). Plus the no-form page correctly reported as having nothing "
        f"to submit, and **{len(misses)} expected misses** kept in the zoo on purpose.",
        "",
        "| Kit | Technique | Expected destination | Found | Findings | Caught | ms |",
        "|---|---|---|---|---|---|---|",
    ]
    for k in z:
        mark = (("first hop only (expected)" if k["caught"] else "❌ missed (expected)") if k["expected_miss"]
                else "✅" if k["caught"] else "❌")
        lines.append(f"| `{k['kit']}` | {k['technique']} | {', '.join(k['expected']) or '–'} | "
                     f"{', '.join(k['found']) or '–'} | {', '.join(k['findings'])} | {mark} | {k['ms']} |")
    lines += ["", "**The expected misses (limitations, said in every C14 item):**", ""]
    for k in misses:
        lines.append(f"- `{k['kit']}`: {k['miss_reason']}." + (f" Real route: {k['real_route']}." if k["real_route"] else "")
                     + f" What the tracker reports: {', '.join(k['found']) or 'nothing'} ({', '.join(k['findings'])}).")
    ms = [k["ms"] for k in z]
    lines += ["", f"Time per kit (one or two sessions): median {statistics.median(ms):.0f} ms, max {max(ms)} ms.", "",
              "## 2. Gallery fixtures through the whole brain", "",
              "| Case | Domain | Label | Hard rule (also fired) | Credential Tracker findings | Tracker ms | Deep ms |",
              "|---|---|---|---|---|---|---|"]
    for g in r["gallery"]:
        rule = (g["hard_rule"] or "–") + (f" ({', '.join(g['also_fired'])})" if g["also_fired"] else "")
        lines.append(f"| {g['case']} | `{g['domain']}` | {g['label'].upper().replace('_', ' ')} | {rule} | {', '.join(g['tracker']) or '–'} | "
                     f"{g['tracker_ms'] or '–'} | {g['deep_ms'] or '–'} |")
    s = r["safety"]
    lines += ["", "Reasons:", ""] + [f"- **{g['case']}**: {g['reason']}" for g in r["gallery"]] + [
        "", "## 3. Safety", "",
        f"- Requests the zoo pages made after the submit: {s['requests']}. Over the whole sessions, answered inside the "
        f"sandbox by the sink: {s['answered_locally']}; refused: {s['refused']}. No hostname resolves (`MAP * ~NOTFOUND`), so nothing could "
        "leave even if a route missed it (Playwright doesn't route HTTP redirects: the resolver is what stops those).",
        f"- Unredacted Telegram tokens in any evidence or verdict: **{s['unredacted_tokens']}** (the fixtures' tokens are "
        "made up, built at runtime, and still redacted to `12345****:[REDACTED]`).",
        f"- Every gallery verdict validates against the contract: **{s['all_valid']}**.",
        "",
        "## 4. What this does and doesn't show",
        "",
        "- The zoo pages and the fixture backends are **ours** (simulated kits); the techniques follow public kit "
        "write-ups, but this is not a measurement on live kits (Doppel never opens one).",
        "- **C15 depends on the kit's server**, which a fixture plays (`backend:` in `sites.yaml`). Without a "
        "backend answer (a form that posts to a foreign server Doppel never contacts) the behaviour after login "
        "is reported as unknown, not guessed.",
        "- **Server-side exfiltration is invisible** (`server_side_mail`): the tracker reports the first hop (the "
        "page's own server, outside the brand's family), which is still enough for H2 when the page claims a brand.",
        "- Encodings: plain, URL-encoded (twice) and base64 are decoded; anything else (`hex_body`) is a miss.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    reg = load_registry()
    assert TELEGRAM_TOKEN.fullmatch(fake_telegram_token("zoo")), "the fixture token must look like a real one"
    z = run_zoo(reg)
    g = run_gallery()
    r = {"date": time.strftime("%Y-%m-%d"), "zoo": z, "gallery": g,
         "safety": {"requests": sum(k["requests"] for k in z), "answered_locally": sum(k["answered_locally"] for k in z),
                    "refused": sum(k["refused"] for k in z),
                    "unredacted_tokens": sum(k["unredacted_tokens"] for k in z) + sum(x["unredacted_tokens"] for x in g),
                    "all_valid": all(x["valid"] for x in g)}}
    OUT.write_text(json.dumps(r, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT}")
    if "--md" in sys.argv:
        md = OUT.with_suffix(".md")
        md.write_bytes(render_md(r).encode("utf-8"))
        print(f"wrote {md}")


if __name__ == "__main__":
    main()
