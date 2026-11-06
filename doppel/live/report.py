"""``docs/eval/p12-live.md``, regenerated from the catch store (``doppel live report``) as the collector runs."""

from __future__ import annotations

import datetime as dt
import json
import statistics
from collections import Counter
from pathlib import Path

from doppel.live import mode_dir
from doppel.live.store import Store

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def _t(x: float | None) -> str:
    return dt.datetime.fromtimestamp(x, IST).strftime("%Y-%m-%d %H:%M IST") if x else "-"


def _rel(p: Path) -> str:
    from doppel.contract import REPO_ROOT
    try:
        return p.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return p.name


def _n(x) -> str:
    return f"{x:,}" if isinstance(x, int) else str(x)


METHOD = [
    "## 0. How it works", "",
    "- **Stream:** `wss://api.certstream.dev/` (public CT logs). Both message formats are parsed (`certificate_update`, "
    "`dns_entries`); since 2026-11-06 the server sends `dns_entries` (names only).",
    "- **Judged by:** the real brain, `Brain.investigate(name, \"ct_feed\")`: Quick for every unique name, Standard "
    "when there's a brand signal, never Deep, never a connection to the name.",
    "- **Naive baseline:** a keyword alert on the same names: any alias of a registry brand (3+ letters) anywhere "
    "in the name (`doppel/live/naive.py`).",
    "- **CT facts:** for flagged names only, one SSLMate lookup at a time under a daily cap (highest priority first; "
    "never platform tenants). Then the name is judged again, so C16/C17 join the verdict.",
    "- **Sleepers:** hagezi NRD look-alikes Doppel flags go on a watch list; when a watched name appears in the "
    "stream (a new certificate), that's an arming alarm.",
    "- **Lead time:** Phishing.Database ACTIVE is polled hourly. A flagged name counts as *ahead* only when a poll "
    "taken after the flag still didn't list it and a later poll did.",
    "- **Resilience:** reconnect with backoff; alarms when the stream goes silent (30 s), slows below 50 names/s, or "
    "sends messages with no names (format change); `doppel live reconnect` forces the reconnect path.",
]

HONEST = [
    "## 10. Honest notes", "",
    "- **These are names, not verdicts on sites.** A flag means the name imitates a protected brand. Nobody visited "
    "the pages, so a flag is a review queue item, never \"confirmed phishing\".",
    "- **False-alarm classes seen live on 2026-11-06:** Google's own regional API hosts "
    "(`*.rep.googleapis.com`, a private-PSL platform, O48, by design); `googlegroups.com` (Google's, not in the "
    "registry, and itself on Phishing.Database because it hosts user content); email-shaped names on hosting "
    "platforms (`vuskosgmail.direct.quickconnect.to`, fix (c) skips platforms on purpose: a free-hosted "
    "`xyzgmail` page can be a real Gmail phish); one-edit typos of short names (`ubi.dev` vs sbi, `nmall.vc` and "
    "`grail.com` vs gmail, O14).",
    "- **The keyword baseline is ours** (our 9 brands' aliases). The 2026-11-06 scratch measurement's \"1,019 "
    "alerts in 35 s\" used a different keyword list; the ratio here is from this baseline only.",
    "- **Dedupe** can skip ~0.1% of new names (Bloom filter false positives). **Hours watched** counts collector "
    "runs only: a sleeping laptop or a stopped collector isn't counted.",
]


def lead_rows(store: Store) -> tuple[Counter, list[dict]]:
    """Per-status counts and the ``listed_after`` rows, for catches (stream) and the watch list (NRD)."""
    counts: Counter = Counter()
    rows = []
    for table, key, seen, src in (("catches", "name", "first_seen", "stream"), ("watchlist", "owner", "added", "nrd")):
        for r in store.db.execute(f"SELECT {key} AS k, brand, {seen} AS f, pdb_status, pdb_prev_poll, "
                                  f"pdb_listed_poll, pdb_match FROM {table}"):
            counts[(src, r["pdb_status"] or "no_poll_yet")] += 1
            if r["pdb_status"] == "listed_after":
                rows.append({"name": r["k"], "source": src, "brand": r["brand"], "flagged": r["f"],
                             "lead_min_h": (r["pdb_prev_poll"] - r["f"]) / 3600,
                             "lead_max_h": (r["pdb_listed_poll"] - r["f"]) / 3600, "match": r["pdb_match"]})
    rows.sort(key=lambda r: -r["lead_min_h"])
    return counts, rows


def build(root: Path | None = None, mode: str = "live") -> str:
    folder = mode_dir(mode, root)
    db = folder / "catches.db"
    if not db.is_file():
        return f"# P12 Live Hunt\n\nNo catch store yet at `{db}`. Start the collector: `doppel live run`.\n"
    s = Store(db, readonly=True)
    sessions = [dict(r) for r in s.db.execute("SELECT * FROM sessions ORDER BY started")]
    tot = s.totals()
    hours = s.hours_watched()
    longest = max(((x["last_beat"] - x["started"]) / 3600 for x in sessions), default=0)
    first = min((x["started"] for x in sessions), default=None)
    last = max((x["last_beat"] for x in sessions), default=None)
    labels = s.count_catches()
    flags = sum(labels.values())
    brands = Counter(r[0] or "?" for r in s.db.execute("SELECT brand FROM catches"))
    tricks = Counter(t for (x,) in s.db.execute("SELECT tricks FROM catches") for t in (x or "").split(",") if t)
    ct = Counter(r[0] or "not queued" for r in s.db.execute("SELECT ct_status FROM catches"))
    armed_ct = s.db.execute("SELECT COUNT(*) FROM catches WHERE ct_armed=1").fetchone()[0]
    genuine = [dict(r) for r in s.db.execute("SELECT * FROM genuine ORDER BY first_seen")]
    gbrand = Counter(g["brand"] or "?" for g in genuine)
    ws = s.watch_stats()
    armings = s.armings(100)
    alarms = s.alarms(limit=200)
    polls = s.polls("pdb")
    nrd_polls = s.polls("nrd")
    counts, lead = lead_rows(s)
    budget = [dict(r) for r in s.db.execute("SELECT * FROM ct_budget ORDER BY day")]
    doppel_only = [dict(r) for r in s.db.execute(
        "SELECT name, brand, tricks, risk FROM catches WHERE naive IS NULL ORDER BY risk DESC LIMIT 15")]
    top = [dict(r) for r in s.db.execute(
        "SELECT name, brand, label, risk, tricks, first_seen, ct_count, ct_first, ct_cert_not_before, pdb_status "
        "FROM catches ORDER BY risk DESC, first_seen LIMIT 25")]
    naive_total, uniq = tot["naive"], tot["uniq"]

    L = [f"# P12 Live Hunt: the world's new certificates, judged live ({mode})", "",
         f"**Regenerated by `doppel live report`** on {_t(dt.datetime.now().timestamp())} from `{_rel(db)}`. "
         "Every number below comes from the catch store; nothing is typed by hand.", "",
         "**Names only.** Every name here comes from Certificate Transparency logs (certstream). Doppel never visited "
         "any of them. \"Flagged\" means *the name imitates a protected brand*, not \"confirmed phishing\".", "",
         *METHOD, "",
         "## 1. Watch time", "",
         "| | |", "|---|---|",
         f"| First start | {_t(first)} |", f"| Last heartbeat | {_t(last)} |",
         f"| Hours watched (sum of collector runs) | **{hours:.1f} h** in {len(sessions)} run(s) |",
         f"| Longest unattended run | **{longest:.1f} h** |",
         f"| Minutes with traffic | {_n(tot['minutes'])} |", "",
         "## 2. The counter (naive keyword vs Doppel)", "",
         "| | |", "|---|---|",
         f"| Certificates (log entries) | **{_n(tot['certs'])}** |",
         f"| Names in them | {_n(tot['names'])} |",
         f"| Unique names judged | **{_n(uniq)}** |",
         f"| Naive keyword alerts (a brand alias anywhere in the name) | **{_n(naive_total)}** |",
         f"| Doppel flags (NEEDS REVIEW / PHISHING) | **{_n(tot['flags'])}** ({_n(flags)} distinct names in the store) |",
         f"| Proven GENUINE live (a brand's own new names) | {_n(tot['genuine'])} |",
         f"| Both flagged | {_n(tot['both_hit'])} |",
         f"| Keyword only (noise Doppel cleared) | {_n(tot['naive_only'])} |",
         f"| Doppel only (look-alikes with no brand spelled out) | **{_n(tot['doppel_only'])}** |",
         f"| Dropped (queue full) / unreadable | {_n(tot['dropped'])} / {_n(tot['errors'])} |", ""]
    if tot["flags"]:
        L.append(f"Keyword alerts per Doppel flag: **{naive_total / max(1, tot['flags']):.1f}x**. "
                 f"Doppel flags {tot['flags'] / max(1, uniq) * 100:.3f}% of unique names.")
        L.append("")
    L += ["Dedupe: two rotating Bloom filters (8M names each, 0.1% false-positive rate): about 1 in 1,000 new names "
          "can be taken for a repeat and skipped.", "",
          "## 3. What was flagged", "",
          "| Label | Names |", "|---|---|", *[f"| {k} | {v:,} |" for k, v in sorted(labels.items())], "",
          "| Brand | Names |", "|---|---|", *[f"| {k} | {v:,} |" for k, v in brands.most_common()], "",
          "| Name-level finding (trick or signal) | Names |", "|---|---|", *[f"| {k} | {v:,} |" for k, v in tricks.most_common(12)], ""]
    if doppel_only:
        L += ["**Doppel-only catches** (no brand alias spelled out, so a keyword filter can't see them), top by risk:", "",
              "| Name | Brand | Tricks | Risk |", "|---|---|---|---|",
              *[f"| `{r['name']}` | {r['brand']} | {r['tricks']} | {r['risk']:.3f} |" for r in doppel_only], ""]
    L += ["**Top catches by risk:**", "",
          "| Name | Brand | Label | Risk | Tricks | First seen | CT certs | Cert not-before | List |",
          "|---|---|---|---|---|---|---|---|---|",
          *[f"| `{r['name']}` | {r['brand']} | {r['label']} | {r['risk']:.3f} | {r['tricks']} | {_t(r['first_seen'])} | "
            f"{r['ct_count'] if r['ct_count'] is not None else '-'} | {r['ct_cert_not_before'] or '-'} | "
            f"{r['pdb_status'] or '-'} |" for r in top], "",
          "## 4. Proven genuine live", "",
          f"{len(genuine):,} names proven genuine as they appeared ({', '.join(f'{k} {v}' for k, v in gbrand.most_common())}). "
          "Samples: " + ", ".join(f"`{g['name']}`" for g in genuine[:8]) + ("" if genuine else "none yet") + ".", "",
          "## 5. Certificate facts for flagged names (CT search, capped)", "",
          "| CT status | Catches |", "|---|---|", *[f"| {k} | {v:,} |" for k, v in ct.most_common()], "",
          f"Armed (first certificate within 90 days): {armed_ct}. Lookups spent per day: " +
          (", ".join(f"{b['day']} {b['used']}" for b in budget) or "none") + ".", "",
          "## 6. Sleepers and arming alarms", "",
          f"Watch list: **{ws['watched']:,}** NRD look-alikes ({ws['cert_known_at_add']:,} already had a cached "
          f"certificate when added); **{ws['armed']:,} armed** so far. NRD ingests: " +
          ("; ".join(f"{_t(p['t'])}: {p['note']}" for p in nrd_polls) or "none yet") + ".", ""]
    if armings:
        L += ["| Armed at | Watched owner | Name in the new certificate | Brand | On the watch list since |",
              "|---|---|---|---|---|",
              *[f"| {_t(a['t'])} | `{a['owner']}` | `{a['name']}` | {a['brand']} | {_t(a['watch_added'])} |"
                for a in armings], ""]
    L += ["## 7. Ahead of the blocklist (Phishing.Database ACTIVE)", "",
          f"Polls: {len(polls)} ({_t(polls[0]['t']) if polls else '-'} to {_t(polls[-1]['t']) if polls else '-'}). "
          "One public list, not Google Safe Browsing.", "",
          "| Source | Status | Names |", "|---|---|---|",
          *[f"| {src} | {st} | {n:,} |" for (src, st), n in sorted(counts.items())], ""]
    if lead:
        lo = [r["lead_min_h"] for r in lead]
        L += [f"**Flagged before the list: {len(lead)} names.** Lead time (lower bound) median "
              f"**{statistics.median(lo):.1f} h**, max {max(lo):.1f} h. Each row's lead lies between the two bounds "
              "(the list is polled, so the listing time is known to within one poll).", "",
              "| Name | From | Brand | Flagged | Lead (h, min-max) | Match |", "|---|---|---|---|---|---|",
              *[f"| `{r['name']}` | {r['source']} | {r['brand']} | {_t(r['flagged'])} | {r['lead_min_h']:.1f}-"
                f"{r['lead_max_h']:.1f} | {r['match']} |" for r in lead[:40]], ""]
    else:
        L += ["No flagged name has appeared on the list after Doppel flagged it yet.", ""]
    L += ["## 8. Alarms (the stream going silent, slow, or changing format)", ""]
    if alarms:
        L += ["| Kind | Raised | Resolved | Message |", "|---|---|---|---|",
              *[f"| {a['kind']} | {_t(a['t'])} | {_t(a['resolved'])} | {a['message']} |" for a in alarms[:40]], ""]
    else:
        L += ["None.", ""]
    L += ["## 9. Runs", "", "| Run | Source | Started | Last heartbeat | Hours |", "|---|---|---|---|---|",
          *[f"| {x['id']} | {x['source'][:60]} | {_t(x['started'])} | {_t(x['last_beat'])} | "
            f"{(x['last_beat'] - x['started']) / 3600:.2f} |" for x in sessions], "", *HONEST]
    s.close()
    return "\n".join(L)


def write(out: Path, root: Path | None = None, mode: str = "live") -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(root, mode), encoding="utf-8")
    return out


def summary(root: Path | None = None, mode: str = "live") -> dict:
    """Small numbers for the API / UI header (all-time, from the store)."""
    db = mode_dir(mode, root) / "catches.db"
    if not db.is_file():
        return {}
    s = Store(db, readonly=True)
    try:
        counts, lead = lead_rows(s)
        out = {"totals": s.totals(), "hours_watched": s.hours_watched(), "catches": s.count_catches(),
               "watch": s.watch_stats(),
               "lead": {"listed_after": len(lead),
                        "median_min_h": round(statistics.median([r["lead_min_h"] for r in lead]), 1) if lead else None,
                        "rows": [{**r, "lead_min_h": round(r["lead_min_h"], 2), "lead_max_h": round(r["lead_max_h"], 2)}
                                 for r in lead[:10]],
                        "by_status": {f"{a}:{b}": n for (a, b), n in counts.items()}},
               "polls": len(s.polls("pdb"))}
    finally:
        s.close()
    return json.loads(json.dumps(out))
