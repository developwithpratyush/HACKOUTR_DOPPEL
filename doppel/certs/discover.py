"""Family auto-discovery (P11): let the brands' own certificates complete their families.

    python -m doppel.certs.discover            # live TLS reads of proven seeds (cached), write discovered.yaml
    python -m doppel.certs.discover --ct       # also search CT logs for certificates that name a seed apex
    python -m doppel.certs.discover --offline  # rebuild discovered.yaml from the cache only

**Why it's proof.** A CA validates control of every name on a certificate before signing it. So when a
certificate lists a name the Family Verifier has already proven (a *seed*) next to another name, the CA has
confirmed that one operator controls both: the other name joins the family. Google's ``google.com``
certificate lists 65 names, including ``*.google.co.in``, ``google-analytics.com`` and ``urchin.com``.

**Guards** (docs/BUILD_PHASES.md, P11):
1. The seed must be proven by the P2 proofs: ``tls.read_seed`` refuses any other host before a socket opens,
   and every certificate must list at least one proven name of the brand.
2. Multi-tenant CDN certificates are skipped (one certificate, many unrelated customers).
3. A name on a user-content or private-PSL host (``*.web.app``, ``*.appspot.com``, ``*.googleapis.com``) proves
   **only the platform, never the tenant**: Google's ``withgoogle.com`` certificate lists ``*.appspot.com``,
   and an HDFC phishing page lives on ``*.uk.r.appspot.com``. Such names go to ``platform_only``; only the bare
   platform name itself (``appspot.com``) is accepted, as an exact name.

SAN links to a proven seed are accepted automatically. Anything else (conflicts, CDN certificates, CT
certificates that don't name a proven seed) is listed under ``review`` for a person.
Output: ``data/brands/discovered.yaml`` (``doppel.certs.index`` reads it).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

import yaml

from doppel.address import read_address
from doppel.certs import ct, store, tls
from doppel.contract import REPO_ROOT, load_yaml
from doppel.family import check_family, load_registry

DISCOVERED = REPO_ROOT / "data" / "brands" / "discovered.yaml"
SEEDS = REPO_ROOT / "data" / "brands" / "cert_seeds.yaml"

# Guard 2: shared CDN certificates (one certificate for many unrelated customers).
CDN_ORGS = {"cloudflare, inc.", "fastly, inc.", "incapsula inc", "imperva inc.", "akamai technologies, inc.",
            "stackpath, llc", "edgecast inc."}
CDN_SAN_MARKERS = ("cloudflaressl.com", "ssl.fastly.net", "incapsula.com", "sucuri.net", "edgecastcdn.net",
                   "akamaihd.net", "netlify.app", "herokuapp.com")


def seed_hosts(reg) -> dict[str, list[str]]:
    extra = load_yaml(SEEDS) if SEEDS.exists() else {}
    out: dict[str, list[str]] = {}
    for b in reg.brands:
        hosts = []
        for e in b.family:
            hosts += [e.domain, "www." + e.domain]
        hosts += list(extra.get(b.id) or [])
        out[b.id] = list(dict.fromkeys(hosts))
    return out


def _strip(san: str) -> str:
    return san[2:] if san.startswith("*.") else san


def _brand_of(name: str, reg) -> tuple[str | None, object]:
    """(brand id proven by P2, the reading) for one SAN name; brand id None if not proven."""
    try:
        r = read_address(name)
    except ValueError:
        return None, None
    fam = check_family(r, reg)
    return (fam.brand.id if fam.genuine and fam.brand else None), (r, fam)


def _user_content(host: str, reg) -> str | None:
    for b in reg.brands:
        for uc in b.user_content:
            if uc.covers(host):
                return uc.host
    return None


def classify(cert: dict, brand: str, seed_host: str, source: str, fetched_at: str, reg) -> dict:
    """Sort one certificate's names: accepted SAN links, platform-only names, or a reason to review it."""
    sans = cert.get("sans", [])
    org = (cert.get("subject") or {}).get("o")
    base = {"brand": brand, "seed_host": seed_host, "cert_sha256": cert.get("sha256"), "source": source,
            "seen_on": fetched_at[:10]}
    if (org or "").lower() in CDN_ORGS or any(s.endswith(m) for s in sans for m in CDN_SAN_MARKERS):
        return {"review": [{**base, "reason": f"shared CDN certificate (O={org!r}): one certificate for many "
                                              "customers proves nothing about any of them (guard 2)"}]}
    proven, others, conflicts = [], [], []
    for san in sans:
        bid, info = _brand_of(_strip(san), reg)
        if bid == brand:
            proven.append(san)
        elif bid is not None:
            conflicts.append(f"{san} ({bid})")
        else:
            others.append((san, info))
    proven.sort(key=lambda s: (s.startswith("*."), s != seed_host, len(s)))   # cite the plainest proven name
    if conflicts:
        return {"review": [{**base, "reason": "lists names proven for another brand: " + ", ".join(conflicts[:5])}]}
    if not proven:
        return {"review": [{**base, "reason": f"no name on it is a proven {brand} name (seed {seed_host})"}]}

    accepted, platform = [], []
    for san, info in others:
        name = _strip(san)
        r = info[0] if info else None
        if r is None:
            continue
        uc = _user_content(name, reg)
        if uc:                       # a brand's own user-content host (docs.google.com): never a family proof
            platform.append({**base, "san": san, "platform": uc,
                             "reason": f"{uc} is {brand}'s user-content host: anyone publishes there (guard 3)"})
            continue
        if r.hosting_platform:
            plat = r.hosting_platform
            # the platform's own registrable name (appspot.com, googleapis.com; a wildcard is validated on its base
            # name, BR 3.2.2.6), not its regional sub-suffixes (de.r.appspot.com)
            if name == plat and plat.count(".") == r.icann_suffix.count(".") + 1:
                accepted.append({**base, "domain": plat, "include_subdomains": False, "san": san,
                                 "linked_to": proven[:3],
                                 "note": "the platform's own name only: its tenants stay unproven (guard 3)"})
            if name != plat or san.startswith("*."):
                platform.append({**base, "san": san, "platform": plat,
                                 "reason": f"{plat} is a hosting platform: a certificate here proves the platform, "
                                           "never a tenant (guard 3)"})
            continue
        if san in (r.owner, "*." + r.owner):
            accepted.append({**base, "domain": r.owner, "include_subdomains": True, "san": san, "linked_to": proven[:3]})
        else:
            accepted.append({**base, "domain": name, "include_subdomains": san.startswith("*."), "san": san,
                             "linked_to": proven[:3]})
    return {"accepted": accepted, "platform_only": platform}


def _dedupe(entries: list[dict]) -> list[dict]:
    """One entry per (brand, domain); drop names already covered by another entry with subdomains."""
    by: dict[tuple[str, str], dict] = {}
    for e in entries:
        k = (e["brand"], e["domain"])
        if k not in by or (e["include_subdomains"] and not by[k]["include_subdomains"]):
            by[k] = e
    wide = {(e["brand"], e["domain"]) for e in by.values() if e["include_subdomains"]}

    def covered(e):
        parts = e["domain"].split(".")
        return any((e["brand"], ".".join(parts[i:])) in wide for i in range(1, len(parts) - 1))
    return sorted((e for e in by.values() if not covered(e)), key=lambda e: (e["brand"], e["domain"]))


def legal_match(cert: dict, brand) -> bool | None:
    org = (cert.get("subject") or {}).get("o")
    if not org:
        return None
    c = (cert.get("subject") or {}).get("c")
    return any(org.casefold() == n.casefold() and (cc is None or c == cc) for n, cc in brand.legal_names)


def discover(reg=None, use_ct: bool = False, refresh: bool = False, log=print,
             ct_brands: set[str] | None = None) -> dict:
    reg = reg or load_registry()
    brands = {b.id: b for b in reg.brands}
    certs: list[tuple[str, str, str, str, dict]] = []      # (brand, seed host, source, fetched_at, cert)
    seeds_out, failures = [], []
    for bid, hosts in seed_hosts(reg).items():
        for host in hosts:
            try:
                rec = tls.read_seed(host, reg, refresh=refresh)
            except tls.NotProvenGenuine as exc:
                failures.append({"brand": bid, "host": host, "error": str(exc)})
                continue
            except (OSError, ConnectionError, ValueError) as exc:
                failures.append({"brand": bid, "host": host, "error": f"{type(exc).__name__}: {str(exc)[:100]}"})
                continue
            c = rec["cert"]
            certs.append((bid, host, "live_tls", rec["fetched_at"], c))
            seeds_out.append({"brand": bid, "host": host, "fetched_at": rec["fetched_at"], "cert_sha256": c["sha256"],
                              "issuer": c["issuer"]["o"], "validation": c["validation"],
                              "organisation": c["subject"]["o"], "country": c["subject"]["c"], "sans": len(c["sans"]),
                              "legal_name_match": legal_match(c, brands[bid])})
        if use_ct and (ct_brands is None or bid in ct_brands):
            for e in brands[bid].family:
                try:
                    rec = ct.search(e.domain, include_subdomains=False, refresh=refresh)
                except (ConnectionError, ct.RateLimited) as exc:
                    failures.append({"brand": bid, "host": e.domain, "error": f"CT: {str(exc)[:120]}"})
                    continue
                for c in (rec or {}).get("issuances", []):
                    certs.append((bid, e.domain, "ct_" + rec["source"], rec["fetched_at"], c))
        log(f"  {bid}: {sum(1 for x in certs if x[0] == bid)} certificates")

    accepted, platform, review, cert_facts = [], [], [], {}
    for bid, host, source, fetched, c in certs:
        res = classify(c, bid, host, source, fetched, reg)
        accepted += res.get("accepted", [])
        platform += res.get("platform_only", [])
        review += res.get("review", [])
        if res.get("accepted") and c.get("sha256"):
            cert_facts[c["sha256"]] = {"issuer": c["issuer"].get("o"), "organisation": (c.get("subject") or {}).get("o"),
                                       "validation": c.get("validation"), "not_before": c.get("not_before"),
                                       "not_after": c.get("not_after"), "sans": c.get("sans", [])}
    plat_seen, plat_out = set(), []
    for p in platform:
        if (p["brand"], p["san"]) not in plat_seen:
            plat_seen.add((p["brand"], p["san"]))
            plat_out.append(p)
    # Validated organisations on proven seeds that aren't the brand's listed legal names: for a person to add
    # (a subsidiary or a department's other name) or to leave out. Never added automatically.
    proposals: dict[tuple[str, str], dict] = {}
    for s in seeds_out:
        if s["legal_name_match"] is False:
            proposals.setdefault((s["brand"], s["organisation"]), {"brand": s["brand"], "organisation": s["organisation"],
                                                                   "country": s["country"], "seen_on": [], "validation": s["validation"]})
            proposals[(s["brand"], s["organisation"])]["seen_on"].append(s["host"])
    return {
        "generated": dt.date.today().isoformat(),
        "rule": ("A name on the same certificate as a name the Family Verifier already proves is controlled by the "
                 "same operator (the CA validated every name). Accepted automatically; guards in doppel/certs/discover.py."),
        "accepted": _dedupe(accepted),
        "platform_only": plat_out,
        "review": review,
        "seeds": seeds_out,
        "legal_name_proposals": list(proposals.values()),
        "seed_failures": failures,
        "certificates": cert_facts,
    }


def write(result: dict, path: Path = DISCOVERED) -> None:
    head = ("# Family auto-discovery (P11): written by `python -m doppel.certs.discover`. Don't edit by hand:\n"
            "# accepted = SAN links to a proven seed (automatic); platform_only = guard 3 (never the tenant);\n"
            "# review = for a person to check. Certificates are cached under data/certs/.\n")
    path.write_text(head + yaml.safe_dump(result, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Family auto-discovery from the brands' own certificates.")
    ap.add_argument("--ct", action="store_true", help="also search CT logs for certificates naming each seed apex")
    ap.add_argument("--ct-brands", help="comma-separated brand ids for --ct (the unauthenticated quota is ~10 lookups)")
    ap.add_argument("--refresh", action="store_true", help="re-read certificates even when cached")
    ap.add_argument("--offline", action="store_true", help="cache only")
    args = ap.parse_args(argv)
    if args.offline:
        import os
        os.environ["DOPPEL_OFFLINE"] = "1"
    res = discover(use_ct=args.ct, refresh=args.refresh,
                   ct_brands=set(args.ct_brands.split(",")) if args.ct_brands else None)
    write(res)
    by = {}
    for e in res["accepted"]:
        by[e["brand"]] = by.get(e["brand"], 0) + 1
    print(f"accepted {len(res['accepted'])} ({', '.join(f'{k} {v}' for k, v in sorted(by.items()))}), "
          f"platform-only {len(res['platform_only'])}, review {len(res['review'])}, "
          f"seed failures {len(res['seed_failures'])} -> {DISCOVERED.relative_to(REPO_ROOT)}")
    for f in res["seed_failures"]:
        print(f"  seed {f['host']}: {f['error']}", file=sys.stderr)


if __name__ == "__main__":
    main()
