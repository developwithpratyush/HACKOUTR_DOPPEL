"""Re-check data/brands/registry.yaml against the live internet.

    python scripts/data/verify_registry.py            # DNS for every family domain
    python scripts/data/verify_registry.py --sources  # also fetch every source URL

For each genuine_family domain it resolves the apex, then www.<domain> (some
apexes, e.g. incometax.gov.in, have no record of their own). Writes
data/brands/verification.json, a dated record of what resolved, so the
datasheet can say when the registry was last checked.

This only touches the brands' own domains and our cited sources. It never
visits look-alike or criminal domains.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from doppel.contract import load_yaml, validate_registry  # noqa: E402

REGISTRY = REPO / "data" / "brands" / "registry.yaml"
REPORT = REPO / "data" / "brands" / "verification.json"
UA = "Mozilla/5.0 (doppel registry check)"


def resolve(host: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def check_domain(domain: str) -> dict:
    for host in (domain, f"www.{domain}"):
        ips = resolve(host)
        if ips:
            return {"domain": domain, "resolves": True, "via": host, "ips": ips[:3]}
    return {"domain": domain, "resolves": False, "via": None, "ips": []}


def check_url(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return {"url": url, "status": resp.status, "final_url": resp.geturl()}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "final_url": url}
    except Exception as exc:  # TLS, timeout, DNS
        return {"url": url, "status": None, "error": type(exc).__name__ + ": " + str(exc)[:120]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", action="store_true", help="also fetch every source URL")
    args = ap.parse_args(argv)

    registry = load_yaml(REGISTRY)
    problems = validate_registry(registry)
    if problems:
        print("registry fails its contract:", *problems, sep="\n  - ")
        return 1

    domains = [(b["id"], e) for b in registry["brands"] for e in b["genuine_family"]]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda item: {"brand": item[0], "verified_on": item[1]["verified_on"],
                                               **check_domain(item[1]["domain"])}, domains))
    report = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "domains": results}

    # A family domain with no DNS isn't an error by itself (parked legacy names),
    # but it is worth a look: a lapsed .com could be re-registered by an attacker.
    no_dns = [r for r in results if not r["resolves"]]
    for r in results:
        mark = "ok  " if r["resolves"] else "WARN"
        print(f"{mark} {r['brand']:11} {r['domain']:32} via {r['via'] or '-'}")

    if args.sources:
        urls = sorted({e["source"] for _, e in domains if e["source"]}
                      | {r["source"] for r in registry["restricted_registries"] if r["source"]}
                      | {r["source"] for r in registry.get("brand_tld_registry", []) if r["source"]})
        with ThreadPoolExecutor(max_workers=8) as pool:
            report["sources"] = list(pool.map(check_url, urls))
        for s in report["sources"]:
            print(f"src  {s.get('status') or 'ERR':>4} {s['url']}")

    unverified = [f"{b}:{e['domain']}" for b, e in domains if e["verified_on"] is None]
    report["unverified_entries"] = unverified
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    bad_sources = [s["url"] for s in report.get("sources", []) if s.get("status") != 200]
    print(f"\n{len(results) - len(no_dns)}/{len(results)} family domains resolve; "
          f"{len(unverified)} entries still unverified. Report: {REPORT.relative_to(REPO)}")
    for r in no_dns:
        print(f"WARN no DNS for {r['domain']}: check it hasn't lapsed (see its note in the registry)")
    for url in bad_sources:
        print(f"WARN source didn't return 200 to this script (may block bots): {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
