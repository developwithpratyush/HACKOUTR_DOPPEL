"""Certificate Forensics tools (P11): C16 certificate identity, C17 certificate history.

``cert_forensics`` (Quick, C16, no network): reads the family auto-discovery index.
  - ``certificate_san_link`` (genuine, strong): the name is on the same certificate as a name the Family
    Verifier proves, so the CA validated that one operator controls both. A 4th family proof.
  - ``certificate_platform_only`` (neutral): the name sits on a hosting platform or a brand's user-content host.
    Any certificate there is the platform's wildcard: it proves the platform, never the tenant (guard 3).
  - ``no_certificate_link`` (neutral): no proven brand certificate lists it.

``ct_history`` (Standard, C16 + C17): a CT-log search for the suspect's registrable domain (third party only;
never a connection to the suspect). Cached; the network only for single investigations.
  - ``certificate_organisation_match`` (genuine, strong): an OV/EV certificate for the name carries one of a
    brand's validated legal names, exactly (case-folded, never a substring), and the country when listed.
  - ``certificate_organisation_other`` (neutral): a validated company that is *not* the brand's legal name
    (SBI Card: "SBI CARDS AND PAYMENT SERVICES LIMITED" is a real company, but not State Bank of India).
    Shown as evidence; it doesn't clear the name. A certificate proves who, not corporate group ties.
  - ``armed`` (phishing, weak): the look-alike got its first certificate in the last 90 days (score 1.0 within
    30): it's getting ready to go live. It raises the priority; it never makes a name PHISHING on its own.
  - ``established_certificates`` (neutral): certificates for more than 90 days: an established site.
  - ``no_certificate_yet`` (neutral): not armed (a sleeper).

**Proof when present, never required.** No Organisation field is neutral: the real e-Challan site, PhonePe,
``sbi.co.in`` and all of Google have DV certificates, exactly like the attackers'.
"""

from __future__ import annotations

import datetime as dt
import time
from collections import Counter
from dataclasses import dataclass, field

from doppel.certs import ct
from doppel.certs.facts import san_covers
from doppel.certs.index import SanIndex, load_index
from doppel.evidence import Ids, brand_ref, evidence

TOOL_Q, TOOL_S = "cert_forensics", "ct_history"
RECENT_DAYS = 30          # first certificate this recent: armed (score 1.0)
ESTABLISHED_DAYS = 90     # first certificate older than this: an established site (neutral)


@dataclass
class CertResult:
    proven: bool = False               # a family proof (SAN link or legal-name match)
    brand: object | None = None        # the brand proven (or imitated, for the history)
    platform_only: bool = False
    checked: bool = False              # ct_history: a CT record was available
    armed: bool | None = None
    organisation: str | None = None
    history: dict = field(default_factory=dict)


def _platform(r, fam) -> str | None:
    if fam is not None and fam.status == "user_content":
        return fam.platform
    # a tenant of a platform; the platform's own name (googleapis.com, appspot.com) can still be proven
    return r.hosting_platform if r.hosting_platform and r.host != r.hosting_platform else None


def cert_forensics(r, fam, brand, reg, ids: Ids | None = None, index: SanIndex | None = None
                   ) -> tuple[CertResult, list[dict]]:
    """Quick-stage C16 from the discovery index. ``brand``: the brand the name imitates (for the wording)."""
    ids = ids or Ids()
    idx = index if index is not None else load_index()
    t0 = time.perf_counter()
    res = CertResult()
    common = {"tool": TOOL_Q, "stage": "quick", "criterion": "C16"}
    brands = {b.id: b for b in reg.brands}
    plat = _platform(r, fam)
    if plat:
        res.platform_only = True
        owner = idx.lookup(plat)
        whose = f" ({plat} itself is {brands[owner['brand']].name}'s, on its own certificate)" if owner and owner["brand"] in brands else ""
        item = evidence(ids, **common, finding="certificate_platform_only", points_to="neutral", strength="strong",
                        score=0, target_brand=brand_ref(brand),
                        summary=(f"{r.host} is a tenant on {plat}{whose}. Any certificate here is the platform's "
                                 f"(a *.{plat} wildcard): it proves the platform, never the tenant, so the padlock "
                                 "says nothing about who made this page."),
                        platform=plat, platform_brand=owner["brand"] if owner else None, guard="platform_never_tenant")
    elif (hit := idx.lookup(r.host)) and hit["brand"] in brands:
        b = brands[hit["brand"]]
        res.proven, res.brand = True, b
        cert = idx.cert(hit.get("cert_sha256"))
        sans = cert.get("sans", [])
        linked = (hit.get("linked_to") or ["a proven name"])[0]
        item = evidence(ids, **common, finding="certificate_san_link", points_to="genuine", strength="strong",
                        score=0.97, target_brand=brand_ref(b),
                        summary=(f"Proven {b.name}: {b.name}'s own certificate (served at {hit['seed_host']}, "
                                 f"{cert.get('issuer') or 'CA'}, {len(sans)} names) lists '{hit['san']}' next to "
                                 f"'{linked}', a proven {b.name} name. The CA checked that one operator controls "
                                 "every name on a certificate."),
                        proof="certificate_san", matched_san=hit["san"], linked_to=hit.get("linked_to", []),
                        family_entry=hit["domain"], include_subdomains=hit["include_subdomains"],
                        seed_host=hit["seed_host"], cert_sha256=hit.get("cert_sha256"), issuer=cert.get("issuer"),
                        validation=cert.get("validation"), organisation=cert.get("organisation"),
                        not_after=cert.get("not_after"), sans=sans, source=hit.get("source"),
                        seen_on=hit.get("seen_on"), discovered_in="data/brands/discovered.yaml")
    else:
        name = brand.name if brand else "a protected brand"
        item = evidence(ids, **common, finding="no_certificate_link", points_to="neutral", strength="medium", score=0,
                        target_brand=brand_ref(brand),
                        summary=(f"No certificate of a proven {name} name lists {r.host} "
                                 f"(family auto-discovery: {len(idx)} names linked, {idx.generated or 'never run'})."),
                        index_size=len(idx), index_generated=idx.generated)
    item["duration_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return res, [item]


def _legal_brand(org: str, country: str | None, reg):
    for b in reg.brands:
        for name, cc in b.legal_names:
            if org.casefold() == name.casefold() and (cc is None or country == cc):
                return b
    return None


def _days(a: str, b: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (dt.datetime.strptime(b[:19] + "Z", fmt) - dt.datetime.strptime(a[:19] + "Z", fmt)).total_seconds() / 86400


def shape(issuances: list[dict], owner: str) -> dict:
    """How the certificates name things: apex, wildcard, which subdomain labels (the attacker's recipe, P13)."""
    subs, recipes = Counter(), Counter()
    for c in issuances:
        parts = []
        sans = c.get("sans", [])
        if owner in sans:
            parts.append("apex")
        if f"*.{owner}" in sans:
            parts.append("wildcard")
        own = [s for s in sans if s.endswith("." + owner) and s != f"*.{owner}"]
        labels = {s[: -len(owner) - 1].lstrip("*.").split(".")[-1] for s in own}
        labels.discard("www")
        if "www." + owner in sans:
            parts.append("www")
        if labels:
            parts.append(f"{len(labels)} subdomain" + ("s" if len(labels) > 1 else ""))
        subs.update(labels)
        recipes[" + ".join(parts) or "other names"] += 1
    return {"recipes": dict(recipes.most_common()), "subdomain_labels": sorted(subs)}


def ct_history(r, brand, reg, ids: Ids | None = None, network: bool = False) -> tuple[CertResult, list[dict]]:
    """Standard-stage C16 (organisation) + C17 (history) from CT logs, for the registrable domain ``r.owner``."""
    ids = ids or Ids()
    t0 = time.perf_counter()
    res = CertResult(brand=brand)
    owner = r.owner
    common = {"tool": TOOL_S, "stage": "standard"}
    bname = brand.name if brand else "the brand"
    try:
        rec = ct.search(owner, include_subdomains=True, network=network)
        err = None
    except (ConnectionError, ct.RateLimited, OSError, ValueError) as exc:
        rec, err = None, f"{type(exc).__name__}: {str(exc)[:140]}"
    items: list[dict] = []
    if rec is None:
        why = err or ("no cached CT record and the network is off for this input" if not network else "no answer")
        items.append(evidence(ids, **common, criterion="C17", finding="ct_not_checked", points_to="neutral",
                              strength="weak", score=0, target_brand=brand_ref(brand),
                              summary=f"CT logs not checked for {owner}: {why}.", domain=owner, error=err))
        return res, _timed(items, t0)
    res.checked = True
    certs = rec.get("issuances", [])
    src = {"ct_source": rec.get("source"), "fetched_at": rec.get("fetched_at"), "truncated": rec.get("truncated", False)}

    # ---- C16: the validated organisation on a certificate that covers this very name
    orgs: dict[tuple[str, str | None], dict] = {}
    for c in certs:
        o = (c.get("subject") or {}).get("o")
        if o and any(san_covers(s, r.host) or s == owner for s in c.get("sans", [])):
            orgs.setdefault((o, (c.get("subject") or {}).get("c")), c)
    for (o, cc), c in orgs.items():
        res.organisation = o
        lb = _legal_brand(o, cc, reg)
        detail = dict(organisation=o, country=cc, validation=c.get("validation"), issuer=(c.get("issuer") or {}).get("o"),
                      cert_sha256=c.get("sha256"), not_before=c.get("not_before"), **src)
        if lb is not None:
            res.proven, res.brand = True, lb
            items.append(evidence(ids, **common, criterion="C16", finding="certificate_organisation_match",
                                  points_to="genuine", strength="strong", score=0.95, target_brand=brand_ref(lb),
                                  summary=(f"Proven {lb.name}: a {c.get('validation')} certificate for {r.host} "
                                           f"({detail['issuer']}) names the validated organisation \"{o}\", "
                                           f"{lb.name}'s exact legal name."), **detail))
            break
        legal = "; ".join(n for n, _ in brand.legal_names) if brand and brand.legal_names else None
        items.append(evidence(ids, **common, criterion="C16", finding="certificate_organisation_other",
                              points_to="neutral", strength="medium", score=0, target_brand=brand_ref(brand),
                              summary=(f"Its {c.get('validation')} certificate names a validated company: \"{o}\" "
                                       f"({detail['issuer']}). " + (f"That is not {bname}'s legal name ({legal}): "
                                                                     if legal else f"It isn't a legal name Doppel has for {bname}: ")
                                       + "a certificate proves who runs a site, not who that company belongs to."),
                              brand_legal_names=[n for n, _ in brand.legal_names] if brand else [], **detail))

    # ---- C17: history (is the look-alike armed?)
    if certs:
        first = min(c["not_before"] for c in certs if c.get("not_before"))
        last = max(c["not_before"] for c in certs if c.get("not_before"))
        age = _days(first, rec["fetched_at"])
        issuers = Counter((c.get("issuer") or {}).get("o") or "?" for c in certs)
        vals = Counter(c.get("validation", "unknown") for c in certs)
        sh = shape(certs, owner)
        res.history = {"count": len(certs), "first_seen": first, "age_days": round(age, 1), "issuers": dict(issuers), **sh}
        n = f"{len(certs)} certificate{'s' if len(certs) != 1 else ''}"
        cas = ", ".join(f"{k} x{v}" for k, v in issuers.most_common(3))
        detail = dict(domain=owner, count=len(certs), first_seen=first, last_seen=last, age_days=round(age, 1),
                      issuers=dict(issuers), validation=dict(vals), **sh,
                      sample=[c.get("sans", [])[:4] for c in certs[:6]], **src)
        if age <= ESTABLISHED_DAYS:
            # a look-alike that got its first certificate recently is getting ready to go live
            res.armed = True
            no_org = "" if orgs else " No Organisation field (DV): neutral; the real e-Challan site is DV too."
            items.append(evidence(ids, **common, criterion="C17", finding="armed", points_to="phishing", strength="weak",
                                  score=1.0 if age <= RECENT_DAYS else 0.8, target_brand=brand_ref(brand),
                                  summary=(f"Armed: first certificate {first[:10]} ({age:.0f} days before the lookup), "
                                           f"{n} in CT logs ({cas}). A fresh look-alike with a certificate is ready to "
                                           f"go live: higher priority, never PHISHING on its own.{no_org}"),
                                  first_cert_recent=age <= RECENT_DAYS, **detail))
        else:
            res.armed = False
            items.append(evidence(ids, **common, criterion="C17", finding="established_certificates",
                                  points_to="neutral", strength="weak", score=0, target_brand=brand_ref(brand),
                                  summary=(f"Certificates since {first[:10]} ({n}, {cas}): an established site, not a "
                                           "fresh look-alike. Age alone doesn't say whose it is."), **detail))
    else:
        res.armed = False
        items.append(evidence(ids, **common, criterion="C17", finding="no_certificate_yet", points_to="neutral",
                              strength="weak", score=0, target_brand=brand_ref(brand),
                              summary=(f"No certificate for {owner} in CT logs yet: not armed. If it gets one, "
                                       "it moves up the review queue."), domain=owner, count=0, **src))
    return res, _timed(items, t0)


def _timed(items: list[dict], t0: float) -> list[dict]:
    ms = round((time.perf_counter() - t0) * 1000, 3)
    for it in items:
        it["duration_ms"] = ms
    return items
