"""Family Verifier (Stage 1, Quick): is this address provably the brand's own?

Three proofs, each reported by name:
  brand_tld            under a closed brand TLD (.sbi, .google): only the brand can register there
  restricted_registry  under a vetted-only suffix (.bank.in, .gov.in) the brand uses, AND on its list
  official_list        on the brand's curated family list, with a recorded source

Before any proof, user-content platforms (forms.gle, sites.google.com …) are ruled out:
the brand owns the host, but anyone can publish there, so ownership proves nothing.

If no proof matches, the verifier names the brand being imitated, when there is one:
  level_squat           a genuine family address used as a prefix of another owner's address
  trust_signal          a trust ending rebuilt with hyphens (sbi.bank-in.com, blog-google.com)
  skeleton              looks identical to a family address (pаytm.com, paytrn.com)
  alias_token           a brand name as a token (sbi-kyc-update.in)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from doppel.address.reader import AddressReading
from doppel.evidence import Ids, brand_ref, evidence
from doppel.family.registry import Brand, FamilyEntry, Registry, load_registry

TOOL, STAGE = "family_verifier", "quick"
PROOFS = ["brand_tld", "restricted_registry", "official_list"]


@dataclass
class FamilyResult:
    status: str                     # genuine | user_content | restricted_unlisted | restricted_other | imitation | none
    brand: Brand | None = None
    proofs_matched: list[str] = field(default_factory=list)
    entry: FamilyEntry | None = None
    verified: bool = True
    matched_by: str | None = None   # how the imitated brand was found
    imitated: str | None = None     # the genuine address or trust signal being copied
    platform: str | None = None

    @property
    def genuine(self) -> bool:
        return self.status == "genuine"


def _tokens(text: str) -> list[str]:
    return [t for t in text.replace(".", "-").split("-") if t]


MIN_AFFIX_ALIAS = 4  # 3-letter aliases (sbi) must be a whole token: akesbi, sbinternal, sbisec aren't SBI


def _alias_hit(token: str, alias: str) -> bool:
    if token == alias:
        return True
    return len(alias) >= MIN_AFFIX_ALIAS and (token.startswith(alias) or token.endswith(alias))


def find_level_squat(r: AddressReading, reg: Registry) -> tuple[Brand, str] | None:
    """A brand's genuine address used as a prefix (or hidden inside) another owner's address."""
    for brand in reg.brands:
        for entry in brand.family:
            d = entry.domain
            if entry.covers(r.host) or entry.covers(r.owner):
                continue
            # The genuine name must sit in the part the owner controls (the subdomain), or run
            # into the owner label with a hyphen. paytm.com.mw is an ending swap, not a level-squat.
            in_subdomain = r.subdomain == d or r.subdomain.endswith("." + d) or r.subdomain.startswith(d + ".")
            runs_into_owner = f".{d}-" in "." + r.host   # at any label boundary: www.bank.sbi-kyc.shop
            if in_subdomain or runs_into_owner:
                return brand, d
            emb = r.embedded["domain"] if r.embedded else None
            if emb and (emb == d or emb.endswith("." + d)):
                return brand, d
    return None


def _trust_signal(r: AddressReading, reg: Registry) -> tuple[Brand | None, str] | None:
    """A trust ending rebuilt with hyphens: sbi.bank-in.com -> sbi.bank.in, blog-google.com -> blog.google."""
    name = r.host[: -len(r.icann_suffix) - 1] if r.host.endswith("." + r.icann_suffix) else r.host
    dotted = name.replace("-", ".")
    if dotted != name:
        for brand in reg.brands:
            for entry in brand.family:
                if entry.covers(dotted):
                    return brand, entry.domain
            for tld in brand.brand_tlds:
                if dotted.endswith("." + tld):
                    return brand, "." + tld
    # A restricted ending spelled out inside the name. "bank-in"/"gov-in" as separate tokens is a
    # signal on its own; glued forms (hdfcbank-in, sbibankin) only count next to a brand name,
    # because "bankin", "govin", "finin" also occur in ordinary words (shinohara-bankin, frigovin).
    tokens = _tokens(name)
    for suffix in reg.restricted:
        first, *rest = suffix.split(".")
        glued = suffix.replace(".", "")
        for i, tok in enumerate(tokens):
            follows = tokens[i + 1:i + 1 + len(rest)] == rest
            if tok == first and follows:
                brand = _alias_brand(r, reg)
                return (brand[0] if brand else None), suffix
            if (tok.endswith(first) and follows) or tok.endswith(glued):
                brand = _alias_brand(r, reg)
                if brand:
                    return brand[0], suffix
    return None


def _skeleton_brand(r: AddressReading, reg: Registry) -> tuple[Brand, str] | None:
    """Looks identical (UTS #39 skeleton) to a genuine family address."""
    hit = reg.family_skeletons.get(r.skeleton)
    if hit and hit[1] != r.host:
        return hit
    return None


def _alias_brand(r: AddressReading, reg: Registry) -> tuple[Brand, str] | None:
    """A brand name as a whole token, or at a token's start or end (raw and skeleton forms)."""
    raw_tokens = _tokens(r.display.lower())
    skel_tokens = _tokens(r.skeleton)
    for brand in reg.brands:
        for alias, alias_skel in brand.alias_skeletons.items():
            if alias in brand.exact_aliases:          # whole tokens only (P11): npcinv isn't NPCI
                if alias in raw_tokens:
                    return brand, alias
                continue
            if any(_alias_hit(t, alias) and _segments_agree(t, alias, reg) for t in raw_tokens) or \
                    any(_alias_hit(t, alias_skel) and _segments_agree(t, alias_skel, reg) for t in skel_tokens):
                return brand, alias
    return _glued_short_alias(raw_tokens, reg)


def _segments_agree(token: str, alias: str, reg: Registry) -> bool:
    """A brand at a token's start or end must also be a word there: sledding|mail isn't g|mail (P5 NRD run)."""
    if token == alias or not token.isascii():
        return True
    from doppel.tricks.segment import segmenter  # P4 module; imported late to avoid a cycle

    return alias in segmenter(reg).split(token)


def _glued_short_alias(raw_tokens: list[str], reg: Registry) -> tuple[Brand, str] | None:
    """A short alias glued to lure/address words (sbibankin -> sbi + bank + in), found by word segmentation (P4).

    Only when every other word in the token is a lure word, an address word or digits: sbisec
    (SBI Securities, Japan) and akesbi stay quiet.
    """
    from doppel.tricks.segment import ADDRESS_WORDS, segmenter  # P4 module; imported late to avoid a cycle

    seg = segmenter(reg)
    ok = set(reg.lure_words) | {w for b in reg.brands for w in b.lure_words} | set(ADDRESS_WORDS)
    for tok in raw_tokens:
        if not tok.isascii() or len(tok) <= MIN_AFFIX_ALIAS:
            continue
        parts = seg.split(tok)
        for brand in reg.brands:
            for alias in brand.aliases:
                if len(alias) < MIN_AFFIX_ALIAS and alias in parts:
                    others = [p for p in parts if p != alias]
                    if others and all(p in ok or p.isdigit() for p in others):
                        return brand, alias
    return None


def check_family(r: AddressReading, reg: Registry | None = None) -> FamilyResult:
    reg = reg or load_registry()

    for brand in reg.brands:
        for uc in brand.user_content:
            if uc.covers(r.host):
                return FamilyResult("user_content", brand, platform=uc.host, imitated=None, matched_by=uc.what)

    for brand in reg.brands:
        proofs: list[str] = []
        matched: FamilyEntry | None = None
        verified = True
        if r.tld in brand.brand_tlds:
            proofs.append("brand_tld")
            verified = reg.brand_tld_rows.get(r.tld, {}).get("verified_on") is not None
        for entry in brand.family:
            if entry.covers(r.host):
                matched = entry
                if any(r.is_under(s) for s in brand.restricted_suffixes):
                    proofs.append("restricted_registry")
                proofs.append("official_list")
                verified = entry.verified_on is not None
                break
        if proofs:
            return FamilyResult("genuine", brand, sorted(set(proofs), key=PROOFS.index), matched, verified)

    restricted = next((s for s in reg.restricted if r.is_under(s) and r.host != s), None)
    if restricted:
        hit = _alias_brand(r, reg)
        if hit:
            return FamilyResult("restricted_unlisted", hit[0], matched_by="alias_token", imitated=restricted)
        return FamilyResult("restricted_other", None, imitated=restricted)

    for how, finder in (("level_squat", find_level_squat), ("trust_signal", _trust_signal),
                        ("skeleton", _skeleton_brand), ("alias_token", _alias_brand)):
        hit = finder(r, reg)
        if hit:
            return FamilyResult("imitation", hit[0], matched_by=how, imitated=hit[1], platform=r.hosting_platform)
    return FamilyResult("none", platform=r.hosting_platform)


def family_verifier(r: AddressReading, reg: Registry | None = None,
                    ids: Ids | None = None) -> tuple[FamilyResult, list[dict]]:
    """Stage-1 tool: check ownership and return (result, evidence items)."""
    reg = reg or load_registry()
    ids = ids or Ids()
    t0 = time.perf_counter()
    res = check_family(r, reg)
    common = {"tool": TOOL, "stage": STAGE, "criterion": "C2", "proofs_checked": PROOFS}
    b = brand_ref(res.brand)

    if res.status == "genuine":
        e = res.entry
        how = " and ".join({"brand_tld": f"under the brand-owned ending .{r.tld}",
                            "restricted_registry": f"under the restricted registry .{r.public_suffix}",
                            "official_list": f"{e.domain if e else r.host} is on {res.brand.name}'s official list"}[p]
                           for p in res.proofs_matched)
        caveat = "" if res.verified else " (this entry is still unverified)"
        item = evidence(ids, **common, finding="genuine_family", points_to="genuine", strength="strong",
                        score=0.98 if res.verified else 0.8, target_brand=b,
                        summary=f"Proven {res.brand.name}: {how}{caveat}.",
                        proofs_matched=res.proofs_matched, family_entry=e.domain if e else None,
                        source=e.source if e else reg.brand_tld_rows.get(r.tld, {}).get("source"),
                        verified_on=e.verified_on if e else reg.brand_tld_rows.get(r.tld, {}).get("verified_on"),
                        verified=res.verified)
    elif res.status == "user_content":
        item = evidence(ids, **common, finding="brand_user_content_platform", points_to="neutral", strength="strong",
                        score=0, target_brand=b,
                        summary=(f"{r.host} belongs to {res.brand.name}, but anyone can publish there "
                                 f"({res.matched_by}), so ownership proves nothing about who made this page."),
                        proofs_matched=[], platform=res.platform)
    elif res.status == "restricted_unlisted":
        item = evidence(ids, **common, finding="restricted_registry_unlisted", points_to="genuine", strength="medium",
                        score=0.6, target_brand=b,
                        summary=(f"Under the restricted registry .{res.imitated} ({reg.restricted[res.imitated]}) and "
                                 f"names {res.brand.name}, but isn't on {res.brand.name}'s official list."),
                        proofs_matched=[], restricted_suffix=res.imitated)
    elif res.status == "restricted_other":
        item = evidence(ids, **common, finding="restricted_registry_other_entity", points_to="genuine",
                        strength="medium", score=0.6, target_brand=None,
                        summary=(f"Under the restricted registry .{res.imitated} ({reg.restricted[res.imitated]}): "
                                 "a vetted organisation, but not one of the protected brands."),
                        proofs_matched=[], restricted_suffix=res.imitated)
    elif res.status == "imitation":
        name = res.brand.name if res.brand else "a protected brand"
        if res.matched_by == "level_squat":
            item = evidence(ids, **common, finding="imitates_trust_signal", points_to="phishing", strength="strong",
                            score=0.9, target_brand=b,
                            summary=(f"Uses {name}'s genuine address '{res.imitated}' as a prefix, "
                                     f"but the real owner is {r.owner}."),
                            proofs_matched=[], imitated=res.imitated, matched_by=res.matched_by)
        elif res.matched_by == "trust_signal":
            # Rebuilding an actual family address (sbi.bank-in.com -> sbi.bank.in) is strong; merely ending
            # like a brand TLD (278254-google.com -> *.google) is weaker evidence.
            exact = not res.imitated.startswith(".")
            item = evidence(ids, **common, finding="imitates_trust_signal", points_to="phishing",
                            strength="strong" if exact else "medium", score=0.85 if exact else 0.6, target_brand=b,
                            summary=(f"Borrows the trust signal '{res.imitated}' without being under it "
                                     f"(real owner {r.owner}); not {name}'s."),
                            proofs_matched=[], imitated=res.imitated, matched_by=res.matched_by)
        else:
            via = (f"looks identical to {res.imitated}" if res.matched_by == "skeleton"
                   else f"contains the brand name '{res.imitated}'")
            where = f" on {res.platform}" if res.platform else ""
            item = evidence(ids, **common, finding="not_in_family", points_to="phishing", strength="medium",
                            score=0.5, target_brand=b,
                            summary=(f"Not {name}'s{where}: it {via}, but no ownership proof matched "
                                     "(no brand-owned ending, restricted registry or official-list entry)."),
                            proofs_matched=[], imitated=res.imitated, matched_by=res.matched_by,
                            platform=res.platform)
    else:
        item = evidence(ids, **common, finding="no_brand_to_verify", points_to="neutral", strength="strong", score=0,
                        summary="The address points to no protected brand, so there is no family to check.",
                        proofs_matched=[])
    item["duration_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return res, [item]
