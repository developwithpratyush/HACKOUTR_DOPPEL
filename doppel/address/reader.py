"""Address Reader (Stage 1, Quick): who really owns this address?

Reads an address the way a browser does:
- strips scheme, credentials, port, path; lowercases; IDNA2008 (UTS #46) to ASCII and Unicode
- the real owner from the Public Suffix List, **including the private section**
  (sbi-kyc.web.app is owned by a web.app user, not Google), plus an extra list of
  hosting platforms the PSL misses
- hidden foreign letters: mixed-script labels, whole-script confusables (UTS #39)
- embedded suffixes: a public suffix such as gov.in sitting inside the subdomain part,
  the trace of a level-squat (echallan.parivahan.gov.in.pay-fine.icu)

``read_address`` returns facts; ``address_reader`` turns them into contract evidence.
Brand knowledge (which embedded name is genuine) belongs to the Family Verifier and the
Trick Detector, so evidence here has no target brand.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import idna
from publicsuffixlist import PublicSuffixList

from doppel.address import unicode_data as ud
from doppel.evidence import Ids, evidence

TOOL, STAGE = "address_reader", "quick"
EXTRA_HOSTING_FILE = Path(__file__).resolve().parent / "free_hosting_extra.txt"


class AddressError(ValueError):
    """The input isn't a usable hostname."""


@lru_cache(maxsize=None)
def _psl() -> tuple[PublicSuffixList, PublicSuffixList]:
    return PublicSuffixList(), PublicSuffixList(only_icann=True)


@lru_cache(maxsize=None)
def _psl_known() -> PublicSuffixList:
    """Like the full list, but an unknown label is NOT treated as a TLD."""
    return PublicSuffixList(accept_unknown=False)


@lru_cache(maxsize=None)
def extra_hosting() -> frozenset[str]:
    lines = EXTRA_HOSTING_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(l.strip() for l in lines if l.strip() and not l.startswith("#"))


@dataclass(frozen=True)
class LabelScripts:
    label: str              # Unicode form
    scripts: list[str]      # short codes, e.g. ["Latn", "Cyrl"]
    mixed: bool
    skeleton: str           # lowercased UTS #39 skeleton
    foreign: list[dict]     # non-ASCII characters: {char, codepoint, script, position}


@dataclass(frozen=True)
class AddressReading:
    raw: str
    host: str                       # lowercase ASCII (punycode)
    display: str                    # Unicode, as a victim sees it
    public_suffix: str              # under the full PSL, e.g. web.app or bank.in
    icann_suffix: str               # under the ICANN section only, e.g. app
    owner: str                      # registrable domain, or <user>.<platform> for free hosting
    subdomain: str                  # labels left of the owner ("" if none)
    hosting_platform: str | None    # web.app, weeblysite.com … (None for ordinary domains)
    labels: list[LabelScripts] = field(default_factory=list)
    embedded: dict | None = None    # {"domain": "parivahan.gov.in", "suffix": "gov.in"} hidden in the subdomain
    is_ip: bool = False

    @property
    def tld(self) -> str:
        return self.host.rsplit(".", 1)[-1]

    @property
    def skeleton(self) -> str:
        """Lowercased UTS #39 skeleton of the whole display form."""
        return ".".join(l.skeleton for l in self.labels)

    @property
    def mixed_script(self) -> bool:
        return any(l.mixed for l in self.labels)

    def is_under(self, domain: str) -> bool:
        """True if host is ``domain`` or a subdomain of it."""
        return self.host == domain or self.host.endswith("." + domain)


def extract_host(raw: str) -> str:
    """The host part of a URL, domain or SMS link."""
    text = raw.strip().strip("<>\"'()[]")
    if "://" in text:
        text = text.split("://", 1)[1]
    elif text.startswith("//"):
        text = text[2:]
    for sep in "/?#\\":
        text = text.split(sep, 1)[0]
    text = text.rsplit("@", 1)[-1]          # user:pass@host
    if text.startswith("[") or text.count(":") > 1:
        raise AddressError(f"IPv6 literals aren't domains: {raw!r}")
    text = text.split(":", 1)[0]             # port
    text = text.strip(".").replace("。", ".").replace("．", ".").replace("｡", ".")
    if not text:
        raise AddressError(f"no host in {raw!r}")
    return text


def to_ascii_and_unicode(host: str) -> tuple[str, str]:
    """IDNA2008 with UTS #46 mapping (as browsers do). Returns (ascii, unicode)."""
    try:
        ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        unicode_host = idna.decode(ascii_host)
    except idna.IDNAError as exc:
        # Some registrable-but-odd names (underscores, emoji) fail strict IDNA2008.
        if host.isascii():
            return host.lower(), host.lower()
        raise AddressError(f"not a valid internationalised domain name: {host!r} ({exc})") from exc
    return ascii_host.lower(), unicode_host


def _label_scripts(label: str) -> LabelScripts:
    foreign = [
        {"char": ch, "codepoint": ud.codepoint(ch), "script": ud.script_name(ud.script_of(ch)), "position": i}
        for i, ch in enumerate(label) if not ch.isascii()
    ]
    return LabelScripts(
        label=label,
        scripts=ud.scripts_used(label),
        mixed=ud.is_mixed_script(label),
        skeleton=ud.skeleton(label).lower(),
        foreign=foreign,
    )


def _owner(host: str) -> tuple[str, str, str, str | None]:
    """(public_suffix, icann_suffix, owner, hosting_platform)."""
    full, icann = _psl()
    public_suffix = full.publicsuffix(host) or host.rsplit(".", 1)[-1]
    icann_suffix = icann.publicsuffix(host) or public_suffix
    owner = full.privatesuffix(host) or host
    platform = public_suffix if public_suffix != icann_suffix else None
    if platform is None:
        for extra in extra_hosting():
            if host.endswith("." + extra):
                platform = extra
                owner = host[: -len(extra) - 1].rsplit(".", 1)[-1] + "." + extra
                break
    return public_suffix, icann_suffix, owner, platform


def _embedded_domain(subdomain: str) -> dict | None:
    """A whole domain hidden in the subdomain part: the subdomain's tail is a real public suffix.

    echallan.parivahan.gov.in.pay-fine.icu -> subdomain 'echallan.parivahan.gov.in' ends in the
    suffix 'gov.in', so it carries the domain 'parivahan.gov.in'. The leftmost (longest) match wins.
    """
    if not subdomain:
        return None
    psl = _psl_known()
    labels = subdomain.split(".")
    for j in range(1, len(labels)):
        suffix = ".".join(labels[j:])
        if psl.publicsuffix(suffix) == suffix:
            return {"domain": ".".join(labels[j - 1:]), "suffix": suffix}
    return None


# Special-use names that can never be a public website (IANA special-use registry; RFC 2606, 6761, 6762, 7686, 9476).
RESERVED_TLDS = {
    "invalid": "reserved so that it can never exist (RFC 2606)",
    "test": "reserved for testing, never on the public internet (RFC 2606)",
    "example": "reserved for documentation (RFC 2606)",
    "localhost": "this computer only (RFC 6761)",
    "local": "the local network only (multicast DNS, RFC 6762)",
    "onion": "Tor only, not the web (RFC 7686)",
    "alt": "reserved for non-DNS names (RFC 9476)",
    "internal": "reserved for private networks (ICANN, 2024)",
}
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def _check_name(raw: str, host: str) -> None:
    """Refuse what can't be a website address: Doppel judges real domains, it never invents a verdict for the rest."""
    if len(host) > 253:
        raise AddressError(f"{raw!r} is longer than a domain name can be (253 characters)")
    labels = host.split(".")
    for lab in labels:
        if not lab:
            raise AddressError(f"{raw!r} has an empty part between dots")
        if not _LABEL.match(lab):
            why = ("longer than 63 characters" if len(lab) > 63 else "starts or ends with a hyphen"
                   if lab[0] == "-" or lab[-1] == "-" else "has characters a domain can't contain")
            raise AddressError(f"{raw!r} isn't a domain: the part {lab[:40]!r} {why}")
    tld = labels[-1]
    if tld in RESERVED_TLDS:
        raise AddressError(f"'.{tld}' is {RESERVED_TLDS[tld]}: no real website can use {raw!r}")
    if not _psl_known().publicsuffix(host):          # the whole name: '.za' itself isn't listed, 'co.za' is
        raise AddressError(f"'.{tld}' isn't a real top-level domain, so {raw!r} can't exist on the internet")


def _userinfo_domain(raw: str) -> dict | None:
    """``https://sbi.co.in@evil.top/``: everything before '@' is a login name the browser ignores, but the victim
    reads 'sbi.co.in' first. When that part is a real domain, it's carried as the embedded (borrowed) address."""
    text = raw.strip().strip("<>\"'()[]")
    text = text.split("://", 1)[1] if "://" in text else text[2:] if text.startswith("//") else text
    for sep in "/?#\\":
        text = text.split(sep, 1)[0]
    if "@" not in text:
        return None
    info = text.rsplit("@", 1)[0].split(":", 1)[0].strip(".")
    if "." not in info:
        return None
    try:
        info, _ = to_ascii_and_unicode(info)
    except AddressError:
        return None
    psl = _psl_known()
    suffix = psl.publicsuffix(info)
    if not suffix or not psl.privatesuffix(info):
        return None
    return {"domain": info, "suffix": suffix, "via": "userinfo"}


def read_address(raw: str) -> AddressReading:
    host_text = extract_host(raw)
    parts = host_text.split(".")
    if all(p.isdigit() for p in parts) and len(parts) == 4:
        if any(int(p) > 255 or (len(p) > 1 and p[0] == "0") for p in parts):
            raise AddressError(f"{raw!r} isn't a valid IP address")
        return AddressReading(raw=raw, host=host_text, display=host_text, public_suffix="", icann_suffix="",
                              owner=host_text, subdomain="", hosting_platform=None, is_ip=True)
    host, display = to_ascii_and_unicode(host_text)
    if "." not in host:
        raise AddressError(f"{raw!r} has no domain suffix")
    _check_name(raw, host)
    public_suffix, icann_suffix, owner, platform = _owner(host)
    if "_" in owner and platform is None:    # registries never allow '_' in a name you buy (platform tenants may)
        raise AddressError(f"{raw!r} can't be registered: '{owner}' contains an underscore")
    subdomain = host[: -len(owner)].rstrip(".") if host != owner else ""
    return AddressReading(
        raw=raw,
        host=host,
        display=display,
        public_suffix=public_suffix,
        icann_suffix=icann_suffix,
        owner=owner,
        subdomain=subdomain,
        hosting_platform=platform,
        labels=[_label_scripts(l) for l in display.split(".")],
        embedded=_embedded_domain(subdomain) or _userinfo_domain(raw),
    )


# ------------------------------------------------------------- evidence ---

def address_reader(raw: str, ids: Ids | None = None) -> tuple[AddressReading, list[dict]]:
    """Stage-1 tool: read the address and return (reading, evidence items)."""
    ids = ids or Ids()
    t0 = time.perf_counter()
    r = read_address(raw)
    items: list[dict] = []
    common = {"tool": TOOL, "stage": STAGE}

    if r.is_ip:
        items.append(evidence(ids, **common, criterion="C1", finding="ip_address_host", points_to="phishing",
                              strength="medium", score=0.6,
                              summary=f"The link uses a bare IP address ({r.host}), not a domain name.",
                              owner=r.host))
        return r, _timed(items, t0)

    owner_details = {"owner": r.owner, "public_suffix": r.public_suffix, "private_suffix": r.hosting_platform is not None,
                     "subdomain_labels": r.subdomain.split(".") if r.subdomain else []}
    if r.embedded:
        multi = "." in r.embedded["suffix"]
        items.append(evidence(
            ids, **common, criterion="C1", finding="owner_differs", points_to="phishing", strength="strong",
            score=0.85 if multi else 0.75,
            summary=(f"Real owner is {r.owner}. Everything before '@' ('{r.embedded['domain']}') is a fake login name "
                     "the browser ignores: it's there so the link reads like a different site."
                     if r.embedded.get("via") == "userinfo" else
                     f"Real owner is {r.owner}. '{r.subdomain}' is only a sub-part the owner chose; "
                     f"it carries the address '{r.embedded['domain']}' to look like a different site."),
            embedded_domain=r.embedded["domain"], embedded_suffix=r.embedded["suffix"], **owner_details))
    elif r.hosting_platform:
        items.append(evidence(
            ids, **common, criterion="C1", finding="free_hosting_owner", points_to="neutral", strength="strong", score=0,
            summary=(f"Real owner is a user of {r.hosting_platform} ({r.owner}), not {r.hosting_platform} itself: "
                     "anyone can get such an address without registering a domain."),
            platform=r.hosting_platform, platform_in_psl=r.public_suffix == r.hosting_platform, **owner_details))
    else:
        items.append(evidence(
            ids, **common, criterion="C1", finding="owner_resolved", points_to="neutral", strength="strong", score=0,
            summary=f"Real owner is {r.owner} (public suffix '{r.public_suffix}').", **owner_details))

    mixed = [l for l in r.labels if l.mixed]
    whole_script = [l for l in r.labels
                    if not l.mixed and l.foreign and l.skeleton.isascii() and l.skeleton != l.label.lower()]
    if mixed:
        lab = mixed[0]
        names = [ud.script_name(s) for s in lab.scripts]
        hidden = ", ".join(f"'{f['char']}' ({f['codepoint']}, {f['script']})" for f in lab.foreign)
        items.append(evidence(
            ids, **common, criterion="C3", finding="mixed_script", points_to="phishing", strength="strong", score=0.95,
            summary=f"'{lab.label}' mixes {' and '.join(names)}: hidden letter(s) {hidden}.",
            scripts=names, unicode=r.display, uts39_skeleton=r.skeleton, edits=_homoglyph_edits(r)))
    elif whole_script:
        lab = whole_script[0]
        items.append(evidence(
            ids, **common, criterion="C3", finding="whole_script_confusable", points_to="phishing", strength="strong",
            score=0.9,
            summary=(f"'{lab.label}' is written entirely in {ud.script_name(lab.scripts[0])} letters "
                     f"that look like the Latin '{lab.skeleton}'."),
            scripts=[ud.script_name(s) for s in lab.scripts], unicode=r.display, uts39_skeleton=r.skeleton,
            edits=_homoglyph_edits(r)))
    else:
        scripts = sorted({ud.script_name(s) for l in r.labels for s in l.scripts}) or ["Latin"]
        summary = ("Plain ASCII, one script: no hidden letters." if r.display.isascii()
                   else f"One script per label ({', '.join(scripts)}), no look-alike mixing.")
        items.append(evidence(ids, **common, criterion="C3", finding="single_script", points_to="neutral",
                              strength="strong", score=0, summary=summary, scripts=scripts))
    return r, _timed(items, t0)


def _homoglyph_edits(r: AddressReading) -> list[dict]:
    """Per-character edits from the display form to its skeleton, for the UI highlight."""
    edits, offset = [], 0
    for lab in r.labels:
        for f in lab.foreign:
            proto = ud.skeleton(f["char"]).lower()
            if proto.isascii() and proto != f["char"]:
                pos = offset + f["position"]
                edits.append({"op": "substitute", "candidate": f["char"], "genuine": proto,
                              "candidate_span": [pos, pos + 1], "genuine_span": [pos, pos + len(proto)],
                              "cost": 0.0, "kind": "homoglyph", "codepoints": [f["codepoint"]]})
        offset += len(lab.label) + 1
    return edits


def _timed(items: list[dict], t0: float) -> list[dict]:
    ms = (time.perf_counter() - t0) * 1000
    for it in items:
        it["duration_ms"] = round(ms, 3)
    return items
