"""Generic baselines on one name: what a keyword alert, edit distance, dnstwist, phishing_catcher, the padlock and a
public blocklist would say. Used by the P4 arena (the same classes, moved here in P14) and by the Presenter's
"generic tools" tile and the finale scoreboard (``demo/finale/scoreboard.py``), so every cell is computed, never typed.

Thresholds are the ones the arena tuned on its dev split (``bench/p4_arena.py`` -> ``docs/eval/p4-arena.json``):
Levenshtein tau 0.5, phishing_catcher score 90. dnstwist is configured generously (our lure words and attacker TLDs).
The padlock row reads the CT cache only; the blocklist row reads the downloaded Phishing.Database ACTIVE list.
"""

from __future__ import annotations

import math
import re
import threading
from collections import Counter
from pathlib import Path

from rapidfuzz.distance import Levenshtein

try:
    import dnstwist
except ImportError:                            # optional extra (".[generator]"): the dnstwist row is left out
    dnstwist = None

from doppel.address import read_address
from doppel.address.unicode_data import skeleton
from doppel.contract import REPO_ROOT
from doppel.generator.pairs import seeds
from doppel.generator.techniques import ATTACKER_TLDS
from doppel.tricks.detector import _name_parts
from doppel.tricks.segment import brand_strings

LEV_TAU = 0.5          # arena, tuned on dev
PC_SCORE = 90          # arena, tuned on dev
BLOCKLIST = REPO_ROOT / "data" / "raw" / "phishing_database" / "phishing-domains-ACTIVE.txt"


class Lev:
    def __init__(self, reg) -> None:
        self.names = brand_strings(reg)

    def score(self, r) -> tuple[float, str]:
        core, _ = _name_parts(r)
        best = (0.0, None)
        for bid, names in self.names.items():
            for n in names:
                s = Levenshtein.normalized_similarity(core, n)
                if s > best[0]:
                    best = (s, bid)
        return best


class Dnstwist:
    def __init__(self, reg) -> None:
        self.index: dict[str, str] = {}
        lures = list(reg.lure_words)
        for b in reg.brands:
            for seed in seeds(b, reg):
                fz = dnstwist.Fuzzer(seed, dictionary=lures, tld_dictionary=ATTACKER_TLDS)
                fz.generate()
                for d in fz.domains:
                    self.index.setdefault(d["domain"].lower(), b.id)

    def __call__(self, r, fam) -> tuple[bool, str | None, dict]:
        brand = self.index.get(r.host) or self.index.get(r.owner)
        return brand is not None, brand, {}


# phishing_catcher, reimplemented: same scoring rules, our own (shorter) generic keyword list.
PC_TLDS = [".top", ".xyz", ".icu", ".online", ".site", ".click", ".link", ".shop", ".live", ".info", ".cc", ".pw",
           ".tk", ".ml", ".ga", ".cf", ".gq", ".club", ".work", ".vip", ".buzz", ".support", ".loan", ".win"]
PC_GENERIC = {"login": 25, "signin": 25, "sign-in": 25, "account": 25, "verify": 25, "verification": 25,
              "password": 25, "support": 25, "security": 25, "update": 25, "wallet": 25, "alert": 25,
              "unlock": 25, "recover": 25, "confirm": 20, "service": 15, "portal": 15, "invoice": 15,
              "secure": 10, "customer": 10, "bill": 10, "online": 10, "safe": 10, "form": 10}


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


class PhishingCatcher:
    def __init__(self, reg) -> None:
        self.brand_kw = {a: b.id for b in reg.brands for a in b.aliases}

    def score(self, r) -> tuple[float, str | None]:
        host = r.host
        score = sum(20 for t in PC_TLDS if host.endswith(t))
        name = host[: -len(r.icann_suffix) - 1] if r.icann_suffix and host.endswith("." + r.icann_suffix) else host
        score += int(round(_entropy(name) * 10))
        name = skeleton(r.display.lower())[: len(name)] if not r.display.isascii() else name  # "unconfuse"
        words = re.split(r"\W+", name)
        if words and words[0] in ("com", "net", "org"):
            score += 10
        brand_pts: Counter = Counter()
        for kw, pts in PC_GENERIC.items():
            if kw in name:
                score += pts
        for kw, bid in self.brand_kw.items():
            if kw in name:
                score += 70
                brand_pts[bid] += 70
            for w in words:
                if w not in ("email", "mail", "cloud") and Levenshtein.distance(w, kw) == 1:
                    score += 70
                    brand_pts[bid] += 70
        if "xn--" not in name and name.count("-") >= 4:
            score += name.count("-") * 3
        if name.count(".") >= 3:
            score += name.count(".") * 3
        return score, (brand_pts.most_common(1)[0][0] if brand_pts else None)


class Blocklist:
    """Phishing.Database ACTIVE (one host per line), loaded once. Missing file = the row says so."""

    def __init__(self, path: Path = BLOCKLIST) -> None:
        self.path = path
        self.names: set[str] | None = None
        if path.is_file():
            self.names = {ln.strip().lower() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
                          if ln.strip() and not ln.startswith("#")}

    def listed(self, host: str, owner: str | None) -> bool | None:
        if self.names is None:
            return None
        return host in self.names or (owner is not None and owner in self.names)


def _padlock(owner: str) -> int | None:
    """How many certificates the CT cache holds for the owner (None: not cached). Never looks anything up."""
    from doppel.certs import ct

    rec = ct.search(owner, network=False)
    return None if rec is None else len(rec.get("issuances") or [])


class Generic:
    """All the generic methods, built once (dnstwist's permutation index takes a few seconds)."""

    def __init__(self, reg) -> None:
        from doppel.live.naive import KeywordBaseline

        self.names = {b.id: b.name for b in reg.brands}
        self.keyword = KeywordBaseline(reg)
        self.lev = Lev(reg)
        self.pc = PhishingCatcher(reg)
        try:
            self.dnstwist: Dnstwist | None = Dnstwist(reg)
        except Exception:                      # noqa: BLE001 - dnstwist is an optional extra
            self.dnstwist = None
        self.blocklist = Blocklist()

    def compare(self, domain: str, verdict: dict | None = None) -> list[dict]:
        """One row per method: ``flagged`` True/False, or None when the method can't say (no data)."""
        r = read_address(domain)
        bn = lambda bid: self.names.get(bid, bid) if bid else None   # noqa: E731
        rows: list[dict] = []
        kw = self.keyword.hit(r.host)
        rows.append({"method": "keyword", "name": "Keyword filter", "flagged": kw is not None,
                     "detail": f"'{kw}' in the name" if kw else "no brand word in the name"})
        s, bid = self.lev.score(r)
        rows.append({"method": "levenshtein", "name": f"Levenshtein (>= {LEV_TAU})", "flagged": s >= LEV_TAU,
                     "detail": f"{s:.2f} to {bn(bid)}" if bid else f"{s:.2f}"})
        if self.dnstwist is not None:
            hit = self.dnstwist.index.get(r.host) or (self.dnstwist.index.get(r.owner) if r.owner else None)
            rows.append({"method": "dnstwist", "name": "dnstwist permutations", "flagged": hit is not None,
                         "detail": f"a permutation of {bn(hit)}" if hit else "not in any brand's permutations"})
        sc, pbid = self.pc.score(r)
        rows.append({"method": "phishing_catcher", "name": f"phishing_catcher (>= {PC_SCORE})", "flagged": sc >= PC_SCORE,
                     "detail": f"score {sc}" + (f", brand {bn(pbid)}" if pbid else "")})
        ml = next((e for e in (verdict or {}).get("evidence", []) if e.get("criterion") == "C8"), None)
        p: float | None = float(ml["details"].get("probability", 0)) if ml is not None else None
        if p is None:                      # the brain stopped before Standard: run the model alone, as a tool would
            try:
                from doppel.risk.model import predict

                p = float(predict(domain))
            except Exception:              # noqa: BLE001 - no trained model on this machine
                p = None
        if p is not None:
            rows.append({"method": "ml", "name": "ML model alone", "flagged": p >= 0.5, "detail": f"{p:.2f}, no reason given"})
        n = _padlock(r.owner or r.host)
        ev = {e.get("criterion"): e for e in (verdict or {}).get("evidence", [])}
        if not n and ev.get("C16", {}).get("points_to") == "genuine":
            n = len(ev["C16"]["details"].get("linked_to") or []) or 1          # served under a proven certificate
        if not n and "C17" in ev:
            n = int(ev["C17"]["details"].get("count") or 1)
        rows.append({"method": "padlock", "name": "Padlock = safe", "flagged": False if n else None,
                     "detail": "has a valid certificate: shows a padlock" if n else "no certificate known"})
        listed = self.blocklist.listed(r.host, r.owner)
        rows.append({"method": "blocklist", "name": "Public blocklist", "flagged": listed,
                     "detail": "on Phishing.Database ACTIVE" if listed else "not on Phishing.Database ACTIVE" if listed is False
                     else "list not downloaded"})
        return rows


_G: Generic | None = None
_LOCK = threading.Lock()


def generic(reg=None) -> Generic:
    global _G
    with _LOCK:
        if _G is None:
            if reg is None:
                from doppel.family import load_registry
                reg = load_registry()
            _G = Generic(reg)
        return _G
