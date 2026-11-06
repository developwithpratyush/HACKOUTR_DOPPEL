"""Trick Detector (Stage 1, Quick): which naming trick is used, and how close is it to each brand?

Three criteria, all from the name alone:
  C4 closeness   visual edit distance to every brand name (``align``), per brand, with the aligned edits
  C5 trick       the trick label: homoglyph, twin_letters, typo, bitsquat, soundsquat, combosquat,
                 level_squat, trust_signal_mimicry, tld_swap (or substring_not_token / no_trick)
  C6 ending      a weak hint from how often the ending carries phishing in PhiUSIIL (``tld_risk``)

It builds on the Family Verifier (P2): a proven family member is never a trick, and P2's structural
findings (a genuine address used as a prefix, a rebuilt trust ending, an identical skeleton) name the
brand directly. On top of that it adds what P2 can't see: look-alikes that are *close* but not
identical (paytrn, hdfcbnak, pāyţm), brands glued to lure words (sbibankin), sound-alikes.

``detect`` returns facts; ``trick_detector`` turns them into contract evidence.
"""

from __future__ import annotations

import time
import unicodedata
from dataclasses import dataclass, field

import jellyfish
from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from doppel.address.reader import AddressReading
from doppel.address.unicode_data import skeleton
from doppel.evidence import Ids, brand_ref, evidence
from doppel.family import FamilyResult, check_family, load_registry
from doppel.family.registry import Brand, Registry
from doppel.perception.glyphs import Glyphs, load_glyphs
from doppel.tricks.align import TWIN_MAX, Alignment, align
from doppel.tricks.segment import ADDRESS_WORDS, brand_strings, segmenter, tokens
from doppel.tricks.tld_risk import tld_risk

TOOL, STAGE = "trick_detector", "quick"

# Tuned on the dev split only (bench/p4_arena.py, docs/eval/p4-arena.md): the visual similarity at
# or above which a name counts as imitating a brand.
TAU_CLOSE = 0.7
MIN_LOCAL = 5          # names shorter than this must match the whole label (no "found inside" matches)
MIN_SOUND = 5          # Metaphone keys of short names collide too often
SHORT_ALIAS = 3        # aliases this short count inside glued text only next to lure/address words
# P11 fix (a): on free hosting, a distinctive brand name (4+ letters) hidden inside a gibberish label counts
# (ezhzxywnitjrudyxhdfcuvotob-dot-gloff849483.uk.r.appspot.com); "gibberish" = real words of 4+ letters cover less
# than GIBBERISH_WORDS of the rest of the label, and the rest has at least GIBBERISH_MIN letters.
DISTINCT_MIN = 4
GIBBERISH_MIN = 6
GIBBERISH_WORDS = 0.35
# P11 fix (c): an email address registered as a domain (redwolf6514gmail.com = redwolf6514@gmail.com, O22):
# a mailbox name, not an imitation, when no lure word or other brand rides along.
EMAIL_ALIASES = ("gmail",)
EMAIL_LOCAL_MIN = 4


@dataclass
class Match:
    brand: Brand
    name: str                      # the brand name compared (alias or family label)
    closeness: float
    via: str                       # visual | local | token | level_squat | trust_signal | skeleton | fold | sound | tld
    alignment: Alignment | None = None


@dataclass
class TrickResult:
    brand: Brand | None = None
    closeness: float | None = None
    genuine: str | None = None             # the genuine address it's compared with
    brand_signal: bool = False
    tricks: list[str] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    per_brand: dict[str, float] = field(default_factory=dict)
    best: Match | None = None
    tokens: list[str] = field(default_factory=list)
    lures: list[dict] = field(default_factory=list)
    brand_token: str | None = None
    substring_hit: str | None = None
    tld: dict | None = None
    core: str = ""                         # the name part compared (owner label, Unicode)
    in_family: bool = False
    hidden_in: str | None = None           # fix (a): the gibberish label a brand name hides in, on free hosting
    email_shaped: str | None = None        # fix (c): the email address the name spells (no brand signal)


def _fold(text: str) -> str:
    """Look-alike letters folded to ASCII: marks stripped (pāyţm -> paytm), and each non-ASCII letter
    mapped through its UTS #39 prototype (pаytm -> paytm). ASCII letters are left alone: the skeleton
    would turn m into rn."""
    out = []
    for ch in unicodedata.normalize("NFD", text):
        if unicodedata.category(ch) == "Mn":
            continue
        out.append(ch if ch.isascii() else skeleton(ch).lower())
    return "".join(out)


def _name_parts(r: AddressReading) -> tuple[str, list[str]]:
    """(owner label, subdomain labels), in display (Unicode) form."""
    disp = r.display.lower().split(".")
    suffix_labels = r.public_suffix.count(".") + 1 if r.public_suffix else 1
    idx = len(disp) - suffix_labels - 1
    if r.hosting_platform and r.hosting_platform != r.public_suffix:   # extra-list platform (weeblysite.com)
        idx = len(disp) - (r.hosting_platform.count(".") + 1) - 1
    idx = max(0, idx)
    return disp[idx], disp[:idx]


def _genuine_for(brand: Brand, name: str) -> str:
    """The family address a name stands for: exact first label, then containing it, then the first entry."""
    for e in brand.family:
        if e.domain.split(".")[0] == name or e.domain == name:
            return e.domain
    for e in brand.family:
        if e.domain.endswith("." + name) or name in e.domain:
            return e.domain
    return brand.family[0].domain


STRUCTURAL = ("level_squat", "trust_signal", "skeleton")
PREFILTER = 50        # rapidfuzz ratio (0-100) on folded text below which the visual DP is skipped
PREFILTER_LOCAL = 70  # rapidfuzz partial_ratio for the "found inside the name" alignment
MIN_EXTRA = 3         # letters beyond the brand name before it counts as "brand + other words"
SOUND_FLOOR = 0.6     # a sound-alike must also look somewhat alike: short Metaphone keys collide (kumilu ~ gmail)
MAX_VISIBLE = 1       # a whole-name look-alike may carry at most one *visible* edit (twins/homoglyphs are free):
                      # routebank ~ statebank is 3 visible letters, not a typo (found in the P5 NRD run)


def visible_edits(a: Alignment) -> int:
    """Ordinary edits (typos, keyboard slips, flipped bits, hyphens, swaps). Look-alike swaps don't count, even
    when our fonts draw them apart (0/o, 1/l are listed confusables): they're the trick, not noise."""
    return sum(1 for e in a.edits if e["kind"] not in ("twin_letters", "homoglyph"))


class TrickDetector:
    def __init__(self, reg: Registry | None = None, glyphs: Glyphs | None = None, tau: float = TAU_CLOSE) -> None:
        self.reg = reg or load_registry()
        self.glyphs = glyphs or load_glyphs()
        self.tau = tau
        self.names = brand_strings(self.reg)
        self.seg = segmenter(self.reg)
        self.lure_cat = {**self.reg.lure_words}
        for b in self.reg.brands:
            for w in b.lure_words:
                self.lure_cat.setdefault(w, "brand")
        self.glue_ok = set(self.lure_cat) | set(ADDRESS_WORDS) | {n for ns in self.names.values() for n in ns}
        self._sound = {(b.id, n): jellyfish.metaphone(n) for b in self.reg.brands for n in self.names[b.id]
                       if len(n) >= MIN_SOUND and n.isalpha()}

    # ------------------------------------------------------------------ tokens ---

    def _tokens(self, labels: list[str]) -> tuple[list[str], list[list[str]]]:
        raw = [t for lab in labels for t in lab.replace("_", "-").split("-") if t]
        return raw, [list(self.seg.split(t)) if t.isascii() else [t] for t in raw]

    def _brand_token(self, raw: list[str], pieces: list[list[str]]) -> tuple[Brand, str] | None:
        """A brand name as a whole token, or as a word inside a glued token whose other words are real."""
        for b in self.reg.brands:
            for name in self.names[b.id]:
                for tok, parts in zip(raw, pieces):
                    if tok == name:
                        return b, name
                    if name in parts and len(parts) > 1:
                        others = [p for p in parts if p != name]
                        short = len(name) <= SHORT_ALIAS
                        if all(p in self.glue_ok or p.isdigit() or (not short and self.seg.known(p)) for p in others):
                            return b, name
        return None

    def _boundaries(self, core: str) -> set[int]:
        """Word boundaries in the owner label: hyphens and segmentation breaks (sledding|mail, pay|trn|kyc)."""
        out, pos = {0, len(core)}, 0
        for part in core.split("-"):
            out.update((pos, pos + len(part)))
            if part.isascii():
                q = pos
                for w in self.seg.split(part):
                    q += len(w)
                    out.add(q)
            pos += len(part) + 1
        return out

    # ------------------------------------------------------------------ detect ---

    def detect(self, r: AddressReading, family: FamilyResult | None = None) -> TrickResult:
        fam = family or check_family(r, self.reg)
        res = TrickResult(tld=None if r.is_ip else tld_risk(r.tld))
        if r.is_ip:
            return res
        core, sub = _name_parts(r)
        res.core = core
        labels = sub + [core]
        raw, pieces = self._tokens(labels)
        res.tokens = [p for ps in pieces for p in ps]

        if fam.genuine:
            res.brand, res.closeness, res.in_family = fam.brand, 1.0, True
            res.genuine = fam.entry.domain if fam.entry else r.host
            return res

        matches: list[Match] = []
        core_fold = _fold(core)
        letters = sum(ch.isalnum() for ch in "".join(labels)) or 1
        core_letters = sum(ch.isalnum() for ch in core)
        bounds = self._boundaries(core)

        for b in self.reg.brands:
            best_b = 0.0
            for name in self.names[b.id]:
                if name in b.exact_aliases and core != name:   # whole tokens only (P11): repay isn't rupay
                    continue
                if core == name:   # same name, other ending
                    full = max((align(r.owner, e.domain, self.glyphs).similarity for e in b.family), default=0.0)
                    matches.append(Match(b, name, round(full, 4), "tld", None))
                    best_b = 1.0
                    continue
                if fuzz.ratio(core_fold, name) >= PREFILTER:
                    a = align(core, name, self.glyphs)
                    best_b = max(best_b, a.similarity)
                    if a.similarity >= self.tau and visible_edits(a) <= MAX_VISIBLE:
                        matches.append(Match(b, name, a.similarity, "visual", a))
                    elif core_fold == name:   # accented / foreign letters that a reader can still notice
                        matches.append(Match(b, name, a.similarity, "fold", a))
                    key = self._sound.get((b.id, name))
                    if (key and a.similarity >= SOUND_FLOOR and core.isascii() and core.isalpha()
                            and not any(e["op"] == "transpose" for e in a.edits)
                            and jellyfish.metaphone(core) == key):
                        matches.append(Match(b, name, a.similarity, "sound", a))
                else:
                    best_b = max(best_b, fuzz.ratio(core_fold, name) / 100 * 0.5)  # far: a rough figure only
                if (len(name) >= MIN_LOCAL and core_letters - len(name) >= MIN_EXTRA
                        and fuzz.partial_ratio(core_fold, name) >= PREFILTER_LOCAL):
                    loc = align(core, name, self.glyphs, local=True)
                    # inside a longer name, the brand must look near-identical (twins, homoglyphs): a
                    # typo-level match somewhere in a long word is noise (dubaiapartments ~ paytm)
                    if (loc.similarity >= self.tau and loc.kinds <= {"twin_letters", "homoglyph"}
                            and loc.span[0] in bounds and loc.span[1] in bounds):
                        matches.append(Match(b, name, round(loc.similarity * (0.5 + 0.5 * loc.coverage), 4),
                                             "local", loc))
            res.per_brand[b.id] = round(best_b, 3)

        tok = self._brand_token(raw, pieces)
        if tok and not (tok[1] == core and not sub):
            b, name = tok
            res.brand_token = name
            matches.append(Match(b, name, round(0.5 + 0.5 * min(1.0, len(name) / letters), 4), "token", None))
        elif not tok:
            flat = r.host.replace("-", "").replace(".", "")
            res.substring_hit = next((a for b in self.reg.brands for a in b.aliases if a in flat), None)

        if not matches and not tok and r.hosting_platform:          # fix (a): free hosting, brand in gibberish
            hid = self._hidden_in_gibberish(raw)
            if hid:
                b, name, label = hid
                res.brand_token, res.hidden_in, res.substring_hit = name, label, None
                matches.append(Match(b, name, round(0.5 + 0.5 * min(1.0, len(name) / letters), 4), "hidden", None))

        if fam.status == "imitation" and fam.brand is not None:
            self._from_family(r, fam, core, letters, matches, res)

        res.matches = matches
        if fam.status in ("restricted_unlisted", "restricted_other", "user_content"):
            # a vetted or brand-owned host: report how close it is, but it isn't a naming trick
            res.brand = fam.brand
            res.brand_signal = fam.status == "restricted_unlisted"
            res.closeness = res.per_brand.get(fam.brand.id) if fam.brand else None
            res.genuine = _genuine_for(fam.brand, fam.brand.aliases[0]) if fam.brand else None
            return res
        if not matches:
            return res

        # P2's structural proofs first, then an exact brand token or same-name ending swap, then the closest look
        rank = {"level_squat": 3, "trust_signal": 3, "skeleton": 3, "token": 2, "tld": 2}
        best = max(matches, key=lambda m: (rank.get(m.via, 1), m.closeness))
        same = [m for m in matches if m.brand.id == best.brand.id]
        res.best, res.brand, res.brand_signal = best, best.brand, True
        res.closeness = round(max(m.closeness for m in same), 4)
        res.genuine = _genuine_for(best.brand, best.name)
        res.lures = [{"word": p, "category": self.lure_cat[p]} for p in dict.fromkeys(res.tokens)
                     if p in self.lure_cat and p not in best.name]
        if (email := self._email_shaped(r, core, best, res)) is not None:    # fix (c): a mailbox name, no imitation
            res.email_shaped, res.brand_signal, res.best, res.substring_hit = email, False, None, None
            return res
        res.tricks = self._tricks(r, fam, best, same, core)
        return res

    def _hidden_in_gibberish(self, raw: list[str]) -> tuple[Brand, str, str] | None:
        """A distinctive brand name (4+ letters) inside a gibberish tenant label on free hosting (fix a)."""
        for label in raw:
            if not label.isascii():
                continue
            for b in self.reg.brands:
                for name in sorted(self.names[b.id], key=len, reverse=True):
                    if len(name) < DISTINCT_MIN or name not in label or label == name:
                        continue
                    rest = "".join(ch for ch in label.replace(name, "", 1) if ch.isalpha())
                    if len(rest) < GIBBERISH_MIN:
                        continue
                    words = sum(len(w) for w in self.seg.split(rest) if len(w) >= 4 and self.seg.known(w))
                    if words / len(rest) < GIBBERISH_WORDS:
                        return b, name, label
        return None

    def _email_shaped(self, r: AddressReading, core: str, best: Match, res: TrickResult) -> str | None:
        """'<mailbox>gmail.<tld>': an email address typed into a domain registration (fix c, O22)."""
        if r.subdomain or r.hosting_platform or best.via not in ("token", "local") or res.lures:
            return None
        for alias in EMAIL_ALIASES:
            if not core.endswith(alias) or alias not in best.brand.aliases:
                continue
            local = core[: -len(alias)].rstrip("-_.")
            if len(local) < EMAIL_LOCAL_MIN or not local.isascii():
                return None
            words = [w for part in local.replace("_", "-").split("-") for w in self.seg.split(part)]
            lure = lambda w: w in self.lure_cat or (w.endswith("s") and w[:-1] in self.lure_cat)   # noqa: E731
            if any(lure(w) or any(w == n for ns in self.names.values() for n in ns) for w in words):
                return None
            return f"{local}@{alias}.com"
        return None

    def _from_family(self, r, fam: FamilyResult, core: str, letters: int, matches: list[Match], res) -> None:
        """Turn the Family Verifier's imitation finding into a match (it names the brand for sure)."""
        brand, via = fam.brand, fam.matched_by
        if via == "skeleton":   # looks identical to a family address: align the labels to show the swap
            label = (fam.imitated or brand.family[0].domain).split(".")[0]
            a = align(core, label, self.glyphs)
            matches.append(Match(brand, label, a.similarity, "skeleton", a))
        elif via in ("level_squat", "trust_signal"):
            target = fam.imitated or brand.family[0].domain
            if target.startswith(".") or not any(e.domain == target for e in brand.family):
                # a trust ending (bank.in, .google): the brand's own address under it
                ending = target.lstrip(".")
                target = next((e.domain for e in brand.family if e.domain.endswith(ending)), brand.family[0].domain)
            loc = align(r.display.lower(), target, self.glyphs, local=True)
            matches.append(Match(brand, target, round(loc.similarity * (0.5 + 0.5 * loc.coverage), 4), via, loc))
        elif not any(m.brand.id == brand.id for m in matches):   # P2 alias token, at a token edge
            name = fam.imitated or brand.aliases[0]
            if name not in r.display.lower():
                # P2 found the alias only after folding look-alike letters (g00gle -> google): that's a twin or
                # homoglyph, not a brand token, so align it to show the swap
                local = len(core) > len(name)
                a = align(core, name, self.glyphs, local=local)
                clos = a.similarity * (0.5 + 0.5 * a.coverage) if local else a.similarity
                matches.append(Match(brand, name, round(clos, 4), "skeleton", a))
                return
            matches.append(Match(brand, name, round(0.5 + 0.5 * min(1.0, len(name) / letters), 4), "token", None))
            res.brand_token = res.brand_token or name

    def _tricks(self, r: AddressReading, fam: FamilyResult, best: Match, same: list[Match], core: str) -> list[str]:
        vias = {m.via for m in same}
        aligned = [m for m in same if m.alignment and m.via in ("skeleton", "fold", "visual", "sound")]
        aligned = aligned or [m for m in same if m.alignment and m.via == "local"]
        primary = max(aligned, key=lambda m: m.closeness) if aligned else None
        kinds = primary.alignment.kinds if primary else set()
        if primary and best.via not in ("level_squat", "trust_signal"):
            best.alignment = primary.alignment   # the edits shown are the name-level swap
        out = []
        if "level_squat" in vias:
            out.append("level_squat")
        if "trust_signal" in vias:
            out.append("trust_signal_mimicry")
        if r.mixed_script or "homoglyph" in kinds or "fold" in vias:
            out.append("homoglyph")
        if "twin_letters" in kinds:
            out.append("twin_letters")
        if kinds & {"typo", "keyboard", "hyphen"} and "sound" not in vias:
            out.append("typo")
        if "bitflip" in kinds:
            out.append("bitsquat")
        if "sound" in vias:
            out.append("soundsquat")
        # "brand + other words" needs real extra words: a single added letter or digit (googlee, google8) is a typo
        name_part = r.display.lower()[: -(len(r.public_suffix) + 1)] if r.public_suffix else r.display.lower()
        letters = sum(ch.isalnum() for ch in name_part)
        token = next((m.name for m in same if m.via in ("token", "local", "hidden")), best.name)
        others = [t for t in name_part.replace(".", "-").split("-") if t and t != token]
        word_added = bool(others) and all(t in self.glue_ok or t.isdigit() for t in others)   # in-echallan
        if (("token" in vias or "local" in vias or "hidden" in vias) and (letters - len(token) >= MIN_EXTRA or word_added)
                and not {"level_squat", "trust_signal_mimicry"} & set(out)):
            out.append("combosquat")
        if "tld" in vias:
            out.append("tld_swap")
        if not out:   # a brand signal must always name its trick
            out.append("typo" if kinds else "combosquat")   # near-miss of the brand / brand + a few characters
        return list(dict.fromkeys(out))


# --------------------------------------------------------------- evidence ---

SCORES = {"level_squat": 0.95, "trust_signal_mimicry": 0.85, "homoglyph": 0.95, "twin_letters": 0.9,
          "typo": 0.75, "bitsquat": 0.7, "soundsquat": 0.7, "combosquat": 0.85, "tld_swap": 0.8}


@dataclass
class _Cache:
    detector: TrickDetector | None = None


_CACHE = _Cache()


def default_detector() -> TrickDetector:
    if _CACHE.detector is None:
        _CACHE.detector = TrickDetector()
    return _CACHE.detector


def _edit_text(e: dict) -> str:
    if e["op"] == "insert":
        return f"added '{e['candidate']}'"
    if e["op"] == "delete":
        return f"dropped '{e['genuine']}'"
    if e["op"] == "transpose":
        return f"swapped '{e['genuine']}' to '{e['candidate']}'"
    cps = f" ({', '.join(e['codepoints'])})" if e.get("codepoints") else ""
    return f"'{e['candidate']}'{cps} for '{e['genuine']}'"


def trick_detector(r: AddressReading, family: FamilyResult | None = None, reg: Registry | None = None,
                   ids: Ids | None = None, detector: TrickDetector | None = None) -> tuple[TrickResult, list[dict]]:
    """Stage-1 tool: detect naming tricks and closeness, and return (result, evidence items)."""
    ids = ids or Ids()
    det = detector or (TrickDetector(reg) if reg is not None else default_detector())
    t0 = time.perf_counter()
    res = det.detect(r, family)
    items: list[dict] = []
    common = {"tool": TOOL, "stage": STAGE}
    b = brand_ref(res.brand)
    best = res.best
    edits = best.alignment.edits if best and best.alignment else []
    name = res.brand.name if res.brand else ""

    if res.in_family:
        items.append(evidence(ids, **common, criterion="C5", finding="no_trick", points_to="neutral", strength="medium",
                              score=0, target_brand=b,
                              summary=f"No naming trick: it is inside {name}'s own family ({res.genuine}).",
                              tokens=res.tokens))
        items.append(evidence(ids, **common, criterion="C4", finding="in_family", points_to="neutral", strength="medium",
                              score=0, target_brand=b, summary=f"Closeness 1.00: it is inside {name}'s family.",
                              closeness=1.0, genuine=res.genuine))
        return res, _timed(items, t0)

    for trick in res.tricks:
        detail: dict = {"genuine": res.genuine}
        if trick == "level_squat":
            summary = f"The genuine '{best.name}' is used as a prefix of a different owner ({r.owner})."
        elif trick == "trust_signal_mimicry":
            summary = f"Rebuilds {name}'s trust signal '{best.name}' with hyphens or glued letters; the real owner is {r.owner}."
        elif trick == "homoglyph":
            hidden = [e for e in edits if e["kind"] == "homoglyph"]
            how = "; ".join(_edit_text(e) for e in hidden) if hidden else "foreign-script letters"
            summary = f"Look-alike letters from another script or with marks: {how}. Reads as '{_fold(res.core)}'."
            detail.update(edits=hidden or edits, folded=_fold(res.core))
        elif trick == "twin_letters":
            tw = [e for e in edits if e["kind"] == "twin_letters"]
            how = "; ".join(_edit_text(e) for e in tw) if tw else "ASCII look-alikes"
            summary = f"Twin letters: {how}. '{res.core}' reads as '{best.name}'."
            detail.update(edits=tw or edits, levenshtein=Levenshtein.distance(res.core, best.name))
        elif trick == "typo":
            ty = [e for e in edits if e["kind"] in ("typo", "keyboard", "hyphen")]
            summary = f"Typo of '{best.name}': " + "; ".join(_edit_text(e) for e in ty) + "."
            detail.update(edits=ty)
        elif trick == "bitsquat":
            bf = [e for e in edits if e["kind"] == "bitflip"]
            summary = f"One flipped bit away from '{best.name}': " + "; ".join(_edit_text(e) for e in bf) + "."
            detail.update(edits=bf)
        elif trick == "soundsquat":
            summary = f"Sounds like '{best.name}' (Metaphone key {jellyfish.metaphone(best.name)}), spelt differently."
            detail.update(metaphone=jellyfish.metaphone(best.name))
        elif trick == "combosquat" and res.hidden_in:
            token = res.brand_token or best.name
            summary = (f"'{token}' hidden inside the gibberish label '{res.hidden_in}' on the free-hosting platform "
                       f"{r.hosting_platform}: a brand name nobody would type by accident.")
            detail.update(tokens=res.tokens, brand_alias=token, lure_words=res.lures, platform=r.hosting_platform,
                          hidden_in=res.hidden_in)
        elif trick == "combosquat":
            lw = ", ".join(f"'{l['word']}'" for l in res.lures)
            token = res.brand_token or best.name
            summary = (f"Brand token '{token}'" + (f" plus lure words {lw}" if lw else " plus other words")
                       + (f", on the free-hosting platform {r.hosting_platform}" if r.hosting_platform else "") + ".")
            detail.update(tokens=res.tokens, brand_alias=token, lure_words=res.lures, platform=r.hosting_platform)
        else:  # tld_swap
            summary = f"Same name as {name} ('{res.core}'), but the ending '.{r.public_suffix}' isn't {name}'s."
            detail.update(ending=r.public_suffix)
        items.append(evidence(ids, **common, criterion="C5", finding=trick, points_to="phishing", strength="medium",
                              score=SCORES[trick], target_brand=b, summary=summary, **detail))

    if res.email_shaped:
        items.append(evidence(ids, **common, criterion="C5", finding="email_shaped_name", points_to="neutral",
                              strength="medium", score=0, target_brand=None,
                              summary=(f"Spells an email address ({res.email_shaped}): someone's mailbox name typed into "
                                       "a domain registration, with no lure word. Not an imitation."),
                              email=res.email_shaped, tokens=res.tokens))
    if not res.tricks and res.substring_hit:
        items.append(evidence(ids, **common, criterion="C5", finding="substring_not_token", points_to="genuine",
                              strength="weak", score=0.7, target_brand=None,
                              summary=(f"'{res.substring_hit}' appears only inside other words "
                                       f"({' + '.join(res.tokens)}), so it isn't the brand."),
                              substring_hit=res.substring_hit, tokens=res.tokens))

    top = dict(sorted(res.per_brand.items(), key=lambda kv: -kv[1])[:3])
    if res.brand is not None and res.brand_signal and res.closeness is not None:
        lev = Levenshtein.normalized_similarity(res.core, best.name) if best else None
        how = {"visual": "by visual edit distance", "local": "found inside the name", "token": "the brand token is exact",
               "fold": "after folding look-alike letters", "sound": "by sound", "tld": "same name, other ending",
               "level_squat": "the genuine address appears in full", "trust_signal": "rebuilt trust signal",
               "skeleton": "identical skeleton", "hidden": "hidden in a gibberish label"}[best.via] if best else "vetted registry"
        lev_txt = f"; plain letter counting says {lev:.2f}" if lev is not None and best and best.via in ("visual", "fold") else ""
        items.append(evidence(ids, **common, criterion="C4", finding="brand_closeness", points_to="phishing",
                              strength="medium", score=res.closeness, target_brand=b,
                              summary=f"Closeness to {res.genuine} is {res.closeness:.2f} ({how}{lev_txt}).",
                              closeness=res.closeness, genuine=res.genuine, compared=best.name if best else None,
                              levenshtein_similarity=round(lev, 3) if lev is not None else None,
                              per_brand=top, edits=edits, method=best.via if best else None))
    else:
        best_id = next(iter(top), None)
        best_name = det.reg.brand(best_id).name if best_id else "-"
        items.append(evidence(ids, **common, criterion="C4", finding="far_from_all_brands", points_to="genuine",
                              strength="medium", score=1 - (top.get(best_id, 0.0) if best_id else 0.0),
                              summary=f"Far from every protected brand (best: {best_name} at {top.get(best_id, 0):.2f}).",
                              per_brand=top))

    if res.tld and res.tld["abused"]:
        items.append(evidence(ids, **common, criterion="C6", finding="abused_tld", points_to="phishing", strength="weak",
                              score=round(0.5 * res.tld["risk"], 3),
                              summary=(f"'.{r.tld}' carries phishing in {res.tld['risk']:.0%} of PhiUSIIL rows "
                                       f"({res.tld['phishing']:,} of {res.tld['phishing'] + res.tld['legitimate']:,}; "
                                       "dataset base rate 43%). A weak hint only."),
                              tld=r.tld, **{k: res.tld[k] for k in ("risk", "phishing", "legitimate")}))
    return res, _timed(items, t0)


def _timed(items: list[dict], t0: float) -> list[dict]:
    ms = (time.perf_counter() - t0) * 1000
    for it in items:
        it["duration_ms"] = round(ms, 3)
    return items
