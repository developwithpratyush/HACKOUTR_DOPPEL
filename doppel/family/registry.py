"""Load data/brands/registry.yaml (contract: contracts/registry.schema.json) into objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from pathlib import Path

from doppel.address.unicode_data import skeleton
from doppel.contract import REPO_ROOT, load_yaml, validate_registry

REGISTRY_PATH = REPO_ROOT / "data" / "brands" / "registry.yaml"


@dataclass(frozen=True)
class FamilyEntry:
    domain: str
    include_subdomains: bool
    proof: str
    source: str | None
    verified_on: str | None
    note: str = ""

    def covers(self, host: str) -> bool:
        return host == self.domain or (self.include_subdomains and host.endswith("." + self.domain))


@dataclass(frozen=True)
class UserContentHost:
    host: str
    what: str

    def covers(self, host: str) -> bool:
        return host == self.host or host.endswith("." + self.host)


@dataclass(frozen=True)
class Brand:
    id: str
    name: str
    aliases: tuple[str, ...]
    brand_tlds: tuple[str, ...]
    restricted_suffixes: tuple[str, ...]
    family: tuple[FamilyEntry, ...]
    user_content: tuple[UserContentHost, ...]
    lure_words: tuple[str, ...]
    legal_names: tuple[tuple[str, str | None], ...] = ()   # (O= name, country) from OV/EV certificates (P11, C16)
    exact_aliases: frozenset[str] = frozenset()             # whole tokens only, never look-alike targets (P11)

    @cached_property
    def alias_skeletons(self) -> dict[str, str]:
        return {a: skeleton(a).lower() for a in self.aliases}


@dataclass(frozen=True)
class Registry:
    brands: tuple[Brand, ...]
    restricted: dict[str, str]          # suffix -> who can register
    brand_tld_rows: dict[str, dict]     # tld -> IANA row
    lure_words: dict[str, str] = field(default_factory=dict)  # word -> category

    @cached_property
    def family_skeletons(self) -> dict[str, tuple[Brand, str]]:
        """Lowercased UTS #39 skeleton of every family domain -> (brand, domain)."""
        return {skeleton(e.domain).lower(): (b, e.domain) for b in self.brands for e in b.family}

    def brand(self, brand_id: str) -> Brand:
        return next(b for b in self.brands if b.id == brand_id)


def parse_registry(raw: dict) -> Registry:
    problems = validate_registry(raw)
    if problems:
        raise ValueError("registry fails its contract:\n  - " + "\n  - ".join(problems))
    brands = tuple(
        Brand(
            id=b["id"], name=b["name"], aliases=tuple(b["aliases"]), brand_tlds=tuple(b["brand_tlds"]),
            restricted_suffixes=tuple(b["restricted_suffixes"]),
            family=tuple(FamilyEntry(e["domain"], e["include_subdomains"], e["proof"], e["source"],
                                     e["verified_on"], e.get("note", "")) for e in b["genuine_family"]),
            user_content=tuple(UserContentHost(u["host"], u["what"]) for u in b.get("user_content_hosts", [])),
            lure_words=tuple(w["word"] for w in b["lure_words"]),
            legal_names=tuple((n["name"], n.get("country")) for n in b.get("legal_names", [])),
            exact_aliases=frozenset(b.get("exact_aliases", [])),
        )
        for b in raw["brands"]
    )
    return Registry(
        brands=brands,
        restricted={r["suffix"]: r["who_can_register"] for r in raw["restricted_registries"]},
        brand_tld_rows={r["tld"]: r for r in raw.get("brand_tld_registry", [])},
        lure_words={w["word"]: w["category"] for w in raw["lure_words"]},
    )


@lru_cache(maxsize=None)
def load_registry(path: Path = REGISTRY_PATH) -> Registry:
    return parse_registry(load_yaml(path))
