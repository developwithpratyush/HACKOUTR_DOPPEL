"""The accepted SAN links from ``data/brands/discovered.yaml``, as a fast lookup (no network).

``lookup(host)`` returns the accepted entry that covers ``host`` (exact name, or a parent with
``include_subdomains``), with the certificate's facts attached, or None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from doppel.contract import REPO_ROOT

DISCOVERED = REPO_ROOT / "data" / "brands" / "discovered.yaml"


@dataclass
class SanIndex:
    exact: dict[str, dict] = field(default_factory=dict)
    wide: dict[str, dict] = field(default_factory=dict)
    certificates: dict[str, dict] = field(default_factory=dict)
    generated: str | None = None

    def lookup(self, host: str) -> dict | None:
        host = host.lower().rstrip(".")
        if host in self.exact:
            return self.exact[host]
        parts = host.split(".")
        for i in range(len(parts) - 1):
            hit = self.wide.get(".".join(parts[i:]))
            if hit:
                return hit
        return None

    def cert(self, sha256: str | None) -> dict:
        return self.certificates.get(sha256 or "", {})

    def __len__(self) -> int:
        return len(set(self.exact) | set(self.wide))


def parse(raw: dict, brand_ids: set[str] | None = None) -> SanIndex:
    idx = SanIndex(certificates=raw.get("certificates") or {}, generated=raw.get("generated"))
    for e in raw.get("accepted") or []:
        if brand_ids is not None and e["brand"] not in brand_ids:
            continue
        (idx.wide if e["include_subdomains"] else idx.exact)[e["domain"]] = e
        if e["include_subdomains"]:
            idx.exact.setdefault(e["domain"], e)
    return idx


@lru_cache(maxsize=4)
def load_index(path: Path = DISCOVERED) -> SanIndex:
    if not path.is_file():
        return SanIndex()
    import yaml

    from doppel.family import load_registry

    return parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, {b.id for b in load_registry().brands})
