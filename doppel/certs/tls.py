"""Live TLS reads, **for proven-genuine names only** (the finale safety rule).

Doppel never opens a connection to a suspect. The one live read it makes is of a name the Family Verifier has
already proven (a registry seed: brand-owned ending, restricted registry, or the official list), to read the
certificate that the brand itself serves. ``read_seed`` enforces that before any socket opens.
"""

from __future__ import annotations

import socket
import ssl

from doppel.certs import store
from doppel.certs.facts import facts_from_der

TIMEOUT = 8.0


class NotProvenGenuine(PermissionError):
    """Raised when asked to read a live certificate of a name that isn't proven genuine."""


def proven_brand(host: str, reg) -> str | None:
    """The brand whose P2 proofs cover ``host`` (genuine family), else None."""
    from doppel.address import read_address
    from doppel.family import check_family

    fam = check_family(read_address(host), reg)
    return fam.brand.id if fam.genuine and fam.brand else None


def read_seed(host: str, reg, refresh: bool = False, root=None) -> dict:
    """The certificate ``host`` serves on port 443, from the cache unless ``refresh``. Proven-genuine hosts only."""
    host = host.lower().rstrip(".")
    brand = proven_brand(host, reg)
    if brand is None:
        raise NotProvenGenuine(f"{host} isn't proven genuine: Doppel never makes a TLS connection to it")
    cached = store.load("tls", host, root)
    if cached and not refresh:
        return cached
    if store.offline():
        raise ConnectionError(f"offline and no cached certificate for {host}")
    ctx = ssl.create_default_context()           # full chain + hostname verification: a genuine site must pass
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    record = {"host": host, "brand": brand, "fetched_at": store.now_iso(), "source": "live_tls",
              "cert": facts_from_der(der)}
    store.save("tls", host, record, root)
    return record
