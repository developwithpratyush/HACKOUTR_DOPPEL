"""Certificate Transparency search: the only way Doppel looks at a suspect's certificates.

Every publicly trusted certificate is logged in CT before browsers accept it, so a third party (SSLMate's
CT Search API, or crt.sh) can tell us which certificates name a domain, without any contact with the domain.

- **SSLMate** (``api.certspotter.com/v1/issuances``): with ``SSLMATE_API_KEY`` (free tier) from ``.env``,
  or unauthenticated (about 10 lookups per window, measured 2026-11-06). Gives the DER, so the Organisation
  field and the validation type are read too.
- **crt.sh** (fallback): names, issuer and dates only (no Organisation field), and often 502s.

Every answer is cached (``store``) with its fetch time; ``DOPPEL_OFFLINE=1`` or ``network=False`` means cache only.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from doppel.certs import store
from doppel.certs.facts import facts_from_der
from doppel.contract import REPO_ROOT

SSLMATE = "https://api.certspotter.com/v1/issuances"
CRTSH = "https://crt.sh/"
USER_AGENT = "doppel-ct/0.1 (certificate transparency research)"
TIMEOUT = 25
MAX_PAGES = 2


class RateLimited(RuntimeError):
    pass


def _api_key() -> str | None:
    if os.environ.get("SSLMATE_API_KEY"):
        return os.environ["SSLMATE_API_KEY"]
    try:
        from dotenv import dotenv_values
    except ImportError:
        return None
    return dotenv_values(REPO_ROOT / ".env").get("SSLMATE_API_KEY") or None


def _get(url: str, headers: dict | None = None) -> tuple[bytes, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:     # noqa: S310 - fixed https endpoints
        return r.read(), dict(r.headers)


def _sslmate(domain: str, include_subdomains: bool) -> dict:
    key = _api_key()
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    params = [("domain", domain), ("include_subdomains", "true" if include_subdomains else "false"),
              ("expand", "dns_names"), ("expand", "issuer"), ("expand", "cert_der")]
    issuances, after, pages, remaining, truncated = [], None, 0, None, False
    while pages < MAX_PAGES:
        q = params + ([("after", after)] if after else [])
        try:
            body, hdr = _get(SSLMATE + "?" + urllib.parse.urlencode(q), headers)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RateLimited(f"SSLMate rate limit ({'key' if key else 'no key: add SSLMATE_API_KEY to .env'})") from exc
            raise
        remaining = hdr.get("X-Ratelimit-Remaining", remaining)
        page = json.loads(body)
        for it in page:
            issuances.append(_issuance(it))
        pages += 1
        if not page or 'rel="next"' not in hdr.get("Link", ""):
            break
        after = page[-1]["id"]
    else:
        truncated = True
    return {"source": "sslmate" + ("" if key else "_unauthenticated"), "issuances": issuances,
            "truncated": truncated, "rate_limit_remaining": remaining}


def _issuance(it: dict) -> dict:
    out = {"id": it.get("id"), "sha256": it.get("cert_sha256"), "sans": [s.lower() for s in it.get("dns_names", [])],
           "issuer": {"o": (it.get("issuer") or {}).get("friendly_name") or (it.get("issuer") or {}).get("name")},
           "not_before": it.get("not_before"), "not_after": it.get("not_after"), "validation": "unknown",
           "subject": {"cn": None, "o": None, "c": None}}
    der = it.get("cert_der") or (it.get("cert") or {}).get("data")
    if der:
        try:
            f = facts_from_der(base64.b64decode(der))
            out.update(subject=f["subject"], validation=f["validation"], sha256=out["sha256"] or f["sha256"])
            out["issuer"] = {"o": f["issuer"]["o"] or out["issuer"]["o"], "cn": f["issuer"]["cn"]}
        except Exception:                          # noqa: BLE001 - a cert we can't parse still counts as logged
            pass
    return out


def _crtsh(domain: str, include_subdomains: bool) -> dict:
    q = ("%." if include_subdomains else "") + domain
    body, _ = _get(CRTSH + "?" + urllib.parse.urlencode({"q": q, "output": "json"}))
    seen, issuances = set(), []
    for row in json.loads(body or b"[]"):
        key = row.get("serial_number")
        if key in seen:                            # precertificate + certificate rows
            continue
        seen.add(key)
        issuances.append({"id": str(row.get("id")), "sha256": None,
                          "sans": sorted({n.lower() for n in str(row.get("name_value", "")).split("\n") if n}),
                          "issuer": {"o": _dn_o(row.get("issuer_name", ""))},
                          "not_before": (row.get("not_before") or "")[:19] + "Z",
                          "not_after": (row.get("not_after") or "")[:19] + "Z",
                          "validation": "unknown", "subject": {"cn": row.get("common_name"), "o": None, "c": None}})
    return {"source": "crtsh", "issuances": issuances, "truncated": False, "rate_limit_remaining": None}


def _dn_o(dn: str) -> str | None:
    for part in dn.split(","):
        k, _, v = part.strip().partition("=")
        if k == "O":
            return v.strip('"')
    return None


def search(domain: str, include_subdomains: bool = True, network: bool = True, refresh: bool = False,
           root=None) -> dict | None:
    """CT issuances naming ``domain`` (and its subdomains). Cached; None when not cached and the network is off."""
    domain = domain.lower().rstrip(".")
    name = domain + ("" if include_subdomains else "__exact")
    cached = store.load("ct", name, root)
    if cached and not refresh:
        return cached
    if not network or store.offline():
        return None
    errors = []
    for fn in (_sslmate, _crtsh):
        try:
            res = fn(domain, include_subdomains)
            break
        except Exception as exc:                   # noqa: BLE001 - try the next source
            errors.append(f"{fn.__name__.strip('_')}: {type(exc).__name__}: {str(exc)[:100]}")
    else:
        raise ConnectionError("; ".join(errors))
    record = {"domain": domain, "include_subdomains": include_subdomains, "fetched_at": store.now_iso(), **res}
    if errors:
        record["fallback_reason"] = errors
    store.save("ct", name, record, root)
    return record
