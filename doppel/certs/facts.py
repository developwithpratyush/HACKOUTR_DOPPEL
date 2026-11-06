"""Certificate facts: what Doppel reads from one X.509 certificate.

A Certificate Authority signs a certificate only after checking that the applicant controls **every** name on
it (the CA/Browser Forum Baseline Requirements, section 3.2.2.4). For OV/EV certificates it also checks the
organisation's legal name. So a certificate is a signed statement of two things Doppel can use:
- *which names one operator controls* (the SAN list), and
- *who* that operator is (the subject's Organisation field), when the certificate is OV or EV.

``facts_from_der`` turns DER bytes into a plain dict (JSON-safe, cached as-is):
    sha256, subject {cn, o, c}, issuer {cn, o}, sans, not_before, not_after, validation (EV/OV/IV/DV/unknown)
"""

from __future__ import annotations

import hashlib

# CA/Browser Forum policy OIDs (Baseline Requirements 7.1.6.1)
POLICY_TYPES = {"2.23.140.1.1": "EV", "2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV", "2.23.140.1.2.1": "DV"}
RANK = {"EV": 4, "OV": 3, "IV": 2, "DV": 1, "unknown": 0}


def facts_from_der(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        vals = [a.value for a in name.get_attributes_for_oid(oid)]
        return str(vals[0]) if vals else None

    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        policies = [p.policy_identifier.dotted_string
                    for p in cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value]
    except x509.ExtensionNotFound:
        policies = []
    kinds = [POLICY_TYPES[p] for p in policies if p in POLICY_TYPES]
    validation = max(kinds, key=RANK.get) if kinds else "unknown"
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": {"cn": attr(cert.subject, NameOID.COMMON_NAME), "o": attr(cert.subject, NameOID.ORGANIZATION_NAME),
                    "c": attr(cert.subject, NameOID.COUNTRY_NAME)},
        "issuer": {"cn": attr(cert.issuer, NameOID.COMMON_NAME), "o": attr(cert.issuer, NameOID.ORGANIZATION_NAME)},
        "sans": [s.lower() for s in sans],
        "not_before": nb.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": na.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "validation": validation,
    }


def san_covers(san: str, host: str) -> bool:
    """True if one SAN entry covers ``host`` (a wildcard covers exactly one label, RFC 6125 6.4.3)."""
    san, host = san.lower().rstrip("."), host.lower().rstrip(".")
    if san == host:
        return True
    if san.startswith("*."):
        base = san[2:]
        return host.endswith("." + base) and "." not in host[: -len(base) - 1]
    return False


def covers(cert: dict, host: str) -> str | None:
    """The SAN entry of ``cert`` that covers ``host``, or None."""
    return next((s for s in cert.get("sans", []) if san_covers(s, host)), None)
