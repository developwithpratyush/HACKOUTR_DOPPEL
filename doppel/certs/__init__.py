"""Certificate Forensics (P11): C16 certificate identity and C17 certificate history.

- ``facts``     what Doppel reads from one certificate (SANs, Organisation, validation type, SHA-256)
- ``store``     the JSON cache under data/certs/ (every read, with its fetch time; replays offline)
- ``tls``       live TLS reads, for proven-genuine names only
- ``ct``        Certificate Transparency search (SSLMate, crt.sh): the only way Doppel looks at a suspect
- ``discover``  family auto-discovery: SAN links from the brands' own certificates -> discovered.yaml
- ``index``     the accepted SAN links, as a lookup the brain uses (no network)
- ``forensics`` the tools: ``cert_forensics`` (Quick, C16) and ``ct_history`` (Standard, C16 + C17)

Needs ``cryptography`` (the ``certs`` extra) to parse certificates.
"""
