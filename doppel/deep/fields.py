"""Form-field reader (C13, the DOM half): which sensitive things does a page ask for?

Reads each visible input's type, name, id, placeholder, autocomplete, aria-label and label text, and maps it
to a fixed vocabulary with English + Hindi keywords. The Vision AI adds what it sees in the screenshot;
the union is the C13 evidence.
"""

from __future__ import annotations

import re

SENSITIVE = [  # (field, pattern) checked in order; first match wins
    ("upi_pin", r"upi.?pin|यूपीआई पिन"),
    ("mpin", r"\bm.?pin\b|एमपिन"),
    ("atm_pin", r"atm.?pin|\bpin\b|पिन"),
    ("cvv", r"\bcvv|\bcvc|\bcsc\b|security code"),
    ("card_number", r"card.?(no|num)|cc.?number|debit card|credit card|कार्ड"),
    ("expiry", r"expir|mm\s*/\s*yy|valid.?thru|cc.?exp"),
    ("otp", r"\botp\b|one.?time|verification code|ओटीपी"),
    ("password", r"pass(word)?|pwd|पासवर्ड"),
    ("aadhaar", r"aadh?aar|आधार|\buid\b"),
    ("pan", r"\bpan\b|pan.?(no|number|card)|पैन"),
    ("username", r"user.?(name|id)|\buser\b|login.?id|customer.?id|email or phone|identifier|उपयोगकर्ता"),
    ("mobile_number", r"mobile|phone|\btel\b|मोबाइल"),
    ("vehicle_number", r"vehicle|\brc.?no|registration.?no|वाहन"),
    ("account_number", r"account.?(no|number)|खाता"),
]
SENSITIVE_RE = [(name, re.compile(p, re.I)) for name, p in SENSITIVE]
CREDENTIALS = {"password", "otp", "mpin", "upi_pin", "atm_pin", "card_number", "cvv", "expiry", "aadhaar", "pan"}


def classify(inp: dict) -> str | None:
    if inp.get("type") == "password":
        return "password"
    text = " ".join(str(inp.get(k) or "") for k in ("name", "id", "placeholder", "autocomplete", "aria", "label"))
    text = re.sub(r"[_\-.\[\]]+", " ", re.sub(r"([a-z])([A-Z])", r"\1 \2", text))   # otp_code, otpCode -> otp code
    if not text.strip():
        return None
    for name, rx in SENSITIVE_RE:
        if rx.search(text):
            return name
    return None


def asks_for(inputs: list[dict]) -> list[str]:
    """Sensitive fields among the visible inputs, in first-seen order."""
    seen: list[str] = []
    for inp in inputs:
        if inp.get("type") in ("hidden", "submit", "button", "checkbox", "radio", "range", "search") or not inp.get("visible", True):
            continue
        f = classify(inp)
        if f and f not in seen:
            seen.append(f)
    return seen
