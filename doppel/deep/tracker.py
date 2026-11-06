"""Credential Tracker (Stage 3, Deep; C14 where the password goes, C15 behaviour after login).

**What it does.** In the sandboxed browser (``sandbox.py``) it opens the page in a fresh context, types a
unique made-up value (a **canary**) into every visible field of the form that asks for credentials, submits
it the way a person would (the submit button, else ``requestSubmit``), and records **every** request the page
makes afterwards: form posts, fetch/XHR, beacons, image pixels, and WebSocket frames (a mocked server: the
socket never connects). Each canary is then searched for in every URL, body and header (plain, URL-decoded
and base64-decoded), so each destination is known together with which fields it carried.

**Nothing leaves the machine.** No hostname resolves (``MAP * ~NOTFOUND``). Calls to anything that isn't the
fixture are answered *inside* the sandbox by a sink (an empty "ok"), so a kit's next step still runs and can
be watched; top-level navigations off the fixture are refused. Telegram bot tokens found on the way are
redacted in the evidence, and Telegram is never called.

**C14 destinations** are classified against the page and the brand it imitates: the page's own server
(same origin / same owner), inside the brand's genuine family, a third-party domain, a free-hosting relay
(``workers.dev``, ``pages.dev``...), or a **direct exfil channel** (Telegram bot API, Discord webhook, Google
Forms / Apps Script).

**C15 behaviour after login** (the DynaPhish invariant): a second session submits a *different* made-up login.
Both accepted (no error, the page moves on) -> ``accepts_any_credentials``; a bounce afterwards to the brand's
own site -> ``redirects_to_real_brand``; both rejected -> ``rejects_wrong_credentials`` (weak: a kit can fake
that too). A proven family member is only checked for C14 (``confirm_only``): we don't test logins on a
genuine site.

**Limitation (said in every C14 item):** most kits exfiltrate **server-side** (PHP ``mail()``, a same-origin
relay). The browser sees only the first hop, so a page that posts to its own server is reported as exactly
that: the credentials leave the brand's family to the page's owner; what happens next is invisible.
"""

from __future__ import annotations

import base64
import binascii
import random
import re
import time
from urllib.parse import unquote_plus, urlsplit

from doppel.deep import fields as FLD
from doppel.evidence import Ids, evidence

TOOL, STAGE = "credential_tracker", "deep"

# --------------------------------------------------------------------------------------- in the page ---

# Lists the forms and fillable visible inputs, tagging each with data-doppel-f / data-doppel-i so the fill and
# submit steps can find them again.
FIELDS_JS = r"""
() => {
  const W = innerWidth;
  const shown = el => {
    const r = el.getBoundingClientRect(), s = getComputedStyle(el);
    if (r.width < 2 || r.height < 2 || s.visibility === 'hidden' || s.display === 'none') return false;
    if (r.right < 0 || r.bottom < 0 || r.left > W * 3) return false;
    for (let e = el; e; e = e.parentElement) if (parseFloat(getComputedStyle(e).opacity) < 0.05) return false;
    return true;
  };
  const FILL = ['text', 'password', 'email', 'tel', 'number', 'url', 'search', ''];
  const desc = (el, i) => ({ i, tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase(),
    name: el.getAttribute('name') || '', id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
    autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
    label: (el.labels && el.labels[0] ? el.labels[0].innerText : '').slice(0, 80),
    inputmode: el.getAttribute('inputmode') || '' });
  let n = 0;
  const pick = root => [...root.querySelectorAll('input, textarea')].filter(el =>
      (el.tagName === 'TEXTAREA' || FILL.includes((el.getAttribute('type') || '').toLowerCase())) && shown(el) && !el.disabled && !el.readOnly);
  const forms = [...document.forms].map((f, k) => {
    f.setAttribute('data-doppel-f', String(k));
    const inputs = pick(f).map(el => { el.setAttribute('data-doppel-i', String(n)); return desc(el, n++); });
    return { f: k, action: f.getAttribute('action') ? f.action : null, method: (f.getAttribute('method') || 'get').toLowerCase(),
             visible: shown(f), inputs };
  });
  const loose = pick(document).filter(el => !el.form).map(el => { el.setAttribute('data-doppel-i', String(n)); return desc(el, n++); });
  return { forms, loose };
}
"""

# Types the canaries: the native value setter (so framework-controlled inputs see it) + the events a person's
# typing fires (keyloggers listen to input/keyup/change).
FILL_JS = r"""
(values) => {
  for (const [i, v] of values) {
    const el = document.querySelector(`[data-doppel-i="${i}"]`);
    if (!el) continue;
    el.focus();
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
    for (const t of ['input', 'keyup', 'change']) el.dispatchEvent(new Event(t, { bubbles: true }));
    el.blur();
  }
  return true;
}
"""

# Submits like a person: the form's visible submit button, else a visible button, else requestSubmit.
SUBMIT_JS = r"""
(target) => {
  const vis = el => { const r = el.getBoundingClientRect(), s = getComputedStyle(el);
                      return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const root = target.form === null ? document : document.querySelector(`[data-doppel-f="${target.form}"]`);
  if (!root) return 'none';
  if (root.tagName === 'FORM') root.noValidate = true;
  const submit = [...root.querySelectorAll('button:not([type=button]):not([type=reset]), input[type=submit], input[type=image]')].find(vis);
  if (submit && root.tagName === 'FORM') { submit.click(); return 'submit_button'; }
  const btn = [...root.querySelectorAll('button, [role=button], input[type=button], a.btn, a.button')].find(vis);
  if (btn) { btn.click(); return 'button'; }
  if (root.tagName === 'FORM') { try { root.requestSubmit(); return 'requestSubmit'; }
                                 catch (e) { HTMLFormElement.prototype.submit.call(root); return 'submit'; } }
  return 'none';
}
"""

FALLBACK_SUBMIT_JS = r"""
(target) => {
  const f = target.form === null ? null : document.querySelector(`[data-doppel-f="${target.form}"]`);
  if (!f) return 'none';
  f.noValidate = true;
  try { f.requestSubmit(); return 'requestSubmit'; } catch (e) { HTMLFormElement.prototype.submit.call(f); return 'submit'; }
}
"""

# The page after the submit: where it is, what it says, whether it still (or now) asks for credentials.
AFTER_JS = r"""
() => {
  const vis = el => { const r = el.getBoundingClientRect(), s = getComputedStyle(el);
                      return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const inputs = [...document.querySelectorAll('input')].filter(vis).map(el => ({
    type: (el.getAttribute('type') || '').toLowerCase(), name: el.getAttribute('name') || '', id: el.id || '',
    placeholder: el.getAttribute('placeholder') || '', visible: true }));
  return { url: location.href, title: document.title,
           text: (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').trim().slice(0, 800),
           password_fields: inputs.filter(i => i.type === 'password').length, inputs };
}
"""

# --------------------------------------------------------------------------------------- canaries ---

NUMERIC_LEN = {"card_number": 16, "aadhaar": 12, "account_number": 12, "mobile_number": 10, "otp": 6,
               "upi_pin": 6, "mpin": 6, "atm_pin": 4, "cvv": 3}
MIN_TRACEABLE = 6                      # shorter values (a CVV, a 4-digit PIN) are typed but not searched for
ASKS = FLD.CREDENTIALS | {"username", "mobile_number", "account_number"}


def _luhn_digit(body: str) -> str:
    total = 0
    for k, ch in enumerate(reversed(body)):
        d = int(ch)
        if k % 2 == 0:
            d *= 2
            d = d - 9 if d > 9 else d
        total += d
    return str((10 - total % 10) % 10)


def canary(field: str | None, inp: dict, rng: random.Random, n: int) -> str:
    """A made-up value for one input, unique to this run: digits where the field wants digits, else text."""
    numeric = (inp.get("type") in ("tel", "number") or inp.get("inputmode") in ("numeric", "tel", "decimal")
               or field in NUMERIC_LEN)
    if field == "expiry":
        return f"{rng.randint(1, 12):02d}/{rng.randint(28, 33)}"
    if numeric:
        size = NUMERIC_LEN.get(field or "", 10)
        digits = "".join(str(rng.randint(0, 9)) for _ in range(size))
        if field == "mobile_number":
            return "9" + digits[1:]
        if field == "card_number":
            body = "4" + digits[1:15]
            return body + _luhn_digit(body)
        return str(rng.randint(1, 9)) + digits[1:]
    tag = "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(7))
    value = f"dpl{tag}{n:02d}"
    return value + "@example.com" if inp.get("type") == "email" else value


def plan_fill(found: dict, seed: str) -> dict | None:
    """Which form to submit and what to type: the visible form asking for the most credential-like fields."""
    rng = random.Random(seed)
    best, best_score = None, 0
    for f in found.get("forms", []):
        kinds = [FLD.classify(i) for i in f["inputs"]]
        score = sum(k in ASKS for k in kinds) + 2 * sum(k in FLD.CREDENTIALS for k in kinds)
        if score > best_score:
            best, best_score = f, score
    if best is not None:
        target, inputs = {"form": best["f"]}, best["inputs"]
        form_info = {"index": best["f"], "action": best["action"], "method": best["method"]}
    else:
        loose = found.get("loose", [])
        if not any(FLD.classify(i) in ASKS for i in loose):
            return None
        target, inputs = {"form": None}, loose
        form_info = {"index": None, "action": None, "method": None, "note": "inputs outside any form"}
    values, canaries = [], []
    for n, inp in enumerate(inputs):
        kind = FLD.classify(inp)
        v = canary(kind, inp, rng, n)
        values.append([inp["i"], v])
        canaries.append({"field": kind or inp.get("name") or inp.get("id") or "other field", "name": inp.get("name") or inp.get("id"),
                         "value": v, "traceable": len(v) >= MIN_TRACEABLE})
    return {"target": target, "values": values, "canaries": canaries,
            "form": {**form_info, "fields": [c["field"] for c in canaries]}}


# --------------------------------------------------------------------------------------- reading requests ---

TELEGRAM_TOKEN = re.compile(r"(?<![0-9])([0-9]{8,10}):[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")
DISCORD_HOOK = re.compile(r"(/api/webhooks/[0-9]+/)[A-Za-z0-9_.-]+")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
ERROR_RE = re.compile(r"invalid|incorrect|wrong (user|pass|pin|otp|cred|detail)|not match|failed|try again|"
                      r"locked|गलत|अमान्य", re.I)
RELAY_SERVICES = ("webhook.site", "pipedream.net", "requestcatcher.com", "formspree.io", "getform.io", "formsubmit.co",
                  "ngrok.io", "ngrok-free.app", "ngrok.app", "requestbin.net", "beeceptor.com")
CHANNEL_NAMES = {"telegram": "Telegram", "discord": "Discord", "google_forms": "Google Forms"}
DIRECT = {"telegram": ("direct_exfil_telegram", 0.98), "discord": ("direct_exfil_discord", 0.97),
          "google_forms": ("direct_exfil_google_forms", 0.95)}
AGGREGATE = {"credentials_to_foreign_domain", "credentials_stay_in_family", "credentials_to_page_owner",
             "no_credentials_sent"}


def redact(text: str) -> str:
    """Telegram bot tokens -> ``12345****:[REDACTED]``; Discord webhook secrets -> ``[REDACTED]``."""
    text = TELEGRAM_TOKEN.sub(lambda m: m.group(1)[:5] + "****:[REDACTED]", text)
    return DISCORD_HOOK.sub(lambda m: m.group(1) + "[REDACTED]", text)


def tokens_in(text: str) -> list[str]:
    """Redacted forms of the Telegram tokens in ``text`` (never the tokens themselves)."""
    return sorted({m.group(1)[:5] + "****:[REDACTED]" for m in TELEGRAM_TOKEN.finditer(text)})


def channel(url: str) -> str | None:
    """Direct exfil channel or relay a URL belongs to, by host and path."""
    p = urlsplit(url)
    host, path = (p.hostname or "").lower(), p.path
    if host == "api.telegram.org" or host.endswith(".telegram.org"):
        return "telegram"
    if host in ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com") and "/api/webhooks/" in path:
        return "discord"
    if (host == "docs.google.com" and "/forms/" in path) or host == "forms.gle" or \
            (host == "script.google.com" and "/macros/" in path):
        return "google_forms"
    if any(host == s or host.endswith("." + s) for s in RELAY_SERVICES):
        return "relay"
    return None


def _b64_bits(text: str) -> list[str]:
    out = []
    for m in _B64.finditer(text):
        s = m.group(0)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = fn(s + "=" * (-len(s) % 4))
            except (binascii.Error, ValueError):
                continue
            dec = raw.decode("utf-8", "ignore")
            if dec and sum(c.isprintable() for c in dec) >= 0.8 * len(dec):
                out.append(dec)
                break
    return out


def haystack(*parts: str) -> str:
    """Everything a canary could hide in: the text plain, URL-decoded (twice) and base64-decoded."""
    bits = []
    for p in parts:
        if not p:
            continue
        once = unquote_plus(p)
        bits += [p, once, unquote_plus(once)]
        bits += _b64_bits(p) + _b64_bits(once)
    return "\n".join(bits).lower()


VIA = {"fetch": "fetch", "xhr": "XHR", "ping": "beacon", "image": "image pixel", "websocket": "WebSocket",
       "script": "script tag", "stylesheet": "stylesheet"}


def _via(r: dict) -> str:
    if r.get("type") == "document":
        return "form post" if r.get("method") == "POST" else "form (GET)"
    return VIA.get(r.get("type", ""), r.get("type") or "other")


def carriers(attempt: dict) -> list[dict]:
    """Requests (and WebSocket frames) that carried at least one canary, in time order."""
    trace = [c for c in attempt.get("canaries", []) if c["traceable"]]
    hits = []
    for r in attempt.get("requests", []):
        hay = haystack(r["url"], r.get("body", ""), " ".join(r.get("headers", {}).values()))
        found = [c["field"] for c in trace if c["value"].lower() in hay]
        if found:
            hits.append({"t_ms": r["t_ms"], "url": r["url"], "method": r["method"], "via": _via(r), "fields": found,
                         "top_nav": r.get("top_nav", False), "raw": r["url"] + "\n" + r.get("body", "")})
    for s in attempt.get("sockets", []):
        hay = haystack(s["url"], "\n".join(s["messages"]))
        found = [c["field"] for c in trace if c["value"].lower() in hay]
        if found:
            hits.append({"t_ms": s["t_ms"], "url": s["url"], "method": "WS", "via": "WebSocket", "fields": found,
                         "top_nav": False, "raw": s["url"] + "\n" + "\n".join(s["messages"])})
    return sorted(hits, key=lambda h: h["t_ms"])


def outcome(attempt: dict, page_host: str) -> dict:
    """C15 for one session: accepted / rejected / unknown, and where the page went afterwards."""
    if not attempt.get("submitted"):
        return {"state": "not_submitted", "bounce": None}
    canary_urls = {h["url"] for h in carriers(attempt)}
    bounces = [r["url"] for r in attempt.get("requests", [])
               if r.get("top_nav") and (urlsplit(r["url"]).hostname or "") != page_host and r["url"] not in canary_urls]
    answered = {p.get("answered_by") for p in attempt.get("posts", [])}
    after = attempt.get("after") or {}
    if after.get("url", "").startswith("chrome-error:"):
        after = {}                                     # the page left for a navigation the sandbox refused
    error = bool(after) and bool(ERROR_RE.search(f"{after.get('title', '')} {after.get('text', '')}"))
    still_login = after.get("password_fields", 0) > 0
    bounce = bounces[-1] if bounces else None
    if error:
        state = "rejected"
    elif bounce or ("fixture_backend" in answered and not still_login):
        state = "accepted"
    else:
        state = "unknown"
    why = ("an error message" if error else f"moved on to {urlsplit(bounce).hostname}" if bounce
           else "the server answered and the login form was gone" if state == "accepted"
           else "no answer from a server Doppel can reach" if "fixture_backend" not in answered else "still on the login form")
    return {"state": state, "bounce": bounce, "why": why,
            "answered_by": sorted(a for a in answered if a), "after_url": after.get("url")}


# --------------------------------------------------------------------------------------- the tool ---

def _dest_note(d: dict, brand_name: str | None) -> str:
    if d["relation"] in ("same_origin", "same_owner"):
        return f"{d['host']} (the page's own server)"
    if d.get("platform"):
        return f"{d['host']} (a free-hosting relay on {d['platform']})"
    if d.get("channel") == "relay":
        return f"{d['host']} (a form/webhook relay service)"
    return d["host"]


def credential_tracker(session: dict, page_host: str, owner: str, brand, genuine: bool, in_family_of,
                       ids: Ids | None = None, confirm_only: bool = False) -> tuple[dict, list[dict]]:
    """Evidence from a tracking session (``Sandbox.track_*``). ``brand``: the registry brand the page imitates or
    belongs to (from the name, the page's own claim, or the visual match), or None."""
    from doppel.address import read_address

    ids = ids or Ids()
    t0 = time.perf_counter()
    attempts = session.get("attempts", [])
    ref = {"id": brand.id, "name": brand.name} if brand is not None else None
    bname = brand.name if brand is not None else None
    ms = float(session.get("ms", 0.0))
    first = attempts[0] if attempts else {}
    static = session.get("static", {})
    common = {"attempts": len(attempts), "dummy_credentials": True, "confirm_only": confirm_only,
              "sandbox": {"answered_locally": sum(a.get("sunk", 0) for a in attempts),
                          "refused": sum(a.get("refused", 0) for a in attempts), "resolver": "MAP * ~NOTFOUND",
                          "contacted_outside": 0},
              **({"in_page_source": static} if static else {})}
    if not first.get("form"):
        item = evidence(ids, tool=TOOL, stage=STAGE, criterion="C14", finding="no_credential_form", points_to="neutral",
                        strength="weak", score=0, target_brand=ref, duration_ms=ms,
                        summary="No visible form asks for credentials, so there was nothing to type into or submit.",
                        **common)
        return {"destinations": [], "outcomes": []}, [item]

    # ---- C14: where did each canary go? --------------------------------------------------------------
    dests: dict[str, dict] = {}
    raw_text = []
    for a in attempts:
        for h in carriers(a):
            host = (urlsplit(h["url"]).hostname or "").lower()
            raw_text.append(h["raw"])
            d = dests.get(host)
            if d is None:
                try:
                    rd = read_address(host)
                    d_owner, platform = rd.owner, rd.hosting_platform
                except ValueError:
                    d_owner, platform = host, None
                rel = ("same_origin" if host == page_host else "same_owner" if d_owner == owner else "third_party")
                d = dests[host] = {"host": host, "url": redact(h["url"])[:240], "owner": d_owner, "relation": rel,
                                   "channel": channel(h["url"]), "platform": platform,
                                   "in_brand_family": bool(brand is not None and in_family_of(brand.id, host)),
                                   "via": [], "fields": [], "method": h["method"], "first_t_ms": h["t_ms"]}
            for k in ("via", "fields"):
                vals = [h["via"]] if k == "via" else h["fields"]
                d[k] += [v for v in vals if v not in d[k]]
    order = sorted(dests.values(), key=lambda d: d["first_t_ms"])
    target_only = False
    if not order:                 # no value travelled: fall back to where the form itself submitted (if it did)
        nav = next((r for r in first.get("requests", []) if r.get("top_nav")), None)
        host = (urlsplit(nav["url"]).hostname or "").lower() if nav else ""
        if host:
            target_only = True
            try:
                d_owner = read_address(host).owner
            except ValueError:
                d_owner = host
            order = [{"host": host, "url": redact(nav["url"])[:240], "owner": d_owner,
                      "relation": "same_origin" if host == page_host else "same_owner" if d_owner == owner else "third_party",
                      "channel": None, "platform": None,
                      "in_brand_family": bool(brand is not None and in_family_of(brand.id, host)),
                      "via": ["form target only"], "fields": [], "method": nav["method"], "first_t_ms": nav["t_ms"]}]
    tokens = tokens_in("\n".join(raw_text))
    canaries = [{"field": c["field"], "value": c["value"], "traceable": c["traceable"]} for c in first.get("canaries", [])]
    detail = {**common, "form": first.get("form"), "submitted_by": first.get("how"), "canaries": canaries,
              "requests_captured": sum(len(a.get("requests", [])) for a in attempts),
              "destinations": [{k: v for k, v in d.items() if k != "first_t_ms"} for d in order],
              "first_hop": order[0]["url"] if order else None,
              "limitation": ("Server-side exfiltration (PHP mail(), a relay behind the page's own server) is invisible "
                             "from the browser: Doppel reports the first hop only.")}
    items: list[dict] = []
    for ch, (finding, score) in DIRECT.items():
        hits = [d for d in order if d["channel"] == ch]
        if not hits:
            continue
        d = hits[0]
        tok = [t for t in tokens] if ch == "telegram" else []
        items.append(evidence(
            ids, tool=TOOL, stage=STAGE, criterion="C14", finding=finding, points_to="phishing", strength="strong",
            score=score, target_brand=ref,
            summary=(f"The page sent what was typed ({', '.join(f.replace('_', ' ') for f in d['fields'])}) straight to "
                     f"{CHANNEL_NAMES[ch]} ({d['host']}) by {', '.join(d['via'])}"
                     + (f"; bot token {tok[0]}" if tok else "") + ". Answered inside the sandbox: "
                     f"{CHANNEL_NAMES[ch]} was never contacted."),
            channel=ch, endpoint=d["host"], url_redacted=d["url"], fields=d["fields"], via=d["via"],
            blocked_by_sandbox=True, **({"token_redacted": tok[0]} if tok else {})))
    others = [d for d in order if d["channel"] not in DIRECT]
    if target_only:
        detail["basis"] = "form_target_only"
        detail["note"] = ("No typed value travelled (the form's fields have no names: the live page sends them by "
                          "script, which a saved copy doesn't run), so only the form's own target is known.")
    what = ("The login form submits to" if target_only else
            "The typed " + ", ".join(f.replace("_", " ") for f in (others[0]["fields"] if others else [])) + " went to")
    strong = "medium" if target_only else "strong"
    if brand is not None:
        leaving = [d for d in others if not d["in_brand_family"]]
        if leaving:
            own = all(d["relation"] in ("same_origin", "same_owner") for d in leaving)
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C14", finding="credentials_to_foreign_domain",
                points_to="phishing", strength=strong, score=0.6 if target_only else 0.9, target_brand=ref,
                summary=(f"{what} {', '.join(_dest_note(d, bname) for d in leaving)}, outside {bname}'s family"
                         + (": what that server does with it next can't be seen from the browser." if own else ".")),
                **detail))
        elif others:
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C14", finding="credentials_stay_in_family", points_to="genuine",
                strength=strong, score=0.6 if target_only else 0.9, target_brand=ref,
                summary=(f"{what} {', '.join(d['host'] for d in others)} only, inside {bname}'s family"
                         + (" (no field value travelled with the saved copy, so this is the form's target)." if target_only
                            else ".")),
                **detail))
    else:
        third = [d for d in others if d["relation"] == "third_party"]
        if third:
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C14", finding="credentials_to_foreign_domain",
                points_to="phishing", strength="medium", score=0.5 if target_only else 0.6, target_brand=None,
                summary=(f"{what} {', '.join(_dest_note(d, None) for d in third)}, a different owner than the page "
                         f"({owner})."), **detail))
        elif others:
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C14", finding="credentials_to_page_owner", points_to="neutral",
                strength="weak", score=0, target_brand=None,
                summary=(f"{what} the page's own server ({others[0]['host']}); with no brand to compare, that's what "
                         "any login does."), **detail))
    if not order:
        items.append(evidence(
            ids, tool=TOOL, stage=STAGE, criterion="C14", finding="no_credentials_sent", points_to="neutral",
            strength="weak", score=0, target_brand=ref,
            summary=("Made-up details were typed and submitted, but no request carried them (the form may need a "
                     "script the kit didn't ship, or send later)."), **detail))
    elif not any(it["finding"] in AGGREGATE for it in items):
        items[0]["details"].update(detail)        # only a direct channel: it carries the destination details

    # ---- C15: what happens after the login? -----------------------------------------------------------
    outs = [outcome(a, page_host) for a in attempts]
    for it in items:
        it["details"]["outcomes"] = outs
    if not confirm_only and len(outs) >= 2 and not genuine:
        states = [o["state"] for o in outs]
        bounce = next((o["bounce"] for o in reversed(outs) if o["bounce"]), None)
        bhost = (urlsplit(bounce).hostname or "") if bounce else None
        if all(s == "accepted" for s in states):
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C15", finding="accepts_any_credentials", points_to="phishing",
                strength="strong", score=0.9, target_brand=ref, outcomes=outs,
                summary=(f"Two different made-up logins were both accepted ({outs[0]['why']}; {outs[1]['why']}). "
                         "A real login rejects wrong details.")))
        elif all(s == "rejected" for s in states):
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C15", finding="rejects_wrong_credentials", points_to="genuine",
                strength="weak", score=0.5, target_brand=ref, outcomes=outs,
                summary="Both made-up logins were rejected, as a real login does (weak: a kit can show an error too)."))
        if bhost and brand is not None and in_family_of(brand.id, bhost):
            items.append(evidence(
                ids, tool=TOOL, stage=STAGE, criterion="C15", finding="redirects_to_real_brand", points_to="phishing",
                strength="strong", score=0.9, target_brand=ref, redirect_to=bounce, outcomes=outs,
                summary=(f"After the made-up login the page sends the victim on to the real {bname} site ({bhost}), so "
                         "the failed login looks like a glitch. (The sandbox refused that navigation.)")))
    items[0]["duration_ms"] = round(ms + (time.perf_counter() - t0) * 1000, 3)
    for it in items[1:]:
        it["duration_ms"] = 0.0
    return {"destinations": order, "outcomes": outs, "tokens": tokens}, items


def static_indicators(html: str) -> list[str]:
    """Exfil endpoints written into the page's own source (redacted): seen even if a kit never fires."""
    out = []
    if "api.telegram.org" in html:
        out.append("api.telegram.org" + (f" (bot token {tokens_in(html)[0]})" if tokens_in(html) else ""))
    if DISCORD_HOOK.search(html):
        out.append("a Discord webhook")
    if re.search(r"docs\.google\.com/forms/|script\.google\.com/macros/", html):
        out.append("a Google Forms / Apps Script endpoint")
    return out
