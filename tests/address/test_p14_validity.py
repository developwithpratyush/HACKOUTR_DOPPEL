"""P14 hardening: names that can't exist are refused (never judged), the '@' disguise is read, and a network drop
mid-demo trips the breaker so every later call answers from cache."""
import socket
import time

import pytest

from doppel import net
from doppel.address import AddressError, read_address
from doppel.brain.brain import investigate


@pytest.mark.parametrize("raw, why", [
    ("xyz.invalid", "reserved"), ("sbi.test", "testing"), ("paytm.localhost", "this computer"),
    ("example.example", "documentation"), ("printer.local", "local network"), ("google.onion", "Tor"),
    ("corp.internal", "private networks"), ("abc.notatld", "isn't a real top-level domain"),
    ("hello world.com", "can't contain"), ("a..com", "empty part"), ("-sbi-.com", "hyphen"),
    ("x" * 64 + ".com", "63"), ("999.1.1.1", "IP address"), ("sbi_login.com", "underscore"),
    ("Your SBI account is blocked, visit sbi-kyc.in", "can't contain"),
])
def test_impossible_names_are_refused(raw, why):
    with pytest.raises(AddressError, match=why):
        read_address(raw)


@pytest.mark.parametrize("raw", ["sbi.co.in.", "1.2.3.4", "_dmarc.google.com", "xn--pytm-53d.com", "onlinesbi.sbi",
                                 "my-site.github.io", "https://user:pass@google.com/", "a.b.c.example.com"])
def test_real_names_still_read(raw):
    read_address(raw)


@pytest.mark.parametrize("raw, borrowed", [("https://sbi.co.in@secure-verify-login.top/account", "sbi.co.in"),
                                          ("http://www.onlinesbi.sbi@kyc-update.xyz/", "www.onlinesbi.sbi")])
def test_at_sign_disguise_is_a_borrowed_address(raw, borrowed):
    r = read_address(raw)
    assert r.embedded == {"domain": borrowed, "suffix": r.embedded["suffix"], "via": "userinfo"}
    v = investigate(raw, "paste")
    assert v["label"] in ("needs_review", "phishing") and v["owner"] == r.owner
    assert "before '@'" in next(e for e in v["evidence"] if e["criterion"] == "C1")["summary"]


def test_plain_login_part_is_not_a_trick():
    assert read_address("https://user:pass@google.com/").embedded is None
    assert investigate("https://user:pass@google.com/", "paste")["label"] == "genuine"


def test_breaker_trips_on_a_network_error_not_on_http_errors():
    import urllib.error

    assert net.is_network_error(urllib.error.URLError("no route")) and net.is_network_error(TimeoutError())
    assert not net.is_network_error(urllib.error.HTTPError("u", 429, "rate", {}, None))
    net.mark_up()
    net.mark_down("test")
    assert net.offline() and net.state()["down"]
    net.mark_up()
    assert not net.down()


def test_network_drop_mid_demo_answers_from_cache(monkeypatch):
    """Online mode, then every outside socket fails: one lookup trips the breaker, the rest answer instantly."""
    monkeypatch.delenv("DOPPEL_OFFLINE", raising=False)
    net.mark_up()
    tries = []

    def dead(*a, **k):
        tries.append(a[0] if a else None)
        raise socket.gaierror(11001, "network down")

    monkeypatch.setattr(socket, "getaddrinfo", dead)
    try:
        t = time.perf_counter()
        for raw in ("hdfc-netbanking-verify-kyc.in", "sbi-yono-reward-points.co", "paytm-cashback-offer.shop"):
            assert investigate(raw, "paste")["label"] in ("needs_review", "phishing", "sleeper")
        assert time.perf_counter() - t < 15
        assert net.down() and len(tries) <= 1
    finally:
        net.mark_up()
