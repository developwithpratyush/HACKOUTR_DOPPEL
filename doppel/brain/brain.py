"""The brain (P5): a deterministic investigator that calls the tools stage by stage and writes the verdict.

Not an LLM. For one domain:

  Quick     address_reader -> family_verifier -> trick_detector -> cert_forensics   (always; each needs the
            previous one; cert_forensics (P11, C16) only when there is something to prove or explain)
  Standard  human_eye_renderer || risk_model || page_probe || ct_history   (in parallel; ct_history: P11, C16/C17)
            then campaign_radar (P13, C18: an index lookup; weak, it raises priority and never decides)
  Deep      page_inspector || vision_ai || credential_tracker       (P8/P9: local fixture pages only)

Escalation is automatic (no mode flag). ``input.source`` decides:
- single investigations (paste, api, fool_it, gallery) run every stage that exists;
- batch sources (file, stdin, nrd_snapshot, ct_feed) stop after Quick unless there is a brand signal
  (or a vetted/brand-owned host to explain), and never re-check a proven family member.

After each stage the brain publishes a provisional verdict; the trace records every tool call with the
risk score before and after, so the Decision Trace Explorer can replay it. Fusion and the label policy
live in ``fusion.py``. The what-if (counterfactual) undoes the detected trick and re-scans the result.
"""

from __future__ import annotations

import datetime as dt
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import os

from doppel import CONTRACT_VERSION, __version__
from doppel.address import address_reader
from doppel.brain import fusion
from doppel.brain.probe import FIXTURES, _sites, page_probe
from doppel.certs import store as cert_store
from doppel.certs.forensics import cert_forensics, ct_history
from doppel.campaign.index import campaign_radar, load_campaigns
from doppel.certs.index import load_index
from doppel.evidence import Ids, brand_ref
from doppel.family import family_verifier, load_registry
from doppel.risk import model as risk
from doppel.tricks import default_detector, trick_detector

SINGLE_SOURCES = {"paste", "api", "fool_it", "gallery"}
BATCH_SOURCES = {"file", "stdin", "nrd_snapshot", "ct_feed"}
ENGINE = f"{__version__}+p13"
DEEP_SOURCES = {"paste", "api", "gallery"}      # fool_it re-scores per keystroke: Deep (seconds + a Gemini call) waits
CHANNEL = {"telegram": "Telegram", "discord": "Discord", "google_forms": "Google Forms"}
DEEP_UNAVAILABLE = ("Deep tools need the `deep` extra (Playwright + Chromium) and genuine snapshots "
                    "(scripts/data/snapshot_genuine.py); not available here, so this verdict uses the name and page probe only.")
PAGE_CLAIM = "claimed_brand_mismatch"
H1_TEXT = "Ownership is proven by the Family Verifier, so the domain is genuine whatever the other signals say."
H1_CERT_TEXT = ("Ownership is proven by Certificate Forensics (a CA-validated certificate ties it to {brand}), so the "
                "domain is genuine whatever the other signals say.")
PROOF_FINDINGS = {"genuine_family", "certificate_san_link", "certificate_organisation_match"}
CERT_CHECKS = ["C16", "C17"]
CT_NETWORK_SOURCES = {"paste", "api"}     # a live CT lookup only for a person's own single investigation
TRICK_WORDS = {"homoglyph": "hidden look-alike letters", "twin_letters": "twin letters", "typo": "a typo",
               "bitsquat": "a flipped bit", "soundsquat": "a sound-alike spelling", "combosquat": "the brand plus extra words",
               "level_squat": "its genuine address as a prefix", "trust_signal_mimicry": "a rebuilt trust ending",
               "tld_swap": "the brand name with another ending"}

_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="doppel-tool")


def _deep_available() -> bool:
    try:
        from doppel.deep.pages import references
        from doppel.deep.sandbox import available
    except ImportError:
        return False
    return available() and bool(references())


class _Case:
    """Collects evidence, stage records and trace steps, with real timings."""

    def __init__(self) -> None:
        self.t0 = time.perf_counter()
        self.ids = Ids()
        self.evidence: list[dict] = []
        self.trace: list[dict] = []
        self.stages = {s: {"stage": s, "status": "completed", "tools": [], "evidence_ids": [], "provisional": None}
                       for s in ("quick", "standard", "deep")}
        self.spans: dict[str, list[float]] = {}
        self.risk = fusion.risk([])

    def now(self) -> float:
        return round((time.perf_counter() - self.t0) * 1000, 3)

    def step(self, **step) -> None:
        self.trace.append({"step": len(self.trace) + 1, **step})

    def tool(self, stage: str, tool: str, args: dict, start: float, items: list[dict], message: str) -> None:
        dur = max([it.get("duration_ms", 0.0) for it in items] + [0.0])
        for it in items:
            it.setdefault("duration_ms", dur)
        self.evidence += items
        rec = self.stages[stage]
        if tool not in rec["tools"]:
            rec["tools"].append(tool)
        rec["evidence_ids"] += [it["evidence_id"] for it in items]
        lo, hi = self.spans.get(stage, [start, start + dur])
        self.spans[stage] = [min(lo, start), max(hi, start + dur)]
        before, self.risk = self.risk, fusion.risk(self.evidence)
        self.step(t_ms=start, kind="tool", stage=stage, tool=tool, args=args, duration_ms=round(dur, 3),
                  evidence_ids=[it["evidence_id"] for it in items], risk_before=before, risk_after=self.risk,
                  message=message)

    def provisional(self, stage: str, label: str, reason: str) -> None:
        self.stages[stage]["provisional"] = {"label": label, "risk_score": self.risk, "reason": reason}
        self.step(t_ms=self.now(), kind="provisional_verdict", stage=stage, label=label, risk_after=self.risk,
                  message=reason)

    def skip(self, stage: str, reason: str) -> None:
        self.stages[stage].update(status="skipped", skip_reason=reason)

    def timings(self) -> dict:
        out = {}
        for s, rec in self.stages.items():
            lo_hi = self.spans.get(s)
            out[s] = None if rec["status"] == "skipped" else round(lo_hi[1] - lo_hi[0], 3) if lo_hi else 0.0
        out["total"] = self.now()
        return out


class Brain:
    def __init__(self, reg=None, fixtures: Path = FIXTURES, render_dir: Path | None = None, deep: bool = True,
                 certs: bool | None = None) -> None:
        self.reg = reg or load_registry()
        # P11 Certificate Forensics (C16/C17); DOPPEL_CERTS=0 turns it off by default (per call: ``certs=``)
        self.certs = (os.environ.get("DOPPEL_CERTS", "1") not in ("0", "false")) if certs is None else certs
        self.cert_index = load_index()
        self.campaigns = load_campaigns()       # P13 Campaign Radar index (data/campaigns/index.json), C18
        self.det = default_detector() if reg is None else None
        self.fixtures = fixtures
        self.render_dir = render_dir
        self.risk_model = risk.default_model() if risk.available() else None   # C8 (P7), loaded once
        self.deep = deep and fixtures == FIXTURES and _deep_available()        # P8: sandbox + snapshots
        self._brands = {b.id: b for b in self.reg.brands}

    # ------------------------------------------------------------------ investigate ---

    def investigate(self, raw: str, source: str = "paste", counterfactual: bool = True,
                    certs: bool | None = None) -> dict:
        """One verdict. ``certs=False`` is the ablation switch: the same run with C16/C17 off (``--no-cert``)."""
        if source not in SINGLE_SOURCES | BATCH_SOURCES:
            raise ValueError(f"unknown source {source!r}")
        single = source in SINGLE_SOURCES
        use_certs = self.certs if certs is None else certs
        c = _Case()
        c.step(t_ms=0.0, kind="case_opened",
               message=f"New case: {raw}. " + ("Single investigation, so every stage runs and the verdict updates "
                                               "after each one." if single else
                                               "Batch input, so the brain escalates only on evidence."))

        # ---- Stage 1: Quick ------------------------------------------------------------
        t = c.now()
        reading, ev = address_reader(raw, c.ids)
        c.tool("quick", "address_reader", {"raw": raw}, t, ev, f"Address Reader: real owner {reading.owner}.")
        t = c.now()
        fam, ev = family_verifier(reading, self.reg, c.ids)
        c.tool("quick", "family_verifier", {"domain": reading.host, "owner": reading.owner}, t, ev,
               f"Family Verifier: {ev[0]['summary']}")
        t = c.now()
        tricks, ev = trick_detector(reading, fam, self.reg, c.ids, detector=self.det)
        c.tool("quick", "trick_detector", {"domain": reading.host, "owner": reading.owner}, t, ev,
               "Trick Detector: " + (", ".join(tricks.tricks) + f" imitating {tricks.brand.name}." if tricks.tricks
                                    else ev[0]["summary"]))

        genuine = fam.genuine
        review_host = fam.status in ("restricted_unlisted", "user_content")
        signal = tricks.brand_signal and not genuine
        cert_res = None
        if use_certs and not genuine and (signal or review_host or self.cert_index.lookup(reading.host)):
            t = c.now()
            cert_res, ev = cert_forensics(reading, fam, tricks.brand if signal else fam.brand, self.reg, c.ids,
                                          self.cert_index)
            c.tool("quick", "cert_forensics", {"domain": reading.host, "index": "data/brands/discovered.yaml"}, t, ev,
                   f"Certificate Forensics: {ev[0]['summary']}")
            if cert_res.proven:
                genuine, review_host, signal = True, False, False
        proof_brand = cert_res.brand if cert_res is not None and cert_res.proven else None
        brand = (proof_brand or fam.brand) if genuine else (tricks.brand if signal else fam.brand if review_host else None)
        q_label = "genuine" if genuine else "suspicious" if signal or review_host else "benign"
        c.provisional("quick", q_label, self._quick_reason(q_label, brand, tricks, fam, proof_brand is not None))

        # ---- escalate? -------------------------------------------------------------------
        go_standard = single or signal or review_host
        if not go_standard:
            why = ("Batch input and no brand signal, so stop after Stage 1." if not genuine
                   else "Batch input and proven family, so stop after Stage 1.")
            c.step(t_ms=c.now(), kind="policy", message=why)
            c.skip("standard", why.replace(", so stop after Stage 1.", ": not escalated."))
            c.skip("deep", why.replace(", so stop after Stage 1.", ": not escalated."))
            page = None
            probe_res = None
        else:
            c.step(t_ms=c.now(), kind="policy", message=(
                "Genuine family: still check the page in Stage 2." if genuine else
                "Brand signal found, so go to Stage 2 (Standard)." if signal else
                "Vetted or brand-owned host: go to Stage 2 to see what the page is." if review_host else
                "Single investigation: continue to Stage 2 anyway (it could be a brand-less clone)."))
            ct_net = source in CT_NETWORK_SOURCES and reading.host not in _sites(self.fixtures)
            probe_res, page = self._standard(c, reading, tricks, fam, brand, genuine, signal,
                                             ct=use_certs and signal and not reading.hosting_platform, ct_network=ct_net)
            ct_res = c.ct_res
            if not genuine and (hit := self.campaigns.get(reading.owner)):   # C18: weak, bounded, never decides
                t = c.now()
                ev = campaign_radar(reading, hit, brand, c.ids)
                c.tool("standard", "campaign_radar", {"owner": reading.owner, "index": "data/campaigns/index.json"}, t,
                       ev, f"Campaign Radar: {ev[0]['summary']}")
            if ct_res is not None and ct_res.proven and not genuine:      # an OV/EV legal-name match (C16)
                genuine, review_host, signal = True, False, False
                brand = proof_brand = ct_res.brand
            c.provisional("standard", *self._standard_provisional(genuine, signal, review_host, page, c.risk))
            why = None
            if page in fusion.EMPTY_PAGE_FINDINGS:
                why = "No live page (parked or empty): nothing to open. Re-check in 24 h."
            elif page == "not_probed":
                why = "Page not opened (Doppel never visits unknown domains), so there is nothing for Deep to inspect."
            elif source not in DEEP_SOURCES:
                why = ("Live re-scoring stops before Deep (a sandboxed browser and a vision model take seconds); "
                       "investigate the name for the full case." if source == "fool_it" else
                       "Batch input: Deep runs only for single investigations.")
            elif not self.deep:
                why = DEEP_UNAVAILABLE
            if why:
                c.step(t_ms=c.now(), kind="policy", message=f"Skip Stage 3 (Deep): {why}")
                c.skip("deep", why)
            else:
                c.step(t_ms=c.now(), kind="policy", message=(
                    "A live page on a local fixture: go to Stage 3 (Deep) and open it in the sandboxed browser "
                    "(no request can leave the machine)."))
                try:
                    self._deep(c, reading, brand, genuine)
                except Exception as exc:                  # noqa: BLE001 - a broken browser must not break the verdict
                    why = f"Deep stage failed ({type(exc).__name__}: {str(exc)[:120]}); verdict from Stages 1-2."
                    c.step(t_ms=c.now(), kind="policy", message=why)
                    c.stages["deep"].update(status="skipped", skip_reason=why, tools=[], evidence_ids=[])

        # ---- the page's own brand claim (Deep, C12) ------------------------------------------
        claim = next((e for e in c.evidence if e["finding"] == PAGE_CLAIM), None)
        page_signal = claim is not None and not genuine
        if page_signal and brand is None:
            brand = self._brands.get(claim["target_brand"]["id"])

        # ---- verdict ---------------------------------------------------------------------
        credential = page in fusion.CREDENTIAL_FINDINGS and not genuine
        fired = fusion.hard_rules(c.evidence, genuine)
        leak = fusion.leaves_family(c.evidence) if genuine else []
        if leak:                                          # proven owner, but the login leaves the family
            label, confidence = "needs_review", "low"
        elif fired:
            label, confidence = "phishing", "high"
        else:
            label, confidence = fusion.decide(genuine=genuine, brand_signal=signal or page_signal,
                                              review_host=review_host, page=page, risk_score=c.risk,
                                              credential_form=credential)
        if label == "needs_review" and (signal or page_signal) and not leak:   # P13: the conformal review line
            above = c.risk >= fusion.REVIEW_TAU
            c.step(t_ms=c.now(), kind="policy", message=(
                f"Review priority: risk {c.risk:.3f} is {'at or above' if above else 'below'} the review line "
                f"{fusion.REVIEW_TAU} (split-conformal on P3 look-alikes: at most 5% of real look-alikes score below it), "
                f"so {'medium' if above else 'low'} priority in the queue."))
        if c.stages["deep"]["status"] == "completed":
            c.provisional("deep", label if label != "needs_review" else "suspicious",
                          self._deep_provisional(label, c.evidence))
        hard_rule = None
        if genuine and not leak:
            gid = [e["evidence_id"] for e in c.evidence if e["finding"] in PROOF_FINDINGS and e["points_to"] == "genuine"]
            stay = [e["evidence_id"] for e in c.evidence if e["finding"] == "credentials_stay_in_family"]
            gid += stay
            text = (H1_TEXT if fam.genuine else H1_CERT_TEXT.format(brand=brand.name)) + \
                (" Its login stays in the family." if stay else "")
            hard_rule = {"id": "H1_genuine_family", "forces": "genuine", "description": text, "evidence_ids": gid}
            c.step(t_ms=c.now(), kind="hard_rule", evidence_ids=gid, message=f"Hard rule fired: H1_genuine_family. {text}")
        elif fired:
            rid, eids = fired[0]
            hard_rule = {"id": rid, "forces": "phishing", "description": fusion.RULE_TEXT[rid], "evidence_ids": eids,
                         **({"also_fired": [r for r, _ in fired[1:]]} if len(fired) > 1 else {})}
            c.step(t_ms=c.now(), kind="hard_rule", evidence_ids=sorted({i for _, ids in fired for i in ids},
                                                                     key=lambda x: int(x[1:])),
                   message=f"Hard rule fired: {', '.join(r for r, _ in fired)}. {fusion.RULE_TEXT[rid]}")
        reason = self._reason(label, brand, tricks, fam, probe_res, page, reading)
        if label == "genuine" and not fam.genuine and proof_brand is not None:
            reason = self._cert_reason(proof_brand, c.evidence)
        elif label in ("needs_review", "sleeper") and (extra := self._cert_extra(c.evidence)):
            reason = reason.rstrip(".") + "; " + extra + "."
        if leak:
            hosts = ", ".join(sorted({d["host"] for e in leak for d in e["details"].get("destinations", [])}
                                     | {e["details"].get("endpoint") for e in leak if e["details"].get("endpoint")}))
            reason = (f"A proven {brand.name} address, but its login sends what you type to {hosts}, outside the family: "
                      f"possibly compromised. Tell {brand.name}; don't block the domain.")
        elif page_signal and not signal:                  # the brand came from the page, not the name
            reason = self._page_reason(label, brand, reading, c.evidence)
        elif label == "phishing":                         # say what the page itself asks for (Deep, C13)
            asks = next((e["details"]["asks_for"] for e in c.evidence if e["finding"] == "asks_sensitive"), None)
            if asks:
                reason = reason.split(" asks for ")[0] + " asks for " + ", ".join(a.replace("_", " ") for a in asks) + "."
        if label == "phishing" and brand is None:          # H3/H4 with no brand in the name or on the page
            reason = f"Imitates no protected brand, but the page on {reading.owner} " + \
                (self._cred_clause(c.evidence) or "it steals credentials")[3:] + "."
        elif label == "phishing" and (where := self._cred_clause(c.evidence)):
            reason = reason.rstrip(".") + f"; {where}."
        elif label == "genuine" and any(e["finding"] == "credentials_stay_in_family" for e in c.evidence):
            reason = reason.rstrip(".") + "; the login stays in the family."
        closeness = None
        if brand is not None:
            closeness = 1.0 if genuine else tricks.closeness if tricks.closeness is not None else \
                tricks.per_brand.get(brand.id, 0.0)
        cf = self._counterfactual(c, label, reading, tricks, fam, page, page_signal and not signal, leak) \
            if counterfactual else None
        meta_extra = {} if use_certs else {"checks_off": CERT_CHECKS}
        src = next((e["details"].get("page_source") for e in c.evidence if e["tool"] == "page_inspector"), None)
        note = ("Page evidence comes from a local fixture: a clone generated from a saved genuine page, rendered in "
                "the sandbox (demo/fixtures)." if src == "generated_clone" else
                "Page evidence comes from a local mock fixture (demo/fixtures).")
        c.step(t_ms=c.now(), kind="final_verdict", label=label, risk_before=c.risk, risk_after=c.risk,
               message=f"{label.upper().replace('_', ' ')}: {reason}")
        return {
            "schema_version": CONTRACT_VERSION, "domain": reading.host,
            "input": {"raw": raw, "display": reading.display, "source": source},
            "owner": reading.owner, "target_brand": brand_ref(brand),
            "closeness": None if closeness is None else round(float(closeness), 4),
            "risk_score": c.risk, "confidence": confidence, "label": label, "reason": reason,
            "hard_rule": hard_rule, "counterfactual": cf, "timings_ms": c.timings(),
            "stages": list(c.stages.values()), "evidence": c.evidence, "trace": c.trace,
            "meta": {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                     "engine_version": ENGINE, "mock": bool(probe_res and probe_res.fixture), **meta_extra,
                     **({"notes": note} if probe_res and probe_res.fixture else {})},
        }

    # ------------------------------------------------------------------ stage 2 ---

    def _standard(self, c, reading, tricks, fam, brand, genuine, signal, ct: bool = False, ct_network: bool = False):
        jobs = {}
        start = c.now()
        c.ct_res = None
        if signal and tricks.genuine:
            from doppel.perception.renderer import human_eye_renderer  # needs the `tricks` extra (Pillow)

            jobs["human_eye_renderer"] = _POOL.submit(
                human_eye_renderer, reading.display, tricks.genuine, tricks.brand, None,
                tricks.closeness, tricks.brand_token, self.render_dir, reading.host)
        if not genuine and self.risk_model is not None:    # H1 decides genuine names; ML adds nothing there
            jobs["risk_model"] = _POOL.submit(risk.risk_model, reading.display, None, self.risk_model)
        jobs["page_probe"] = _POOL.submit(page_probe, reading.host, None, self.fixtures, brand_ref(brand), genuine)
        if ct:              # CT logs only (a third party): never a connection to the suspect
            jobs["ct_history"] = _POOL.submit(ct_history, reading, brand, self.reg, None,
                                              ct_network and not cert_store.offline())
        results = {name: f.result() for name, f in jobs.items()}
        probe_res, page = None, None
        if "ct_history" in results and not ct_network and not results["ct_history"][0].checked:
            del results["ct_history"]    # batch or replay with no cached CT record: say nothing rather than "not checked"
        for name in ("human_eye_renderer", "risk_model", "page_probe", "ct_history"):   # fixed order: deterministic trace
            if name not in results:
                continue
            info, items = results[name]
            for it in items:                                  # IDs are allocated here, in trace order
                it["evidence_id"] = c.ids()
            if name == "page_probe":
                probe_res, page = info, items[0]["finding"]
                msg = f"Page Probe: {items[0]['summary']}"
                args = {"domain": reading.host}
            elif name == "risk_model":
                msg = f"Risk Model: {items[0]['summary']}"
                args = {"domain": reading.host, "model_input": info.host}
            elif name == "ct_history":
                c.ct_res = info
                msg = "CT History: " + " ".join(it["summary"] for it in items)
                args = {"domain": reading.owner, "include_subdomains": True, "network": ct_network,
                        "via": "CT logs (third party)"}
            else:
                msg = f"Human-Eye Renderer: {items[0]['summary']}"
                args = {"candidate": reading.display, "genuine": tricks.genuine, "view": "sms"}
            c.tool("standard", name, args, start, items, msg)
        return probe_res, page

    # ------------------------------------------------------------------ stage 3 ---

    def _deep(self, c, reading, brand, genuine) -> None:
        """Render the fixture page once in the sandbox, then Page Inspector || Vision AI || the Credential Tracker's
        sessions; the tracker's evidence is read last (it needs the brand the page claims). Fixed trace order."""
        from doppel.deep import in_family_of
        from doppel.deep.inspector import page_inspector
        from doppel.deep.sandbox import sandbox
        from doppel.deep.tracker import credential_tracker
        from doppel.deep.vision import vision_ai

        sb = sandbox()
        start = c.now()
        render = sb.render_fixture(reading.host)
        if render is None:
            raise RuntimeError("no fixture page to render")
        fam_of = lambda b, h: in_family_of(self.reg, b, h, certs=True)   # noqa: E731
        jobs = {"page_inspector": _POOL.submit(page_inspector, render, sb, brand, genuine, fam_of,
                                               self._brands.__getitem__, None),
                "vision_ai": _POOL.submit(vision_ai, render, reading.owner, self.reg.brands, fam_of, None),
                # a proven family member is only confirmed (one session, C14): we don't test logins on a genuine site
                "tracking": _POOL.submit(sb.track_fixture, reading.host, 1 if genuine else 2)}
        results = {}
        for name, f in jobs.items():
            try:
                results[name] = f.result()
            except Exception as exc:                  # noqa: BLE001 - one tool failing must not sink the others
                if name != "tracking":
                    raise
                results[name] = exc
        page_meta = {"page_source": render.source.get("source"), "clone_of": render.source.get("clone_of"),
                     "kit_edits": [t["kind"] for t in render.source.get("transforms", [])], "sandbox": render.sandbox,
                     "render_ms": render.ms}
        for name in ("page_inspector", "vision_ai"):
            _, items = results[name]
            for it in items:
                it["evidence_id"] = c.ids()
            if name == "page_inspector":
                items[0]["details"].update(page_meta)
                items[0]["duration_ms"] = round(render.ms + items[0].get("duration_ms", 0.0), 3)
                msg = "Page Inspector: " + " ".join(it["summary"] for it in items)
                args = {"domain": reading.host, "views": ["desktop 1280x800", "mobile 390x844"]}
            else:
                claim = results[name][0]
                msg = "Vision AI: " + " ".join(it["summary"] for it in items)
                args = {"screenshot": render.desktop, "model": claim.model or claim.method,
                        "hidden_text_removed": len(render.hidden_text)}
            c.tool("deep", name, args, start, items, msg)

        # ---- Credential Tracker (C14/C15): judged against the brand from the name, else the page's own claim,
        # else the genuine page it copies.
        session = results["tracking"]
        if isinstance(session, Exception) or session is None:
            why = (f"{type(session).__name__}: {str(session)[:100]}" if isinstance(session, Exception)
                   else "no page to submit")
            c.step(t_ms=c.now(), kind="policy", message=f"Credential Tracker not run ({why}); verdict from the other evidence.")
            return
        deep = [e for e in c.evidence if e["stage"] == "deep"]
        page_brand = next((e["target_brand"]["id"] for e in deep if e["finding"] in
                           ("claimed_brand_mismatch", "claimed_brand_matches_owner")), None) or \
            next((e["target_brand"]["id"] for e in deep if e["finding"] in ("visual_match", "matches_genuine_snapshot")), None)
        tbrand = brand or (self._brands.get(page_brand) if page_brand else None)
        _, items = credential_tracker(session, reading.host, reading.owner, tbrand, genuine, fam_of, None,
                                      confirm_only=genuine)
        for it in items:
            it["evidence_id"] = c.ids()
        n = len(session["attempts"])
        c.tool("deep", "credential_tracker",
               {"url": session["url"], "sessions": n, "dummy_credentials": True, "judged_against": tbrand.id if tbrand else None},
               start, items, "Credential Tracker: " + (
                   f"made-up details typed and submitted ({n} session{'s' if n > 1 else ''}); "
                   f"{self._cred_clause(items)[3:]}." if self._cred_clause(items) else items[0]["summary"]))

    @staticmethod
    def _cred_clause(evidence) -> str | None:
        """'it sends what you type straight to Telegram and to x.top, accepts any password, then bounces ...'."""
        f = {}
        for e in evidence:
            if e["tool"] == "credential_tracker" and e["points_to"] == "phishing":
                f.setdefault(e["finding"], e)
        sends = [f"straight to {CHANNEL[e['details']['channel']]}" for k, e in f.items() if k in fusion.DIRECT_FINDINGS]
        if (e := f.get("credentials_to_foreign_domain")) is not None:
            hosts = ["its own server" if d.get("relation") in ("same_origin", "same_owner") else d["host"]
                     for d in e["details"].get("destinations", [])
                     if not d.get("in_brand_family") and d.get("channel") not in CHANNEL]
            if hosts:
                sends.append("to " + ", ".join(dict.fromkeys(hosts)))
        parts = (["sends what you type " + " and ".join(sends)] if sends else [])
        if "accepts_any_credentials" in f:
            parts.append("accepts any password")
        if (e := f.get("redirects_to_real_brand")) is not None:
            from urllib.parse import urlsplit
            parts.append(f"then bounces you to the real {urlsplit(e['details']['redirect_to']).hostname}")
        return "it " + ", ".join(parts) if parts else None

    @staticmethod
    def _deep_provisional(label, evidence) -> str:
        found = {e["finding"] for e in evidence if e["stage"] == "deep"}
        if label == "genuine":
            return ("Genuine: the page matches the brand's saved page, its owner is in the family"
                    + (", and its login stays in the family." if "credentials_stay_in_family" in found else "."))
        if found & fusion.LEAVE_FINDINGS and label != "phishing":
            return "The login sends what you type outside the brand's family."
        if found & {"direct_exfil_telegram", "direct_exfil_discord", "direct_exfil_google_forms"}:
            return "The page sends what you type straight to an attacker's channel."
        if PAGE_CLAIM in found and "credentials_to_foreign_domain" in found:
            return "The page presents itself as a brand its owner doesn't belong to, and the password leaves that brand's family."
        if "accepts_any_credentials" in found:
            return "The page accepts any made-up password."
        if PAGE_CLAIM in found:
            return "The page presents itself as a brand its owner doesn't belong to" + (
                ", and asks for credentials." if "asks_sensitive" in found else ".")
        if "visual_match" in found:
            return "The page copies a genuine brand page."
        return "The page doesn't copy or claim a protected brand."

    @staticmethod
    def _standard_provisional(genuine, signal, review_host, page, risk):
        if genuine:
            return "genuine", "Genuine: nothing on the page contradicts the ownership proof."
        if signal and page in fusion.EMPTY_PAGE_FINDINGS:
            return "sleeper", "Sleeper: a brand look-alike with no live page yet."
        if page in fusion.CREDENTIAL_FINDINGS:
            return "suspicious", "Suspicious: a live page asks for credentials."
        if signal or review_host:
            return "suspicious", "Suspicious by name; the page evidence doesn't settle it."
        return "benign", "Benign: no brand signal and nothing alarming on the page."

    # ------------------------------------------------------------------ text ---

    @staticmethod
    def _cert_reason(brand, evidence) -> str:
        e = next((e for e in evidence if e["finding"] in ("certificate_san_link", "certificate_organisation_match")), None)
        if e and e["finding"] == "certificate_san_link":
            d = e["details"]
            return (f"A proven {brand.name} address (certificate): {brand.name}'s own certificate lists "
                    f"'{d['matched_san']}' next to '{(d.get('linked_to') or ['a proven name'])[0]}'.")
        if e:
            return (f"A proven {brand.name} address (certificate): its {e['details'].get('validation')} certificate "
                    f"names '{e['details']['organisation']}', {brand.name}'s legal name.")
        return f"A proven {brand.name} address (certificate)."

    @staticmethod
    def _cert_extra(evidence) -> str | None:
        """What the certificates add to a review: who the validated company is, whether it's armed."""
        out = []
        for e in evidence:
            if e["finding"] == "certificate_organisation_other":
                out.append(f"its certificate names a different company, '{e['details']['organisation']}'")
            elif e["finding"] == "armed":
                n = e["details"]["count"]
                out.append(f"armed: {n} certificate{'s' if n != 1 else ''} since {e['details']['first_seen'][:10]}")
            elif e["finding"] == "certificate_platform_only":
                out.append(f"the padlock is {e['details']['platform']}'s, not the tenant's")
        return "; ".join(out) or None

    @staticmethod
    def _quick_reason(label, brand, tricks, fam, by_cert: bool = False):
        if label == "genuine":
            how = " (proven by its certificate)" if by_cert else ""
            return f"Genuine: proven {brand.name} family{how}. Checking the page in later stages."
        if label == "benign":
            return "Benign by name: it resembles no protected brand."
        if fam.status == "restricted_unlisted":
            return f"Suspicious: a vetted-registry name that mentions {brand.name} but isn't on its list."
        if fam.status == "user_content":
            return f"Suspicious: hosted on {brand.name}'s user-content platform, where anyone can publish."
        words = ", ".join(TRICK_WORDS.get(t, t) for t in tricks.tricks) or "a close look-alike name"
        return f"Suspicious: {words}, imitating {brand.name}."

    @staticmethod
    def _reason(label, brand, tricks, fam, probe_res, page, reading):
        name = brand.name if brand else ""
        words = ", ".join(TRICK_WORDS.get(t, t) for t in tricks.tricks) or "a close look-alike name"
        if label == "genuine":
            return f"A proven {name} address ({' + '.join(fam.proofs_matched).replace('_', ' ')})."
        if label == "sleeper":
            return f"Imitates {name} with {words}; registered but {'parked' if page == 'parked' else 'not set up'}: re-check daily."
        if label == "phishing":
            asks = ", ".join(probe_res.asks_for) if probe_res else "credentials"
            return f"Imitates {name} with {words}, and a live page on {reading.owner} asks for {asks}."
        if label == "needs_review":
            if fam.status == "restricted_unlisted":
                return f"Under a vetted registry and names {name}, but isn't on {name}'s official list: confirm with the brand."
            if fam.status == "user_content":
                return f"On {name}'s user-content platform ({reading.host}): anyone can publish there, so the page decides."
            if brand is None:
                return "No brand in the name, but a live login form: it could be a brand-less clone, and the page didn't settle it."
            if page == "not_probed":
                return f"Imitates {name} with {words}; the page wasn't checked (names only), so a person should review it."
            if page == "live_no_credentials":
                return f"Imitates {name} with {words}, but the live page asks for nothing."
            return f"Imitates {name} with {words}; the evidence doesn't settle it."
        if tricks.email_shaped:
            return f"Spells an email address ({tricks.email_shaped}): a mailbox name registered as a domain, not an imitation."
        return ("Resembles no protected brand." + (f" '{tricks.substring_hit}' appears only inside other words."
                                                   if tricks.substring_hit else ""))

    @staticmethod
    def _page_reason(label, brand, reading, evidence) -> str:
        """Reason for a verdict whose brand came from the page itself (the name names no brand)."""
        f = {e["finding"]: e for e in evidence if e["stage"] == "deep"}
        copy = f.get("visual_match")
        asks = f.get("asks_sensitive")
        parts = [f"The name names no brand, but the page presents itself as {brand.name} and {reading.owner} isn't {brand.name}'s"]
        if copy:
            parts.append(f"it copies {brand.name}'s genuine page ({copy['score']:.0%})")
        if asks:
            parts.append("asks for " + ", ".join(a.replace("_", " ") for a in asks["details"]["asks_for"]))
        text = "; ".join(parts) + "."
        return text if label == "phishing" else text + " A person should confirm."

    # ------------------------------------------------------------------ what-if ---

    def _counterfactual(self, c, label, reading, tricks, fam, page, page_driven: bool = False,
                        leak: list | None = None) -> dict | None:
        if leak:                                          # a proven address whose login leaves the family
            lid = [e["evidence_id"] for e in leak]
            rest = [e for e in c.evidence if e["evidence_id"] not in lid]
            return {"change": "the credential leak undone (the login stays in the family)", "undone_evidence_ids": lid,
                    "label": "genuine", "risk_score": fusion.risk(rest),
                    "summary": "Would be GENUINE if its login stayed in the family: the ownership proof holds; the leak blocks it."}
        trick_ids = [e["evidence_id"] for e in c.evidence
                     if (e["tool"] == "trick_detector" and e["points_to"] == "phishing")
                     or (e["tool"] == "family_verifier" and e["points_to"] == "phishing")
                     or e["tool"] == "human_eye_renderer"]
        if label == "genuine":
            gid = [e["evidence_id"] for e in c.evidence if e["finding"] in PROOF_FINDINGS and e["points_to"] == "genuine"]
            rest = [e for e in c.evidence if e["evidence_id"] not in gid]
            r = max(0.5, fusion.risk(rest))   # an unproven brand address is at best a coin toss
            if not fam.genuine:               # proven by the certificate: the what-if is the --no-cert view
                return {"change": "certificate proof removed (the same name with Certificate Forensics off)",
                        "undone_evidence_ids": gid, "label": "needs_review", "risk_score": round(r, 3),
                        "summary": "Would be NEEDS REVIEW without its certificate: no list or rule could prove it."}
            return {"change": "ownership proof removed (not on the list, not under a brand or vetted ending)",
                    "undone_evidence_ids": gid, "label": "needs_review", "risk_score": round(r, 3),
                    "summary": "Would be NEEDS REVIEW without the ownership proof: the proof, not the looks, makes it green."}
        if (label == "needs_review" or page_driven) and tricks.brand is None and page in fusion.CREDENTIAL_FINDINGS:
            pid = [e["evidence_id"] for e in c.evidence if e["tool"] == "page_probe" or e["stage"] == "deep"]
            rest = [e for e in c.evidence if e["evidence_id"] not in pid]
            return {"change": "judged by the name only (page evidence removed)", "undone_evidence_ids": pid,
                    "label": "benign", "risk_score": fusion.risk(rest),
                    "summary": "Would be BENIGN judged by the name alone, which is all a name-only tool sees."}
        if label == "benign" or not trick_ids or not tricks.brand_signal:
            return None
        for change, domain in self._undo(reading, tricks):
            if not domain or domain == reading.host:
                continue
            try:
                v = self.investigate(domain, source="file", counterfactual=False)
            except ValueError:
                continue
            if v["label"] != label:
                return {"change": change, "undone_evidence_ids": trick_ids, "counterfactual_domain": v["domain"],
                        "label": v["label"], "risk_score": v["risk_score"],
                        "summary": f"Would be {v['label'].upper().replace('_', ' ')} as {v['input']['display']}: {change}."}
        rest = [e for e in c.evidence if e["evidence_id"] not in trick_ids]
        alt = "benign" if label != "benign" else "needs_review"
        return {"change": "the naming tricks undone", "undone_evidence_ids": trick_ids, "label": alt,
                "risk_score": fusion.risk(rest), "summary": f"Would be {alt.upper()} without the look-alike name evidence."}

    @staticmethod
    def _undo(reading, tricks):
        """Candidate what-if names, most specific first."""
        best = tricks.best
        owner_suffix = reading.owner.split(".", 1)[1] if "." in reading.owner else ""
        out = []
        if {"level_squat", "trust_signal_mimicry"} & set(tricks.tricks):
            out.append((f"the borrowed '{tricks.genuine}' removed (only the real owner left)", reading.owner))
        if "combosquat" in tricks.tricks and tricks.brand_token:
            rest = [t for t in tricks.core.split("-") if t != tricks.brand_token]
            rest = [t.replace(tricks.brand_token, "") for t in rest]
            rest = [t for t in rest if t]
            if rest:
                out.append((f"brand token '{tricks.brand_token}' removed", "-".join(rest) + "." + owner_suffix))
        if best and best.alignment and best.alignment.edits and best.via not in ("level_squat", "trust_signal"):
            swaps = "; ".join(f"{e['candidate'] or '∅'}→{e['genuine'] or '∅'}" for e in best.alignment.edits)
            out.append((f"{swaps} undone", best.name + "." + owner_suffix if "." not in best.name else best.name))
        if "tld_swap" in tricks.tricks and tricks.genuine:
            out.append((f"ending changed to {tricks.genuine}", tricks.genuine))
        return out


_BRAIN: Brain | None = None


def investigate(raw: str, source: str = "paste", render_dir: Path | None = None, certs: bool | None = None) -> dict:
    """One verdict with the default registry (module-level brain, reused)."""
    global _BRAIN
    if _BRAIN is None or _BRAIN.render_dir != render_dir:
        _BRAIN = Brain(render_dir=render_dir)
    return _BRAIN.investigate(raw, source, certs=certs)
