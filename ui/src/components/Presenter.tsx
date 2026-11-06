// P14 Presenter view: one question, one search bar; Enter opens "the space", where every Doppel feature that ran on
// this name rises in as a tile, from the real verdict (no mock numbers). The dense Analyst view stays as it was.
import { useCallback, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import "../presenter.css";
import { api, ApiError } from "../lib/api";
import { BrandsCtx } from "../lib/context";
import { packCase, packContext, packIndex, type ArenaCell, type BaselineRow } from "../lib/pack";
import {
  ev, ev1, exfilFlow, generic, heat, heatColour, isBad, isKit, islandLayout, LABEL_TEXT, nodeTone, NODES, pickCampaign,
  segments, trickName, type Seg,
} from "../lib/presenter";
import type { Campaign, LiveSummary, Source, Stage, Verdict } from "../lib/types";

export type NavTarget = "explore" | "live" | "radar" | "fool";

/** The finale cases (docs/finale-examples.md §0). Kits are our own localhost fixtures, so they use the gallery source. */
const CASES: { d: string; tag: string; source: Source }[] = [
  { d: "echallan.parivahan.gov.in.pay-fine.icu", tag: "the opener", source: "gallery" },
  { d: "google.co.in", tag: "looks fake, isn't", source: "paste" },
  { d: "in-echallan.online", tag: "a real attacker", source: "paste" },
  { d: "kx72-secure.top", tag: "no brand in the name", source: "gallery" },
  { d: "hdfc-pan-up-date2.web.app", tag: "Google's padlock", source: "paste" },
];
const KITS = new Set(["echallan.parivahan.gov.in.pay-fine.icu", "kx72-secure.top", "xn--pytm-53d.com", "kyc-helpdesk.online"]);
const TONE: Record<string, string> = { phishing: "var(--rose)", sleeper: "var(--rose)", needs_review: "var(--amber)", genuine: "var(--mint)", benign: "var(--mint)" };
const NOTE_COL: Record<string, string> = { own: "var(--rose)", brand: "var(--acc)", mut: "var(--amber)", proved: "var(--mint)", dec: "var(--mute)", plain: "var(--mute)" };
const HOOD: Record<string, string> = {
  pipe: "The brain is a deterministic policy, not an LLM: it escalates Quick → Standard → Deep only while evidence is unresolved.",
  Q1: "Address Reader · Public Suffix List (incl. the private section) → the registrable owner · C1, C3",
  Q2: "Family Verifier · proofs: restricted registry, brand-owned TLD, official list, certificate SANs · C2",
  Q3: "Trick Detector · 16 tricks, glyph-cost edit distance, combo words, TLD priors · C4, C5, C6",
  Q4: "Certificate Forensics + CT history · SAN links, validated organisation, first certificate (armed) · C16, C17",
  S1: "Human-Eye Renderer · renders the name as a phone shows it and compares with SSIM · C7",
  S2: "Risk Model · PhiUSIIL-trained logistic regression, calibrated; a supporting signal only · C8",
  S5: "Campaign Radar · naming template + certificate recipe + timing → islands · C18",
  deep: "Page Inspector · Vision AI · Credential Tracker, in a sandboxed browser on our own fixture pages; never a real suspect · C10–C15",
  gen: "Each row is computed from this verdict's own evidence (no hand-typed cells). Levenshtein uses a stated 0.8 cut-off.",
  whatif: "Counterfactual: the brain re-scores with the named evidence undone.",
  live: "P12 collector: the public CT stream → the brain → the catch store.",
  case: "Grounded narration: every sentence must cite an evidence id, or it is dropped.",
};

const norm = (s: string) => s.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/?#].*$/, "").replace(/^www\./, "");
const chip = (c: string, t: ReactNode) => <span className={`chip ${c}`}>{t}</span>;
const domSize = (n: number) => `${Math.max(17, Math.min(34, 34 - (n - 20) * 0.5))}px`;

interface Shown { label: string; risk: number; segs: Seg[]; reason: string; rule: string }

export default function Presenter({ live, ready = true, offline = false, onNav }:
  { live: boolean; ready?: boolean; offline?: boolean; onNav: (t: NavTarget) => void }) {
  const brands = useContext(BrandsCtx);
  const [q, setQ] = useState("");
  const [docked, setDocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [v, setV] = useState<Verdict | null>(null);
  const [vOff, setVOff] = useState<Verdict | null>(null);
  const [certOn, setCertOn] = useState(true);
  const [whatOn, setWhatOn] = useState(false);
  const [still, setStill] = useState(false);
  const [sheet, setSheet] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [radar, setRadar] = useState<Campaign[]>([]);
  const [sum, setSum] = useState<LiveSummary | null>(null);
  const [base, setBase] = useState<BaselineRow[] | null>(null);
  const [replayAt, setReplayAt] = useState<string | null>(null);
  const [arena, setArena] = useState<Record<string, ArenaCell> | null>(null);
  const slot = useRef<HTMLDivElement>(null);
  const bar = useRef<HTMLFormElement>(null);
  const [anim, setAnim] = useState(false);

  // the search bar sits over the landing slot, then glides to the top bar (one element, so it really moves)
  const place = useCallback(() => {
    const s = slot.current, b = bar.current;
    if (!b || (!docked && !s)) return;
    if (docked || !s) {
      const w = Math.max(260, Math.min(600, innerWidth - 200 - 480));   // between the logo and the nav pills
      Object.assign(b.style, { position: "fixed", left: "190px", top: "14px", width: `${w}px`, height: "52px" });
    } else {
      const r = s.getBoundingClientRect();
      Object.assign(b.style, { position: "absolute", left: `${r.left + scrollX}px`, top: `${r.top + scrollY}px`, width: `${r.width}px`, height: `${r.height}px` });
    }
  }, [docked]);
  useLayoutEffect(() => { place(); addEventListener("resize", place); return () => removeEventListener("resize", place); }, [place]);
  useEffect(() => { document.fonts?.ready.then(place); }, [place]);

  useEffect(() => {
    packContext().then((c) => {
      if (c) setArena(c.arena);
      if (c && !live) {                                  // the API is down: the recorded radar and live summary
        setRadar(c.campaigns.campaigns);
        setSum(c.live && "totals" in c.live.summary ? c.live.summary as LiveSummary : null);
      }
    });
    if (!live) return;
    api.campaigns().then((r) => setRadar(r.campaigns)).catch(() => undefined);
    api.live("live").then((r) => setSum("totals" in r.summary ? r.summary as LiveSummary : null)).catch(() => undefined);
  }, [live]);

  const say = (m: string) => { setToast(m); setTimeout(() => setToast((t) => (t === m ? null : t)), 3800); };

  const run = async (raw: string) => {
    const d = norm(raw);
    if (!d) return;
    setQ(d);
    const rec = live ? null : await packCase(raw);
    if (!live && !rec) { say("The engine isn't running: only the recorded stage cases can be shown (start: python -m doppel.cli serve)."); return; }
    if (!docked) {
      const b = bar.current!, r = b.getBoundingClientRect();
      Object.assign(b.style, { position: "fixed", left: `${r.left}px`, top: `${r.top}px` });
      void b.offsetWidth;
      setAnim(true); setDocked(true); scrollTo({ top: 0 });
    }
    const source = CASES.find((c) => c.d === d)?.source ?? (KITS.has(d) ? "gallery" : "paste");
    const reset = () => { setCertOn(true); setWhatOn(false); setStill(false); setSheet(null); };
    if (rec) {                                           // REPLAY: the verdict recorded by build_pack.py
      reset(); setVOff(rec.verdict_certs_off ?? null); setBase(rec.baselines); setV(rec.verdict);
      packIndex().then((i) => setReplayAt(i?.generated_at ?? "recorded"));
      return;
    }
    setBusy(true);
    try {
      const verdict = await api.investigate(d, source, true);
      reset(); setReplayAt(null); setVOff(null); setBase(null); setV(verdict);
      api.baselines(verdict).then((r) => setBase(r.rows)).catch(() => setBase(null));
      if (verdict.evidence.some((e) => e.criterion === "C16" && e.points_to === "genuine")) {
        api.investigate(d, source, false).then(setVOff).catch(() => undefined);
      }
    } catch (e) {
      say(e instanceof ApiError ? e.message : String(e));
    } finally { setBusy(false); }
  };

  // ?d=<domain> opens straight into the space (deep link for the backup video and screenshots)
  const deep = useRef(new URLSearchParams(location.search).get("d"));
  useEffect(() => { if ((live || ready) && deep.current) { const d = deep.current; deep.current = null; run(d); } });

  const home = () => { setDocked(false); setAnim(false); setV(null); setQ(""); };
  const flip = (f: () => void) => { setStill(true); f(); };

  return (
    <div className={`pz ${docked ? "docked" : ""}`}>
      <div className="bg"><i className="orb o1" /><i className="orb o2" /><i className="orb o3" /><i className="orb o4" /><div className="grain" /></div>
      <header className="ptop">
        <div className="logo" onClick={home}><div className="mark"><i /></div>Doppel</div>
        <nav className="navr">
          <button className="ppill" onClick={() => onNav("live")}><span className={`pdot ${live ? "" : "off"}`} />Live Hunt</button>
          <button className="ppill" onClick={() => onNav("radar")}>Campaign Radar</button>
          <button className="ppill" onClick={() => onNav("fool")}>Try to fool it</button>
          <button className="ppill" onClick={() => onNav("explore")}>Analyst view</button>
        </nav>
      </header>

      {!docked && (
        <section className="landing">
          <div className="kicker glass"><span className={`pdot ${live ? "" : "off"}`} />{!live ? "Engine not running · recorded stage cases (REPLAY)" : offline ? "Offline mode · every check answers from its cache" : "Reading the world's new certificates"}</div>
          <h1>Is this link <span>who it says it is?</span></h1>
          <p className="lede">Paste any address from an SMS, email or ad. Doppel proves who owns it, names the trick, and shows every step.</p>
          <div className="slot" ref={slot} />
          <div className="tries">
            {CASES.map((c) => <div key={c.d} className="try" onClick={() => run(c.d)}><small>{c.tag}</small>{c.d}</div>)}
          </div>
          <div className="stats">
            {sum?.totals.certs ? <div className="stat glass"><b>{fmtBig(sum.totals.certs)}</b><span>certificates read live in {sum.hours_watched.toFixed(1)} h</span></div> : null}
            {sum?.totals.flags ? <div className="stat glass"><b>{sum.totals.flags.toLocaleString()} <small style={{ fontSize: 14, color: "var(--mute)" }}>vs {(sum.totals.naive ?? 0).toLocaleString()}</small></b><span>Doppel flags vs keyword alerts</span></div> : null}
            <div className="stat glass"><b>0 / 2,548</b><span>false alarms on benign names (arena)</span></div>
          </div>
        </section>
      )}

      <form ref={bar} className={`search glass ${anim ? "anim" : ""}`} autoComplete="off" onSubmit={(e) => { e.preventDefault(); run(q); }}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z" /><path d="M9 12l2 2 4-4" /></svg>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Paste a link… e.g. echallan.parivahan.gov.in.pay-fine.icu" spellCheck={false} />
        <button className="go" aria-label="Investigate">{busy ? <span className="spin" /> :
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M5 12h14M13 6l6 6-6 6" /></svg>}</button>
      </form>

      {docked && v && <Space key={v.domain + v.meta.generated_at} v={v} vOff={vOff} certOn={certOn} whatOn={whatOn} still={still} radar={radar}
        sum={sum} brands={brands} base={base} arena={arena} replayAt={replayAt} onCert={() => flip(() => setCertOn((x) => !x))} onWhat={() => flip(() => setWhatOn((x) => !x))}
        onOpen={setSheet} onNav={onNav} sheet={sheet} />}
      {docked && !v && busy && <div className="space"><p className="foot" style={{ marginTop: 120 }}>Investigating…</p></div>}

      <div className="toast glass" style={{ opacity: toast ? 1 : 0 }}>{toast}</div>
    </div>
  );
}

const fmtBig = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}k` : String(n));

interface SpaceProps {
  v: Verdict; vOff: Verdict | null; certOn: boolean; whatOn: boolean; still: boolean; radar: Campaign[]; sum: LiveSummary | null;
  brands: Record<string, import("../lib/types").BrandInfo>; base: BaselineRow[] | null; arena: Record<string, ArenaCell> | null;
  replayAt: string | null; onCert: () => void; onWhat: () => void; onOpen: (id: string | null) => void;
  onNav: (t: NavTarget) => void; sheet: string | null;
}

function Space({ v, vOff, certOn, whatOn, still, radar, sum, brands, base, arena, replayAt, onCert, onWhat, onOpen, onNav, sheet }: SpaceProps) {
  const cf = v.counterfactual;
  const proof = v.evidence.find((e) => e.criterion === "C16" && e.points_to === "genuine");
  const view = !certOn && vOff ? vOff : v;
  const shown: Shown = whatOn && cf ? {
    label: cf.label, risk: cf.risk_score, reason: cf.summary, rule: `What-if · ${cf.change}`,
    segs: [{ text: cf.counterfactual_domain ?? v.domain, kind: isBad(cf.label) ? "own" : "proved", note: LABEL_TEXT[cf.label] ?? cf.label, up: false }],
  } : {
    label: view.label, risk: view.risk_score, reason: view.reason, segs: segments(view),
    rule: !certOn && vOff ? "Ablation · Certificate Forensics off" : view.hard_rule ? `Hard rule · ${view.hard_rule.description}` : `Confidence ${view.confidence}`,
  };
  const skipWhy = (st: Stage) => v.stages.find((s) => s.stage === st)?.skip_reason ?? "Not needed for this name.";
  const brand = v.target_brand?.name;

  // ---- tiles ----
  const tiles: { id: string; cls: string; ic: string; q: string; tt?: string; skip?: string; body?: ReactNode }[] = [];
  const c1 = ev1(v, "C1"), c2 = ev1(v, "C2"), c4 = ev1(v, "C4"), c5 = ev1(v, "C5"), c7 = ev1(v, "C7"), c8 = ev1(v, "C8"), c17 = ev1(v, "C17");

  tiles.push(cf ? { id: "whatif", cls: "s4", ic: "↺", q: "What if…", body: <>
    <p className="tline" style={{ marginTop: 0 }}>{cf.change}</p>
    <div style={{ font: "600 15px var(--mono)", margin: "10px 0" }}>{cf.counterfactual_domain ?? v.domain}</div>
    {chip(isBad(cf.label) ? "c-warn" : "c-good", `${LABEL_TEXT[cf.label] ?? cf.label} · ${cf.risk_score.toFixed(3)}`)}
    <p className="tline">{cf.summary}</p>
    <button className="toggle" onClick={(e) => { e.stopPropagation(); onWhat(); }}><span className={`sw ${whatOn ? "on" : ""}`} />{whatOn ? "Showing the what-if" : "Show it in the hero"}</button>
  </> } : { id: "whatif", cls: "s4", ic: "↺", q: "What if…", skip: "No what-if: nothing in this verdict depends on one piece of evidence." });

  tiles.push({ id: "pipe", cls: "s12", ic: "⟶", q: "The investigation · the brain escalates only as far as it needs", body: <Pipe v={v} /> });

  tiles.push({ id: "Q1", cls: "s4", ic: "Q1", q: "Who really owns it?", tt: "C1 C3", body: <>
    <div style={{ font: "600 20px var(--mono)", letterSpacing: "-.4px", overflowWrap: "anywhere" }}>{v.owner ?? v.domain}</div>
    {c1?.details.public_suffix && <div style={{ marginTop: 8 }}>{chip("c-neu", `public suffix .${c1.details.public_suffix}${c1.details.private_suffix ? " (free hosting)" : ""}`)}</div>}
    <p className="tline">{c1?.summary}</p></> });

  tiles.push(!c2 || c2.finding === "no_brand_to_verify"
    ? { id: "Q2", cls: "s4", ic: "Q2", q: "Is it the brand's own family?", tt: "C2", skip: c2?.summary ?? "No brand to check." }
    : { id: "Q2", cls: "s4", ic: "Q2", q: "Is it the brand's own family?", tt: "C2", body: <>
        {chip(proof ? "c-good" : c2.points_to === "genuine" ? "c-good" : "c-bad", proof ? "in the family (certificate)" : c2.points_to === "genuine" ? "in the family" : "not in the family")}
        <p className="tline">{proof ? proof.summary : c2.summary}</p>
        {proof && <p className="tline" style={{ fontSize: 12 }}>The list alone said: {c2.summary}</p>}</> });

  tiles.push({ id: "Q3", cls: "s4", ic: "Q3", q: "Which trick is it using?", tt: "C4 C5 C6", body: <>
    <div className="pvrow" style={{ marginBottom: 12 }}>{chip(c5 ? "c-warn" : "c-neu", trickName(v))}
      {v.closeness != null && chip("c-neu", `closeness ${v.closeness.toFixed(2)}${c4?.details.genuine ? ` to ${c4.details.genuine}` : ""}`)}</div>
    <div className="heat">{heat(v).map((c, i) => <span key={i} style={{ background: heatColour(c.h) }}>{c.ch}</span>)}</div>
    <div className="plegend">matches the brand<i />foreign</div>
    <p className="tline">{(c5 ?? c4)?.summary}</p></> });

  const certBody = proof ? <>
    <div className="cert"><div className="pvrow" style={{ marginBottom: 10 }}>{chip(certOn ? "c-good" : "c-neu", certOn ? "proves ownership" : "check off")}</div>
      <dl className="pkv"><dt>Served at</dt><dd>{proof.details.seed_host}</dd><dt>Lists</dt><dd style={{ color: "var(--mint)", fontWeight: 600 }}>{proof.details.matched_san}</dd>
        <dt>Linked to</dt><dd>{(proof.details.linked_to ?? []).slice(0, 3).join(", ")}</dd><dt>SHA-256</dt><dd>{String(proof.details.cert_sha256 ?? "").slice(0, 16)}…</dd></dl></div>
    {vOff && <button className="toggle" onClick={(e) => { e.stopPropagation(); onCert(); }}><span className={`sw ${certOn ? "on" : ""}`} />Certificate check {certOn ? "on" : "off"}</button>}
  </> : c17 ? <div className="cert"><div className="pvrow" style={{ marginBottom: 10 }}>{chip(c17.points_to === "phishing" ? "c-bad" : "c-neu", c17.finding.replace(/_/g, " "))}{chip("c-neu", "padlock ✓ · proves nothing")}</div>
      <dl className="pkv"><dt>Issuers</dt><dd>{Object.keys(c17.details.issuers ?? {}).join(" + ") || "—"}</dd><dt>First cert</dt><dd>{fmtTime(c17.details.first_seen)}</dd>
        <dt>In CT logs</dt><dd>{c17.details.count} certificates</dd><dt>Validation</dt><dd>{Object.keys(c17.details.validation ?? {}).join(", ") || "—"}</dd></dl>
      <p className="tline">{c17.summary}</p></div> : null;
  const otherCert = ev(v, "C16").find((e) => e.finding !== "no_certificate_link" && e !== proof);
  tiles.push(certBody ? { id: "Q4", cls: "s5", ic: "Q4", q: "Does its certificate prove who it is?", tt: "C16 C17", body: <>{certBody}{otherCert && <p className="tline">{otherCert.summary}</p>}</> }
    : { id: "Q4", cls: "s5", ic: "Q4", q: "Does its certificate prove who it is?", tt: "C16 C17", skip: otherCert?.summary ?? ev1(v, "C16")?.summary ?? "No certificate evidence for this name." });

  tiles.push(c7 ? { id: "S1", cls: "s3", ic: "S1", q: "Would a person notice?", tt: "C7", body: <>
    <div className="pphone"><div className="pbubble">Action needed on your {brand ?? "account"}. Open: <a>{v.domain.length > 34 ? v.domain.slice(0, 33) + "…" : v.domain}</a></div></div>
    <p className="tline">{c7.summary}</p></> } : { id: "S1", cls: "s3", ic: "S1", q: "Would a person notice?", tt: "C7", skip: skipWhy("standard") });

  tiles.push(c8 ? { id: "S2", cls: "s4", ic: "S2", q: "What does the ML model say?", tt: "C8", body: <>
    <div className="pbig">{Number(c8.details.probability).toFixed(2)}</div>
    <div className="pbar"><b style={{ width: `${Number(c8.details.probability) * 100}%` }} /><u style={{ left: `${Number(c8.details.base_rate ?? 0.379) * 100}%` }} /></div>
    <div className="plegend" style={{ marginTop: 0 }}>0<span style={{ marginLeft: "31%" }}>base rate {Number(c8.details.base_rate ?? 0.379).toFixed(3)}</span><span style={{ marginLeft: "auto" }}>1</span></div>
    <p className="tline">{c8.summary.split(". Sup")[0]}. A supporting signal, never the verdict.</p></> }
    : { id: "S2", cls: "s4", ic: "S2", q: "What does the ML model say?", tt: "C8", skip: skipWhy("standard") });

  const pc0 = pickCampaign(v, radar);
  const pc = pc0 && (pc0.member || isBad(v.label)) ? pc0 : null;      // no "related" attacker island on a genuine name
  tiles.push(pc ? { id: "S5", cls: "s7", ic: "S5", q: "Is it part of a campaign?", tt: "C18", body: <>
    {pc.member ? chip("c-bad", `member · ${pc.c.strength}`) : chip("c-neu", "related island · same brand, not a member")}
    <Island c={pc.c} focus={pc.member ? (pc.c.members_ids.includes(v.domain) ? v.domain : v.owner) : null} />
    <p className="tline" style={{ marginTop: 0 }}>{pc.c.size} domains · template {pc.c.templates.join(", ") || "—"}{pc.c.recipe?.span_h != null ? ` · certificates within ${pc.c.recipe.span_h.toFixed(0)} h` : ""} · {pc.c.armed.length} armed</p>
    <button className="toggle" onClick={(e) => { e.stopPropagation(); onNav("radar"); }}>Open Campaign Radar →</button></> }
    : { id: "S5", cls: "s7", ic: "S5", q: "Is it part of a campaign?", tt: "C18", skip: radar.length ? "No campaign links this name or its brand." : "Campaign Radar data not loaded (run `doppel campaigns`)." });

  const gen = base ? base.map((r) => ({ name: r.name, says: r.detail, agrees: r.flagged == null ? null : r.flagged === isBad(v.label) }))
    : generic(v, brands);
  const lev = arena?.levenshtein;
  const mk = (a: boolean | null) => a === true ? <span className="pok">✓</span> : a === false ? <span className="no">✕</span> : <span className="na">–</span>;
  tiles.push({ id: "gen", cls: "s5", ic: "vs", q: "Generic tools on this name", body: <>
    <table className="score"><tbody>{gen.map((r) => <tr key={r.name}><td>{r.name}</td><td>{mk(r.agrees)}</td><td>{r.says}</td></tr>)}
      <tr><td>Doppel</td><td>{mk(true)}</td><td>{LABEL_TEXT[v.label]}, with the evidence above</td></tr></tbody></table>
    <p className="tline" style={{ fontSize: 11.5 }}>✓ same call as Doppel · ✕ the opposite call · – can't say{base ? "" : " · engine rows unavailable, derived from the verdict"}</p>
    {lev && <p className="tline"><b>In our arena</b>, Levenshtein flags <b>{lev.flagged} of {lev.of}</b> of the brands' own genuine addresses; Doppel flags <b>{arena?.doppel?.flagged ?? 0}</b>. It proves the family first.</p>}</> });

  const flow = exfilFlow(v);
  const dl = (crits: string[]) => v.evidence.filter((e) => crits.includes(e.criterion)).map((e) => <li key={e.evidence_id}>{e.summary}</li>);
  tiles.push(v.evidence.some((e) => e.stage === "deep") ? { id: "deep", cls: "s12", ic: "D", q: "Deep stage · the page, opened safely in a sandbox", tt: "C10–C15", body: <>
    {isKit(v) && <div className="pvrow" style={{ margin: "-4px 0 14px" }}>{chip("c-acc", "simulated kit · our own localhost fixture")}</div>}
    <div className="deep">
      <div className="psub"><h6>D1 · Does it copy the real page?</h6><ul>{dl(["C10", "C11"])}</ul></div>
      <div className="psub"><h6>D2 · Who does it claim to be?</h6><ul>{dl(["C12", "C13"])}</ul></div>
      <div className="psub"><h6>D3 · Where does the password go?</h6><ul>{dl(["C14", "C15"])}</ul></div>
    </div>
    {flow.length > 0 && <div className="flow">{flow.map((f, i) => <span key={i} className={f.hot ? "hot" : ""}>{f.text}</span>).flatMap((el, i) => i ? [<em key={"a" + i}>→</em>, el] : [el])}</div>}</> }
    : { id: "deep", cls: "s12", ic: "D", q: "Deep stage · the page, opened safely in a sandbox", tt: "C10–C15", skip: ev1(v, "C9")?.summary ?? skipWhy("deep") });

  tiles.push({ id: "live", cls: "s6", ic: "◉", q: "Live Hunt", body: <>
    <div style={{ font: "600 15px var(--disp)" }}>{c17 ? `First certificate ${fmtTime(c17.details.first_seen)} · ${c17.details.count} in CT logs` : isKit(v) ? "Our local kit: never in CT logs." : "Doppel reads every new certificate on the planet."}</div>
    {sum?.totals.certs ? <div className="pvrow" style={{ marginTop: 12 }}>{chip("c-neu", `${fmtBig(sum.totals.certs)} certificates read`)}{chip("c-neu", `${(sum.totals.flags ?? 0).toLocaleString()} flags vs ${(sum.totals.naive ?? 0).toLocaleString()} keyword alerts`)}{chip("c-neu", `${(sum.totals.genuine ?? 0).toLocaleString()} proven genuine`)}</div> : null}
    <button className="toggle" onClick={(e) => { e.stopPropagation(); onNav("live"); }}>Open Live Hunt →</button></> });

  tiles.push({ id: "case", cls: "s6", ic: "¶", q: "Case file", body: <CaseFile v={v} /> });

  const order = (i: number) => ({ ["--d" as string]: `${(0.12 + i * 0.06).toFixed(2)}s` });
  const tileEl = (t: (typeof tiles)[number], i: number) => (
    <section key={t.id} className={`ptile glass ${t.cls} ${t.skip ? "skip" : ""}`} style={order(i)} onClick={() => !t.skip && onOpen(t.id)}>
      <div className="th"><div className="pic">{t.ic}</div><div className="tq">{t.q}</div>{t.tt && <div className="ptt">{t.tt}</div>}</div>
      {t.skip ? <p className="tline">{t.skip}</p> : t.body}
    </section>
  );
  const open = tiles.find((t) => t.id === sheet && !t.skip);

  return (
    <main className={`space ${still ? "still" : ""}`}>
      <div className="grid">
        <section className="ptile glass s8 hero" style={order(0)}>
          <div style={{ minWidth: 0 }}>
            <div className="pvrow"><span className={`vpill v-${shown.label}`}>{LABEL_TEXT[shown.label] ?? shown.label}</span>{chip("c-neu", shown.rule)}{isKit(v) && chip("c-acc", "simulated kit")}{replayAt && chip("c-warn", `REPLAY · recorded ${fmtTime(replayAt)}`)}</div>
            <div className="reason">{shown.reason}</div>
            <div className="pdom" style={{ fontSize: domSize(shown.segs.reduce((n, s) => n + s.text.length, 0)) }}>
              {shown.segs.map((s, i) => <span key={i} className={`seg ${s.kind}`}>{s.text}<span className={`note ${s.up ? "up" : "dn"}`} style={{ color: NOTE_COL[s.kind] }}>{s.note}</span></span>)}
            </div>
            <div className="pvrow">{NODES.map((st) => { const on = st.nodes.some((n) => nodeTone(view, n.tool)); return <span key={st.stage}>{chip(on ? "c-acc" : "c-neu", `${on ? "●" : "○"} ${st.name}`)}</span>; })}
              {chip("c-neu", `${Math.round(view.timings_ms.total)} ms`)}</div>
          </div>
          <div className="ring" style={{ ["--c" as string]: TONE[shown.label] ?? "var(--acc)", ["--p" as string]: (shown.risk * 100).toFixed(1) }}>
            <div><b>{shown.risk.toFixed(2)}</b><span>risk score</span></div>
          </div>
        </section>
        {tiles.map((t, i) => tileEl(t, i + 1))}
      </div>
      <div className="foot">Every number on this screen is the brain's real output for {v.domain} · engine {v.meta.engine_version} · risk is a ranking score, not a probability</div>

      <div className={`veil ${open ? "on" : ""}`} onClick={() => onOpen(null)} />
      <div className={`sheet glass ${open ? "on" : ""}`}>
        {open && <>
          <button className="close" onClick={() => onOpen(null)}>✕</button>
          <section className="ptile"><div className="th"><div className="pic">{open.ic}</div><div className="tq">{open.q}</div></div>{open.body}</section>
          <div className="hood"><div>Under the hood · {HOOD[open.id] ?? ""}</div>
            {v.evidence.filter((e) => (open.tt ?? "").split(/[\s–]+/).includes(e.criterion)).map((e) =>
              <div key={e.evidence_id}>{e.evidence_id} · {e.criterion} · {e.finding} · points to {e.points_to} ({e.strength})</div>)}</div>
        </>}
      </div>
    </main>
  );
}

function Pipe({ v }: { v: Verdict }) {
  let k = 0;
  return (
    <div className="ppipe">{NODES.map((st) => (
      <div key={st.stage} className="stage"><h5>{st.name}{v.timings_ms[st.stage] != null ? ` · ${Math.round(v.timings_ms[st.stage]!)} ms` : ""}</h5>
        <div className="nodes">{st.nodes.map((n) => {
          const t = nodeTone(v, n.tool);
          return <div key={n.id} className={`node ${t ?? "skip"}`} style={{ ["--d" as string]: t ? `${(0.2 + k++ * 0.08).toFixed(2)}s` : "0s" }}><i /><b>{n.id}</b>{n.label}</div>;
        })}</div>
      </div>))}
    </div>
  );
}

function Island({ c, focus }: { c: Campaign; focus: string | null }) {
  const { pos, edges, centre } = islandLayout(c, focus);
  return (
    <div className="graph"><svg viewBox="0 0 520 200">
      <g stroke="#6366F1" strokeOpacity=".35" strokeWidth="2">{edges.map(([a, b], i) => <line key={i} x1={pos[a][0]} y1={pos[a][1]} x2={pos[b][0]} y2={pos[b][1]} />)}</g>
      {Object.entries(pos).map(([d, [x, y]]) => {
        const me = d === centre;
        return <g key={d}><circle cx={x} cy={y} r={me ? 13 : 9} fill={me ? "#E5484D" : "#fff"} stroke={me ? "#fff" : "#6366F1"} strokeWidth="3" />
          <text x={x} y={y + (y < 100 ? -16 : 26)} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="11" fill="#5B6478">{d.length > 26 ? d.slice(0, 25) + "…" : d}</text></g>;
      })}
    </svg></div>
  );
}

function CaseFile({ v }: { v: Verdict }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const open = async (lang: "en" | "hi") => {
    const tab = window.open("", "_blank");
    setBusy(lang); setErr(null);
    try {
      const html = await api.report(v, lang);
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      if (tab) tab.location.href = url; else window.location.href = url;
    } catch (e) { tab?.close(); setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(null); }
  };
  return <>
    <p className="tline" style={{ marginTop: 0 }}>A one-page report a bank or CERT-In can act on. Every sentence cites a piece of evidence; nothing is invented.</p>
    <div className="pvrow" style={{ marginTop: 12 }}>
      <button className="ppill" onClick={(e) => { e.stopPropagation(); open("en"); }}>{busy === "en" ? "Writing…" : "English"}</button>
      <button className="ppill" onClick={(e) => { e.stopPropagation(); open("hi"); }}>{busy === "hi" ? "Writing…" : "हिंदी"}</button>
    </div>
    {err && <p className="tline" style={{ color: "var(--rose)" }}>{err}</p>}
  </>;
}

const fmtTime = (s: unknown) => {
  if (typeof s !== "string") return "—";
  const d = new Date(s);
  return isNaN(+d) ? s : d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
};
