// "Try to fool it": the judge invents a fake of any protected brand; Doppel has never seen it and re-scores
// as they type (every keystroke is a real investigation, ~3–40 ms warm). Unseen input is the proof the demo
// isn't scripted, and the scoreboard counts honestly, misses included.
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import { tricksOf } from "../lib/replay";
import type { Verdict } from "../lib/types";
import { LABEL_CLS, labelText, TRICK_TEXT } from "../lib/vocab";
import { Marked } from "./visuals";

export interface Attempt { raw: string; verdict: Verdict; at: number }

// Look-alike letters a judge can't easily type: Cyrillic, Greek, Armenian, plus ASCII twins.
const GLYPHS: [string, string][] = [
  ["а", "Cyrillic a"], ["е", "Cyrillic e"], ["о", "Cyrillic o"], ["р", "Cyrillic p"], ["с", "Cyrillic c"],
  ["х", "Cyrillic x"], ["у", "Cyrillic y"], ["і", "Ukrainian i"], ["ј", "Cyrillic j"], ["ѕ", "Cyrillic s"],
  ["ԁ", "Cyrillic d"], ["ο", "Greek o"], ["α", "Greek a"], ["ı", "dotless i"], ["ɡ", "Latin script g"],
  ["օ", "Armenian o"], ["rn", "twin of m"], ["vv", "twin of w"], ["cl", "twin of d"], ["0", "zero for o"], ["1", "one for l"],
];
const IDEAS = ["pаytm.com", "hdfcbank-kyc-verify.in", "sbi.bank.in.secure-login.co", "lncometax.gov.in-refund.top",
               "icici-netbanking.web.app", "indiapost-redelivery.icu", "gooogle.com", "statebankofindia-yono.in"];

const flagged = (v: Verdict) => v.label !== "benign" && v.label !== "genuine";

export default function FoolIt({ live, initial = "", attempts, setAttempts, onReplay }: {
  live: boolean; initial?: string; attempts: Attempt[]; setAttempts: (f: (a: Attempt[]) => Attempt[]) => void; onReplay: (v: Verdict) => void;
}) {
  const [text, setText] = useState(initial);
  const [preview, setPreview] = useState<Verdict | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ms, setMs] = useState<number | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const seq = useRef(0);

  useEffect(() => {                          // live re-score, debounced; stale answers are dropped
    const raw = text.trim();
    if (!live || !raw) { setPreview(null); setErr(null); return; }
    const my = ++seq.current;
    const t = setTimeout(async () => {
      const t0 = performance.now();
      try {
        const v = await api.investigate(raw, "fool_it");
        if (my === seq.current) { setPreview(v); setErr(null); setMs(performance.now() - t0); }
      } catch (e) {
        if (my === seq.current) { setPreview(null); setErr(e instanceof ApiError ? e.message : String(e)); }
      }
    }, 220);
    return () => clearTimeout(t);
  }, [text, live]);

  const insert = (g: string) => {
    const el = input.current;
    const at = el?.selectionStart ?? text.length;
    const end = el?.selectionEnd ?? at;
    setText(text.slice(0, at) + g + text.slice(end));
    requestAnimationFrame(() => { el?.focus(); el?.setSelectionRange(at + g.length, at + g.length); });
  };
  const submit = () => {
    if (!preview) return;
    setAttempts((a) => [{ raw: text.trim(), verdict: preview, at: Date.now() }, ...a]);
  };
  const caught = attempts.filter((a) => flagged(a.verdict)).length;

  return (
    <section className="pt-4 pb-8">
      <h2>Try to fool it</h2>
      <p className="lead">Invent a fake address for any protected brand (SBI, HDFC, ICICI, Paytm, India Post, Parivahan, Income Tax, Google). Doppel has never seen it. It re-investigates on every keystroke with the same brain, and nothing is opened: the name is judged, and pages exist only for our local fixtures.</p>
      {!live && <div className="err mb-3">The API is offline, so live scoring is unavailable. Start it with <code>python -m doppel.cli serve</code>.</div>}

      <div className="split2">
        <div className="panel">
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); submit(); }}>
            <input ref={input} className="field flex-1" style={{ fontSize: 18, padding: "11px 14px" }} value={text} disabled={!live}
                   onChange={(e) => setText(e.target.value)} placeholder="type a fake, e.g. sbi-yono-rewardz.in" aria-label="Your fake domain" autoFocus />
            <button className="btn go" disabled={!preview}>Judge it</button>
          </form>
          <div className="flex flex-wrap gap-1.5 mt-2.5 items-center">
            <span className="text-xs font-bold text-[var(--muted)] mr-1">Insert a look-alike:</span>
            {GLYPHS.map(([g, name]) => (
              <button key={g} className="glyph" type="button" title={name} onClick={() => insert(g)} disabled={!live}>
                {g}<small>{g.length === 1 && g.charCodeAt(0) > 127 ? "U+" + g.charCodeAt(0).toString(16).toUpperCase() : "ascii"}</small>
              </button>))}
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2.5 items-center">
            <span className="text-xs font-bold text-[var(--muted)] mr-1">Ideas:</span>
            {IDEAS.map((x) => <button key={x} className="btn sm mono" type="button" onClick={() => setText(x)} disabled={!live}>{x}</button>)}
          </div>
          <div className="mt-4">
            {err && <div className="err">{err}</div>}
            {preview && <Result v={preview} ms={ms} onReplay={onReplay} />}
            {!preview && !err && <div className="empty">The verdict appears here as you type.</div>}
          </div>
        </div>

        <div className="panel">
          <h3>Scoreboard</h3>
          <p className="ph">{attempts.length ? <>Doppel flagged <b>{caught} of {attempts.length}</b> attempts (anything not BENIGN or GENUINE counts as flagged). Misses stay on the board.</> : "Press Judge it to put an attempt on the board."}</p>
          <div className="flex flex-col gap-1.5" style={{ maxHeight: 520, overflow: "auto" }}>
            {attempts.map((a) => (
              <div key={a.at} className="tr" style={{ gridTemplateColumns: "1fr auto auto", cursor: "default", alignItems: "center" }}>
                <span className="mono text-[13px] break-all">{a.verdict.input.display}
                  <span className="meta block">{a.verdict.target_brand?.name ?? "no brand"} · {tricksOf(a.verdict).map((t) => TRICK_TEXT[t] ?? t).join(", ") || "no trick"}</span></span>
                <span className={"lab " + LABEL_CLS[a.verdict.label]}>{labelText(a.verdict.label)}{flagged(a.verdict) ? "" : " · missed?"}</span>
                <button className="btn sm" onClick={() => onReplay(a.verdict)}>▶ trace</button>
              </div>))}
          </div>
          {attempts.length > 0 && <button className="btn sm mt-2" onClick={() => setAttempts(() => [])}>Clear board</button>}
        </div>
      </div>
    </section>
  );
}

function Result({ v, ms, onReplay }: { v: Verdict; ms: number | null; onReplay: (v: Verdict) => void }) {
  const trick = v.evidence.find((e) => e.tool === "trick_detector" && e.details.edits?.length);
  const tr = tricksOf(v);
  return (
    <div className={"vcard " + LABEL_CLS[v.label]}>
      <div className="flex justify-between items-start gap-2 flex-wrap">
        <div className="big">{labelText(v.label)}</div>
        <span className="meta">{ms != null ? `round trip ${Math.round(ms)} ms · brain ${v.timings_ms.total.toFixed(1)} ms` : ""}</span>
      </div>
      <div className="mt-1.5"><Marked text={v.input.display} edits={trick?.details.edits} />
        {v.domain !== v.input.display && <span className="meta ml-2">sent as {v.domain}</span>}</div>
      <div className="kv">
        <div><small>Imitates</small><b>{v.target_brand?.name ?? "–"}</b></div>
        <div><small>Closeness</small><b>{v.closeness == null ? "–" : v.closeness.toFixed(2)}</b></div>
        <div><small>Risk score</small><b>{v.risk_score.toFixed(2)}</b></div>
        <div><small>Trick</small><b className="text-[13px]">{tr.map((t) => TRICK_TEXT[t] ?? t).join(", ") || "–"}</b></div>
      </div>
      <div className="vrow"><span className="k">Why:</span>{v.reason}</div>
      {v.counterfactual && <div className="whatif"><b>What-if:</b> {v.counterfactual.summary}</div>}
      <button className="btn sm mt-2.5" onClick={() => onReplay(v)}>▶ Replay the full decision trace</button>
    </div>
  );
}
