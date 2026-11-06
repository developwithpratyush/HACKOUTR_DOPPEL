// ⭐ The Decision Trace Explorer: replays a real verdict's trace step by step through the 9-question
// pipeline of the ideation round (stage → tool → evidence → score change), then the hard rule and the what-if.
import { useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../lib/api";
import { BrandsCtx, isMockVerdict } from "../lib/context";
import { GALLERY, SOURCE_STORY, type Case } from "../lib/gallery";
import { evidenceOf, reachedStage, replay, type ReplayView } from "../lib/replay";
import type { Evidence, Stage, TraceStep, Verdict } from "../lib/types";
import {
  BLOCK_BY_TOOL, BLOCKS, CHECKS, ICON, LABEL_CLS, LABELS, labelText, points, STAGE_SHORT, STAGES, tone,
} from "../lib/vocab";
import { ClosenessBars, CredentialTrackerView, EditTable, FamilyTree, OwnerSplit, PageInspectorView, PagePreview, RiskPath, SmsView, VisionView } from "./visuals";

export interface Loaded { verdict: Verdict; caseId?: string; story?: Case["input"]; startAt?: number }

const BASE_MS = 1100;

export default function Explorer({ loaded, busy, error, live, onRun, active }: {
  loaded: Loaded | null; busy: boolean; error: string | null; live: boolean; active: boolean;
  onRun: (raw: string, source: Verdict["input"]["source"], c?: Case) => void;
}) {
  const v = loaded?.verdict ?? null;
  const [idx, setIdx] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [view, setView] = useState<number | null>(null);
  const [paste, setPaste] = useState("");
  const last = v ? v.trace.length - 1 : -1;

  useEffect(() => {                       // a new verdict: replay it from the top, automatically
    if (!v) return;
    setView(null);
    if (loaded?.startAt !== undefined) { setIdx(Math.min(loaded.startAt, v.trace.length - 1)); setPlaying(false); }
    else if (speed >= 99) { setIdx(v.trace.length - 1); setPlaying(false); } else { setIdx(0); setPlaying(true); }
  }, [v]);  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!playing || !v) return;
    if (idx >= last) { setPlaying(false); return; }
    const t = setTimeout(() => setIdx((i) => Math.min(i + 1, last)), BASE_MS / speed);
    return () => clearTimeout(t);
  }, [playing, idx, speed, v, last]);

  const step = (d: number) => { setPlaying(false); setView(null); setIdx((i) => Math.max(0, Math.min(last, i + d))); };
  const play = () => { if (!v) return; setView(null); if (idx >= last) setIdx(0); setPlaying((p) => !p); };

  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.code === "Space") { e.preventDefault(); play(); }
      if (e.code === "ArrowRight") step(1);
      if (e.code === "ArrowLeft") step(-1);
      if (e.code === "End") { setPlaying(false); setView(null); setIdx(last); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const r = useMemo(() => (v ? replay(v, idx) : null), [v, idx]);
  const shown = view ?? idx;
  const pick = (i: number) => { setPlaying(false); if (i > idx) setIdx(i); setView(i); };

  return (
    <section className="pt-4 pb-8">
      <div className="flex flex-wrap gap-2.5 items-start mb-3">
        <div className="flex flex-wrap gap-1.5">
          {GALLERY.map((c) => (
            <button key={c.id} className={"case" + (loaded?.caseId === c.id ? " sel" : "")} disabled={!live && !c.mock}
                    title={!live && !c.mock ? "Needs the API (no mock for this case)" : c.raw}
                    onClick={() => onRun(c.raw, c.source, c)}>
              <b>{c.id} · {c.title}</b><span>{c.raw.replace(/^https?:\/\//, "").replace(/\/.*$/, "")}</span>
            </button>))}
        </div>
      </div>
      <div className="flex flex-wrap gap-2 items-center mb-3">
        <form className="flex gap-2 flex-1 min-w-[260px]" onSubmit={(e) => { e.preventDefault(); if (paste.trim()) onRun(paste.trim(), "paste"); }}>
          <input className="field flex-1" placeholder={live ? "Investigate any domain, URL or SMS link…" : "API offline: only the gallery's mock verdicts are available"}
                 value={paste} onChange={(e) => setPaste(e.target.value)} disabled={!live} aria-label="Domain to investigate" />
          <button className="btn go" disabled={!live || busy || !paste.trim()}>{busy ? "Investigating…" : "Investigate"}</button>
        </form>
        <div className="flex gap-1.5 items-center flex-wrap">
          <button className="btn go" onClick={play} disabled={!v}>{playing ? "❚❚ Pause" : idx >= last && v ? "▶ Replay" : "▶ Run"}</button>
          <button className="btn" onClick={() => step(-1)} disabled={!v || idx <= 0}>⏮ Back</button>
          <button className="btn" onClick={() => step(1)} disabled={!v || idx >= last}>Step ⏭</button>
          <button className="btn" onClick={() => { setPlaying(false); setView(null); setIdx(last); }} disabled={!v}>End ⏭⏭</button>
          <select className="btn" value={speed} onChange={(e) => setSpeed(parseFloat(e.target.value))} aria-label="Replay speed">
            <option value={0.6}>0.6×</option><option value={1}>1×</option><option value={1.6}>1.6×</option>
            <option value={3}>3×</option><option value={99}>instant</option>
          </select>
          <span className="keys hidden lg:inline">Space run/pause · ←/→ step · End</span>
        </div>
      </div>
      {error && <div className="err mb-3">{error}</div>}

      <BrainBar v={v} r={r} playing={playing} />
      {v && r ? (
        <>
          <Pipeline v={v} r={r} story={loaded?.story} viewing={shown} onPick={pick} />
          <div className="split2 wide-left mt-3.5">
            <div className="panel"><StepDetail v={v} i={shown} story={loaded?.story} onRun={onRun} live={live} /></div>
            <div className="panel">
              <h3>Decision trace</h3>
              <p className="ph">Every step the brain took, with real timings. Click a line (or a block) to inspect it.</p>
              <RiskPath verdict={v} idx={idx} onPick={pick} />
              <Trace v={v} idx={idx} sel={shown} onPick={pick} />
            </div>
          </div>
        </>
      ) : (
        <div className="panel empty">{busy ? "Investigating…" : <>Pick a gallery case or paste a domain. The brain investigates it for real, then the replay walks you through every step.</>}</div>
      )}
    </section>
  );
}

function BrainBar({ v, r, playing }: { v: Verdict | null; r: ReplayView | null; playing: boolean }) {
  const s = r?.step;
  let msg: ReactNode = "Waiting for a domain…";
  if (v && s) {
    msg = s.kind === "final_verdict"
      ? <><b>Final verdict: {labelText(v.label)}.</b> {v.reason}</>
      : <>{s.message}{s.kind === "tool" && <Delta s={s} />}</>;
  }
  const risk = r?.risk;
  return (
    <div className={"brainbar" + (playing ? " running" : "")}>
      <div className="who"><span className="pulse" />Central brain</div>
      <div className="brainmsg">{msg}</div>
      <div className="clock">t = {r ? fmtMs(r.clock) : "0 ms"}{v && r?.final ? ` · total ${fmtMs(v.timings_ms.total)}` : ""}</div>
      <div className="meter">
        <div className="lbl"><span>risk score</span><b>{risk == null ? "–" : risk.toFixed(2)}</b></div>
        <div className="bar"><div className="knob" style={{ left: `calc(${(risk ?? 0) * 100}% - 2px)` }} /></div>
        <div className="lbl"><span>real</span><span>fake</span></div>
      </div>
    </div>
  );
}

const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`);

function Delta({ s }: { s: TraceStep }) {
  if (typeof s.risk_before !== "number" || typeof s.risk_after !== "number") return null;
  const d = s.risk_after - s.risk_before;
  if (Math.abs(d) < 0.0005) return <span className="meta"> · risk unchanged {s.risk_after.toFixed(2)}</span>;
  return <span className={"meta " + (d > 0 ? "delta-up" : "delta-down")}> · risk {s.risk_before.toFixed(2)} → {s.risk_after.toFixed(2)} ({d > 0 ? "+" : ""}{d.toFixed(2)})</span>;
}

function stageTime(v: Verdict, st: Stage) {
  const t = v.timings_ms[st];
  return t == null ? "skipped" : fmtMs(t);
}

function Pipeline({ v, r, story, viewing, onPick }: {
  v: Verdict; r: ReplayView; story?: Case["input"]; viewing: number; onPick: (i: number) => void;
}) {
  const gate = (id: "a1" | "a2" | "a3" | "a4") => (
    <div className={"arw" + (r.gates[id].lit ? " lit" : "")}><div className="line" /><div className={"gate " + r.gates[id].tone}>{r.gates[id].text}</div></div>
  );
  return (
    <div className="pipewrap"><div className="pipe">
      <div className="col i">
        <div className="colhead"><span className="nm">INPUT</span><span className="tm">{v.input.source}</span></div>
        <div className="inputcard">
          <div className="src">{story?.src ?? SOURCE_STORY[v.input.source] ?? v.input.source}</div>
          <div className="msg">{story?.msg && <>{story.msg}<br /></>}<span className="dom">{v.input.display}</span></div>
          <div className="ctx">{story?.ctx ?? (v.domain !== v.input.display ? <>Sent as <span className="mono">{v.domain}</span></> : "Never seen before: investigated live.")}</div>
        </div>
      </div>
      {gate("a1")}
      {STAGES.map((st, k) => (
        <StageCol key={st.id} v={v} r={r} stage={st} viewing={viewing} onPick={onPick} gateAfter={gate((["a2", "a3", "a4"] as const)[k])} />
      ))}
      <div className="col v">
        <div className="colhead"><span className="nm">VERDICT</span><span className="tm">{r.final ? fmtMs(v.timings_ms.total) : ""}</span></div>
        {LABELS.map((l) => (
          <div key={l.id} className={`vt ${l.cls}` + (r.final === l.id ? " win" : "") + (r.nextIsVerdict && v.label === l.id ? " next" : "")
                                    + (r.final === l.id && r.hardRule ? " ruled" : "")}
               onClick={() => r.final && onPick(v.trace.length - 1)} style={{ cursor: r.final ? "pointer" : "default" }}>
            {l.text}<small>{l.sub}</small>
          </div>))}
      </div>
    </div></div>
  );
}

function StageCol({ v, r, stage, viewing, onPick, gateAfter }: {
  v: Verdict; r: ReplayView; stage: (typeof STAGES)[number]; viewing: number; onPick: (i: number) => void; gateAfter: ReactNode;
}) {
  const prov = r.provisional[stage.id];
  const viewedTool = v.trace[viewing]?.tool;
  return (
    <>
      <div className={"col " + stage.short}>
        <div className="colhead"><span className="nm">{stage.name}</span><span className="tm">{r.idx >= 0 ? stageTime(v, stage.id) : ""}</span></div>
        <div className="colhead" style={{ marginTop: -6 }}><span className="why">{stage.why}</span></div>
        {BLOCKS.filter((b) => b.stage === stage.id).map((b) => {
          const bv = r.blocks[b.id];
          const st = { idle: "", next: "next", active: "running", done: "done ✓", skipped: "skipped", notbuilt: "not built" }[bv.state];
          const res = bv.state === "skipped" || bv.state === "notbuilt" ? { tone: "neutral" as const, text: bv.note ?? "" } : bv.res;
          return (
            <button key={b.id} className={`blk ${bv.state === "idle" ? "" : bv.state}` + (viewedTool === b.tool ? " viewing" : "")}
                    onClick={() => bv.stepIndex !== undefined && bv.stepIndex <= r.idx && onPick(bv.stepIndex)}
                    title={bv.note ?? b.toolName}>
              <div className="top"><span className="id">{b.id}</span><span className="st">{st}</span></div>
              <div className="tt">{b.title}</div>
              <div className="tool">{b.toolName}</div>
              <div className="cs">{b.checks.map((c) => <span key={c} className="c" title={CHECKS[c]}>{c}</span>)}</div>
              {res && (bv.state !== "idle" && bv.state !== "next") && (
                <div className={"res " + res.tone}>{bv.state === "done" || bv.state === "active" ? ICON[res.tone] + " " : ""}{res.text}</div>)}
            </button>);
        })}
        <div className={"prov" + (prov ? " on" : "")}
             onClick={() => { const k = v.trace.findIndex((s) => s.kind === "provisional_verdict" && s.stage === stage.id); if (prov && k >= 0) onPick(k); }}>
          {prov ? <><span>provisional: <span className="pl">{labelText(prov.label)}</span></span><span className="num">{prov.risk.toFixed(2)}</span></>
                : <span className="text-[var(--faint)] font-semibold">provisional verdict</span>}
        </div>
      </div>
      {gateAfter}
    </>
  );
}

function Trace({ v, idx, sel, onPick }: { v: Verdict; idx: number; sel: number; onPick: (i: number) => void }) {
  return (
    <div className="trace">
      {v.trace.slice(0, Math.max(idx, sel) + 1).map((s, k) => {
        const blk = s.tool ? BLOCK_BY_TOOL[s.tool] : undefined;
        const cls = s.kind === "tool" && s.stage ? STAGE_SHORT[s.stage] : s.kind === "final_verdict" ? "v" : "p";
        const tid = blk?.id ?? { case_opened: "IN", policy: "⇢", provisional_verdict: "PV", hard_rule: "RULE", final_verdict: "V", tool: "?" }[s.kind];
        const d = typeof s.risk_after === "number" && typeof s.risk_before === "number" ? s.risk_after - s.risk_before : null;
        return (
          <button key={k} className={`tr ${cls}` + (k === sel ? " sel" : "") + (s.kind === "hard_rule" ? (v.hard_rule?.forces === "phishing" ? " rule bad" : " rule") : "") + (k > idx ? " future" : "")}
                  onClick={() => onPick(k)}>
            <span className="tid">{tid}</span>
            <span>{s.kind === "final_verdict" ? <b>Verdict: {labelText(v.label)}</b>
                   : s.kind === "provisional_verdict" ? <><b>{cap(s.stage)} provisional: {labelText(s.label!)}</b></>
                   : s.kind === "hard_rule" ? <b>{s.message}</b>
                   : s.kind === "tool" ? <><b>{blk?.title ?? s.tool}</b> <span className="text-[var(--muted)]">{s.message.replace(/^[^:]+:\s*/, "")}</span></>
                   : <span className="text-[var(--muted)]">{s.message}</span>}</span>
            <span className="tsc">
              {fmtMs(s.t_ms)}
              {d !== null && s.kind === "tool" && <><br /><span className={d > 0.0005 ? "delta-up" : d < -0.0005 ? "delta-down" : ""}>{d >= 0 ? "+" : ""}{d.toFixed(2)}</span></>}
              {s.kind !== "tool" && typeof s.risk_after === "number" && <><br />{s.risk_after.toFixed(2)}</>}
            </span>
          </button>);
      })}
    </div>
  );
}

const cap = (s?: string) => (s ? s[0].toUpperCase() + s.slice(1) : "");

function EvidenceRows({ items }: { items: Evidence[] }) {
  return (
    <div className="ev">
      {items.map((e) => {
        const tn = tone(e);
        const p = points(e);
        return [
          <span key={e.evidence_id + "c"} className="c" title={CHECKS[e.criterion]}>{e.criterion}</span>,
          <span key={e.evidence_id + "i"} className={"ic " + tn}>{ICON[tn]}</span>,
          <span key={e.evidence_id + "s"}>
            <span className="text-[var(--muted)] text-[12.5px]">{CHECKS[e.criterion] ?? e.criterion}:</span> {e.summary}
            <div className="meta">{e.evidence_id} · {e.finding} · points to {e.points_to} · {e.strength} · score {e.score.toFixed(2)}
              {p !== 0 && <> · <span className={p > 0 ? "delta-up" : "delta-down"}>{p > 0 ? "+" : ""}{p.toFixed(2)} log-odds</span></>}</div>
          </span>,
        ];
      })}
    </div>
  );
}

function StepDetail({ v, i, story, onRun, live }: {
  v: Verdict; i: number; story?: Case["input"]; onRun: (raw: string, source: Verdict["input"]["source"]) => void; live: boolean;
}) {
  const brands = useContext(BrandsCtx);
  const s = v.trace[i];
  if (!s) return <div className="empty">Press <b>Run</b> to replay the investigation.</div>;
  const names = Object.fromEntries(Object.values(brands).map((b) => [b.id, b.name]));

  if (s.kind === "final_verdict") return <VerdictCard v={v} onRun={onRun} live={live} />;
  if (s.kind === "hard_rule") {
    const cited = evidenceOf(v, s.evidence_ids);
    return (<>
      <h3>Hard rule fired: {v.hard_rule?.id ?? ""}</h3>
      <p className="ph">A hard rule decides the label outright, whatever the score says. t = {fmtMs(s.t_ms)}</p>
      <div className={"rulebox" + (v.hard_rule?.forces === "phishing" ? " bad" : "")}><b>Forces {labelText(v.hard_rule?.forces ?? v.label)}.</b> {v.hard_rule?.description}
        {v.hard_rule?.also_fired?.length ? <div className="tnote mt-1">Also fired: {v.hard_rule.also_fired.join(", ")} (lower priority; any one of them forces the same label).</div> : null}</div>
      <div className="section-t">Evidence it rests on</div>
      <EvidenceRows items={cited} />
    </>);
  }
  if (s.kind === "case_opened") {
    return (<>
      <h3>Case opened</h3>
      <p className="ph">{s.message}</p>
      <div className="kv">
        <div><small>Submitted</small><b className="mono text-[13px]">{v.input.raw}</b></div>
        <div><small>As a victim sees it</small><b className="mono text-[13px]">{v.input.display}</b></div>
        <div><small>Lowercase ASCII host</small><b className="mono text-[13px]">{v.domain}</b></div>
        <div><small>Source</small><b>{v.input.source}</b></div>
      </div>
      {story && <p className="text-sm text-[var(--muted)]">{story.ctx}</p>}
    </>);
  }
  if (s.kind === "policy") {
    return (<><h3>Brain decision</h3><p className="ph">t = {fmtMs(s.t_ms)} · the brain is a deterministic policy, not an LLM</p>
      <div className="whatif">{s.message}</div></>);
  }
  if (s.kind === "provisional_verdict") {
    const st = v.stages.find((x) => x.stage === s.stage);
    return (<><h3>{cap(s.stage)} stage: provisional verdict</h3>
      <p className="ph">After each stage the brain publishes its current answer; “suspicious” exists only here, never as a final label.</p>
      <div className="kv">
        <div><small>Provisional</small><b>{labelText(s.label!)}</b></div>
        <div><small>Risk so far</small><b>{(s.risk_after ?? 0).toFixed(3)}</b></div>
        <div><small>Stage time</small><b>{s.stage ? stageTime(v, s.stage) : "–"}</b></div>
        <div><small>Evidence</small><b>{st?.evidence_ids.length ?? 0} items</b></div>
      </div>
      <div className="vrow">{s.message}</div></>);
  }

  // a tool step
  const blk = s.tool ? BLOCK_BY_TOOL[s.tool] : undefined;
  const items = evidenceOf(v, s.evidence_ids);
  const brandId = items.find((e) => e.target_brand)?.target_brand?.id ?? v.target_brand?.id;
  return (<>
    <h3>{blk?.id} · {blk?.title ?? s.tool}</h3>
    <p className="ph">{cap(s.stage)} stage · tool: <b>{blk?.toolName ?? s.tool}</b> · t = {fmtMs(s.t_ms)} · took {fmtMs(s.duration_ms ?? 0)}
      <Delta s={s} /></p>
    <EvidenceRows items={items} />
    {s.tool === "address_reader" && <OwnerSplit verdict={v} />}
    {s.tool === "family_verifier" && items[0] && (
      brandId && brands[brandId] ? <FamilyTree brand={brands[brandId]} ev={items[0]} verdict={v} />
        : brandId ? <div className="tnote mt-2">Family tree needs the API (registry).</div> : null)}
    {s.tool === "trick_detector" && items.map((e) => {
      if (e.criterion === "C5" && e.details.edits?.length) return <EditTable key={e.evidence_id} ev={e} verdict={v} />;
      if (e.finding === "combosquat") return (
        <div key={e.evidence_id} className="mt-3"><div className="section-t">The name, as words</div>
          <div className="flex flex-wrap gap-1.5">{(e.details.tokens ?? []).map((t: string, k: number) => {
            const lure = (e.details.lure_words ?? []).some((w: { word: string }) => w.word === t);
            return <span key={k} className={"c " + (t === e.details.brand_alias ? "ink" : lure ? "" : "")}
                         style={lure ? { background: "var(--warn-soft)", color: "var(--warn)" } : undefined}>{t}{t === e.details.brand_alias ? " · brand" : lure ? " · lure" : ""}</span>;
          })}</div></div>);
      return null;
    })}
    {s.tool === "trick_detector" && (() => {
      const c = items.find((e) => e.details.per_brand);
      return c ? <ClosenessBars perBrand={c.details.per_brand} names={names} /> : null;
    })()}
    {s.tool === "human_eye_renderer" && <SmsView verdict={v} ev={items[0]} message={story?.msg} />}
    {s.tool === "page_probe" && items[0] && <PagePreview ev={items[0]} />}
    {s.tool === "page_inspector" && items[0] && <PageInspectorView items={items} />}
    {s.tool === "vision_ai" && items[0] && <VisionView items={items} />}
    {s.tool === "credential_tracker" && items[0] && <CredentialTrackerView items={items} />}
    {items.some((e) => e.details.artifacts?.length) && s.tool !== "human_eye_renderer" && (
      <div className="tnote mt-2">Artifacts: {items.flatMap((e) => e.details.artifacts ?? []).map((a) => a.path).join(", ")}</div>)}
  </>);
}

function VerdictCard({ v, onRun, live }: { v: Verdict; onRun: (raw: string, source: Verdict["input"]["source"]) => void; live: boolean }) {
  const cls = LABEL_CLS[v.label];
  const cf = v.counterfactual;
  const mockEx = isMockVerdict(v);
  return (
    <div className={"vcard " + cls}>
      <div className="flex justify-between items-start gap-2 flex-wrap">
        <div className="big">{labelText(v.label)}</div>
        <div className="flex gap-1.5 flex-wrap">
          {mockEx && <span className="pill mock">mock verdict (contract example, illustrative numbers)</span>}
          {!mockEx && v.meta.mock && <span className="pill mock">page evidence from a local mock fixture</span>}
        </div>
      </div>
      <div className="kv">
        <div><small>Target brand</small><b>{v.target_brand?.name ?? "–"}</b></div>
        <div><small>Closeness (name)</small><b>{v.closeness == null ? "–" : v.closeness.toFixed(2)}</b></div>
        <div><small>Risk score</small><b>{v.risk_score.toFixed(3)}</b></div>
        <div><small>Confidence</small><b>{v.confidence}</b></div>
        <div><small>Real owner</small><b className="mono text-[13px]">{v.owner ?? "–"}</b></div>
        <div><small>Reached stage</small><b>{reachedStage(v)}</b></div>
        <div><small>Total time</small><b>{fmtMs(v.timings_ms.total)}</b></div>
        <div><small>Evidence items</small><b>{v.evidence.length}</b></div>
      </div>
      <div className="vrow"><span className="k">Why:</span>{v.reason}</div>
      <div className="vrow"><span className="k">Rule:</span>{v.hard_rule ? <><b>{v.hard_rule.id}</b>: {v.hard_rule.description}{v.hard_rule.also_fired?.length ? <> Also fired: {v.hard_rule.also_fired.join(", ")}.</> : null}</> :
        "No hard rule fired; the label comes from the evidence and the label policy (a name alone never yields PHISHING)."}</div>
      <div className="vrow text-[13px]">
        {v.stages.map((st) => (
          <span key={st.stage} className="c mr-1.5" style={{ fontSize: 11 }}>
            {st.stage}: {st.status === "skipped" ? "skipped" : st.provisional ? labelText(st.provisional.label) + " " + st.provisional.risk_score.toFixed(2) : "done"}
          </span>))}
      </div>
      {cf && (
        <div className="whatif">
          <b>What-if:</b> {cf.summary} <span className="meta">(undoes {cf.undone_evidence_ids.join(", ")}; risk would be {cf.risk_score.toFixed(3)})</span>
          {cf.counterfactual_domain && live && (
            <div className="mt-1.5"><button className="btn sm" onClick={() => onRun(cf.counterfactual_domain!, "paste")}>▶ Investigate {cf.counterfactual_domain} for real</button></div>)}
        </div>)}
      {v.stages[2].status === "skipped" && (
        <div className="tnote">Deep stage: {v.stages[2].skip_reason}</div>)}
      {v.meta.notes && <div className="tnote">{v.meta.notes}</div>}
      {live && !isMockVerdict(v) && <CertToggle v={v} />}
      {live && <CaseFileButtons v={v} />}
    </div>
  );
}

/** The P11 ablation switch: the same name with Certificate Forensics (C16/C17) flipped, and what changed. */
function CertToggle({ v }: { v: Verdict }) {
  const [other, setOther] = useState<Verdict | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const on = !v.meta.checks_off?.includes("C16");
  useEffect(() => { setOther(null); setErr(null); }, [v]);
  const flip = async () => {
    setBusy(true); setErr(null);
    try { setOther(await api.investigate(v.input.raw, v.input.source, !on)); }
    catch (e) { setErr(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };
  const [offV, onV] = on ? [other, v] : [v, other];
  const added = onV ? onV.evidence.filter((e) => e.tool === "cert_forensics" || e.tool === "ct_history") : [];
  return (
    <div className="whatif mt-2">
      <div className="flex flex-wrap items-center gap-2">
        <b>Certificate check:</b> <span className="pill">{on ? "ON" : "OFF (ablation)"}</span>
        <button className="btn sm" disabled={busy} onClick={flip}>{busy ? "Re-running…" : `▶ Re-run with it ${on ? "OFF" : "ON"}`}</button>
        {err && <span className="err">{err}</span>}
      </div>
      {offV && onV && (
        <div className="mt-1.5 text-[13px]">
          <div>OFF: <b>{labelText(offV.label)}</b> (risk {offV.risk_score.toFixed(3)}) → ON: <b>{labelText(onV.label)}</b> (risk {onV.risk_score.toFixed(3)})
            {offV.label === onV.label ? " · same label" : ""}</div>
          {added.length ? added.map((e) => (
            <div key={e.evidence_id} className="mt-1"><span className="mono">+ {e.evidence_id} {e.criterion} {e.finding}</span>: {e.summary}
              {e.details.cert_sha256 && <div className="tnote mono">certificate SHA-256 {String(e.details.cert_sha256)}</div>}
              {Array.isArray(e.details.sans) && e.details.matched_san && (
                <div className="tnote mono">SANs: {(e.details.sans as string[]).map((s) => s === e.details.matched_san ? `[${s}]` : s).join(" · ")}</div>)}
            </div>)) : <div className="tnote">The certificate checks add nothing for this name.</div>}
        </div>)}
    </div>
  );
}

/** Opens the case file (P10) in a new tab: every narrated sentence cites its evidence; print it to PDF from there. */
function CaseFileButtons({ v }: { v: Verdict }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const open = async (lang: "en" | "hi") => {
    const tab = window.open("", "_blank");
    setBusy(lang); setErr(null);
    try {
      const html = await api.report(v, lang);
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      if (tab) tab.location.href = url; else window.location.href = url;
    } catch (e) {
      tab?.close();
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(null); }
  };
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <button className="btn sm" disabled={!!busy} onClick={() => open("en")}>{busy === "en" ? "Writing…" : "📄 Case file"}</button>
      <button className="btn sm" disabled={!!busy} onClick={() => open("hi")}>{busy === "hi" ? "लिख रहे हैं…" : "📄 केस फ़ाइल (हिंदी)"}</button>
      <span className="tnote">Narrated by an LLM that may only cite this verdict's evidence; the label and actions come from the brain.</span>
      {err && <span className="err">{err}</span>}
    </div>
  );
}
