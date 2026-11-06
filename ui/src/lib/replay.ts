// Replaying a verdict's `trace` step by step. Everything the pipeline shows at step i is a pure function of
// (verdict, i), so stepping back, jumping and clicking a trace line all give the same picture.
import type { Evidence, Label, Provisional, Stage, TraceStep, Verdict } from "./types";
import { BLOCKS, headline, shortFinding, tone, type Tone } from "./vocab";

export type BlockState = "idle" | "next" | "active" | "done" | "skipped" | "notbuilt";
export interface BlockView { state: BlockState; res?: { tone: Tone; text: string }; note?: string; stepIndex?: number }
export interface Gate { lit: boolean; text: string; tone: Tone }
export interface ReplayView {
  idx: number;
  step: TraceStep | null;
  blocks: Record<string, BlockView>;
  gates: Record<"a1" | "a2" | "a3" | "a4", Gate>;
  risk: number | null;
  clock: number;
  provisional: Partial<Record<Stage, { label: Provisional; risk: number }>>;
  final: Label | null;
  nextIsVerdict: boolean;
  hardRule: boolean;
}

const ORDER: Stage[] = ["quick", "standard", "deep"];

export function evidenceOf(v: Verdict, ids: string[] = []): Evidence[] {
  const set = new Set(ids);
  return v.evidence.filter((e) => set.has(e.evidence_id));
}

/** Trace index at which the brain decides whether `stage` runs (its first policy step after the previous
 *  stage's provisional verdict). Tools of that stage that never ran are shown as skipped from then on. */
export function decisionIndex(v: Verdict, stage: Stage): number {
  const t = v.trace;
  const last = t.length - 1;
  const at = ORDER.indexOf(stage);
  if (at === 0) return 0;
  const prev = ORDER[at - 1];
  const pv = t.findIndex((s) => s.kind === "provisional_verdict" && s.stage === prev);
  if (pv < 0) return decisionIndex(v, prev);           // previous stage skipped: decided together with it
  const pol = t.findIndex((s, i) => i > pv && s.kind === "policy");
  if (pol >= 0) return pol;
  const firstHere = t.findIndex((s) => s.kind === "tool" && s.stage === stage);
  return firstHere >= 0 ? firstHere : Math.min(pv + 1, last);
}

const DEEP_NOT_BUILT = /P8|P9|not built|arrive/i;

/** A short label for the arrow between two columns, from the brain's policy message. */
export function shortGate(msg: string | undefined): [string, Tone] {
  const m = msg ?? "";
  const rules: [RegExp, string, Tone][] = [
    [/brand signal found/i, "brand signal → Standard", "bad"],
    [/genuine family: still check/i, "family proven → check page", "ok"],
    [/single investigation: continue/i, "no brand → page check", "neutral"],
    [/vetted or brand-owned host/i, "vetted host → Standard", "warn"],
    [/batch input and no brand signal/i, "no signal → stop", "ok"],
    [/batch input and proven family/i, "family proven → stop", "ok"],
    [/no live page|parked/i, "no page → watch-list", "warn"],
    [/page not opened|never visits/i, "page not opened → verdict", "neutral"],
    [DEEP_NOT_BUILT, "Deep not built yet → verdict", "neutral"],
    [/deep|live page/i, "→ Deep", "bad"],
  ];
  for (const [re, text, t] of rules) if (re.test(m)) return [text, t];
  return [m.length > 30 ? m.slice(0, 28) + "…" : m, "neutral"];
}

export function replay(v: Verdict, idx: number): ReplayView {
  const t = v.trace;
  const i = Math.max(-1, Math.min(idx, t.length - 1));
  const toolStep: Record<string, number> = {};
  t.forEach((s, k) => { if (s.kind === "tool" && s.tool && toolStep[s.tool] === undefined) toolStep[s.tool] = k; });
  const nextTool = t.findIndex((s, k) => k > i && s.kind === "tool");
  const stageRec = Object.fromEntries(v.stages.map((s) => [s.stage, s]));

  const blocks: Record<string, BlockView> = {};
  for (const b of BLOCKS) {
    const k = toolStep[b.tool];
    if (k !== undefined) {
      const state: BlockState = k < i ? "done" : k === i ? "active" : k === nextTool ? "next" : "idle";
      const view: BlockView = { state, stepIndex: k };
      if (k <= i) {
        const items = evidenceOf(v, t[k].evidence_ids);
        // The Trick Detector headlines the trick it named (closeness is the same fact as a number).
        const trick = items.find((e) => e.criterion === "C5" && e.points_to === "phishing");
        const close = items.find((e) => e.finding === "brand_closeness");
        const h = trick ?? headline(items);
        if (h) view.res = { tone: tone(h), text: shortFinding(h) + (trick && close ? ` · closeness ${close.score.toFixed(2)}` : "") };
      }
      blocks[b.id] = view;
      continue;
    }
    if (i < decisionIndex(v, b.stage) || i < 0) { blocks[b.id] = { state: "idle" }; continue; }
    const rec = stageRec[b.stage];
    if (rec?.status === "skipped") {
      const reason = rec.skip_reason ?? "stage skipped";
      blocks[b.id] = b.phase && DEEP_NOT_BUILT.test(reason)
        ? { state: "notbuilt", note: `not built yet (${b.phase})` }
        : { state: "skipped", note: `skipped: ${reason}` };
    } else if (b.phase) {
      blocks[b.id] = { state: "notbuilt", note: `not built yet (${b.phase})` };
    } else {
      const certOff = (b.tool === "cert_forensics" || b.tool === "ct_history") && v.meta.checks_off?.includes("C16");
      blocks[b.id] = { state: "skipped", note: certOff ? "off: certificate checks switched off (ablation)"
        : b.tool === "cert_forensics" ? "skipped: proven by its list, or nothing to prove"
        : b.tool === "ct_history" ? "skipped: no look-alike to look up, or no cached CT record"
        : b.tool === "human_eye_renderer" ? "skipped: no brand to compare"
        : b.tool === "risk_model" ? "skipped: ownership proven, the ML model can't add anything"
        : "skipped: not needed" };
    }
  }

  const gate = (lit: boolean, msg?: string): Gate => {
    if (!lit) return { lit: false, text: "", tone: "neutral" };
    const [text, tn] = shortGate(msg);
    return { lit, text, tone: tn };
  };
  const dStd = decisionIndex(v, "standard");
  const dDeep = decisionIndex(v, "deep");
  const last = t.length - 1;
  const fin = t[last];
  const finTone: Tone = v.label === "phishing" ? "bad" : v.label === "genuine" ? "ok"
    : v.label === "benign" ? "neutral" : "warn";
  const gates = {
    a1: { lit: i >= 0, text: "", tone: "neutral" as Tone },
    a2: gate(i >= dStd, t[dStd]?.kind === "policy" ? t[dStd].message : undefined),
    a3: gate(i >= dDeep, t[dDeep]?.kind === "policy" ? t[dDeep].message : undefined),
    a4: i >= last ? { lit: true, text: (v.label === "needs_review" ? "uncertain" : v.label), tone: finTone } as Gate
                  : { lit: false, text: "", tone: "neutral" as Tone },
  };
  if (stageRec.deep?.status === "completed" && i >= dDeep && t[dDeep]?.kind !== "policy") gates.a3 = { lit: true, text: "→ Deep", tone: "bad" };

  let risk: number | null = null;
  for (let k = 0; k <= i; k++) if (typeof t[k].risk_after === "number") risk = t[k].risk_after!;
  const provisional: ReplayView["provisional"] = {};
  for (let k = 0; k <= i; k++) {
    const s = t[k];
    if (s.kind === "provisional_verdict" && s.stage && s.label) provisional[s.stage] = { label: s.label, risk: s.risk_after ?? 0 };
  }
  const hr = t.findIndex((s) => s.kind === "hard_rule");
  return {
    idx: i, step: i >= 0 ? t[i] : null, blocks, gates, risk, clock: i >= 0 ? t[i].t_ms : 0, provisional,
    final: i >= last && fin.kind === "final_verdict" ? v.label : null,
    nextIsVerdict: i === last - 1, hardRule: hr >= 0 && i >= hr,
  };
}

/** Risk after each trace step (carried forward), for the risk-path chart. */
export function riskPath(v: Verdict): { step: number; risk: number; kind: string; tool?: string }[] {
  let r: number | null = null;
  const out: { step: number; risk: number; kind: string; tool?: string }[] = [];
  v.trace.forEach((s, k) => {
    if (typeof s.risk_after === "number") r = s.risk_after;
    if (r !== null) out.push({ step: k, risk: r, kind: s.kind, tool: s.tool });
  });
  return out;
}

/** Tool names a verdict's flagged trick evidence lists (for tables). */
export function tricksOf(v: Verdict): string[] {
  return v.evidence.filter((e) => e.tool === "trick_detector" && e.criterion === "C5" && e.points_to === "phishing")
    .map((e) => e.finding);
}

export const reachedStage = (v: Verdict): Stage =>
  [...v.stages].reverse().find((s) => s.status === "completed")?.stage ?? "quick";
