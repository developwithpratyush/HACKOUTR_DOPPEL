// P14 Presenter view: turns one real verdict into what each tile shows. Pure functions (tested), no React.
import type { BrandInfo, Campaign, Evidence, Verdict } from "./types";

export type Tone = "bad" | "warn" | "good" | "neutral";
export type SegKind = "dec" | "own" | "brand" | "mut" | "proved" | "plain";
export interface Seg { text: string; kind: SegKind; note: string; up: boolean }

export const NODES: { stage: "quick" | "standard" | "deep"; name: string; nodes: { id: string; label: string; tool: string }[] }[] = [
  { stage: "quick", name: "Quick", nodes: [
    { id: "Q1", label: "Who owns it", tool: "address_reader" }, { id: "Q2", label: "Family", tool: "family_verifier" },
    { id: "Q3", label: "Trick", tool: "trick_detector" }, { id: "Q4", label: "Certificate", tool: "cert_forensics" }] },
  { stage: "standard", name: "Standard", nodes: [
    { id: "S1", label: "Human eye", tool: "human_eye_renderer" }, { id: "S2", label: "ML model", tool: "risk_model" },
    { id: "S3", label: "Page probe", tool: "page_probe" }, { id: "S4", label: "CT history", tool: "ct_history" },
    { id: "S5", label: "Campaign", tool: "campaign_radar" }] },
  { stage: "deep", name: "Deep", nodes: [
    { id: "D1", label: "Page copy", tool: "page_inspector" }, { id: "D2", label: "Vision AI", tool: "vision_ai" },
    { id: "D3", label: "Credential tracker", tool: "credential_tracker" }] },
];

export const LABEL_TEXT: Record<string, string> = {
  phishing: "PHISHING", needs_review: "NEEDS REVIEW", genuine: "GENUINE", benign: "BENIGN", sleeper: "SLEEPER",
};
export const isBad = (label: string) => label === "phishing" || label === "needs_review" || label === "sleeper";

export const ev = (v: Verdict, crit: string) => v.evidence.filter((e) => e.criterion === crit);
export const ev1 = (v: Verdict, crit: string): Evidence | undefined => ev(v, crit)[0];
const byTool = (v: Verdict, tool: string) => v.evidence.filter((e) => e.tool === tool);

/** One node per tool: not run (null), or the strongest direction among its evidence. */
export function nodeTone(v: Verdict, tool: string): Tone | null {
  const es = byTool(v, tool);
  if (!es.length) return null;
  if (es.some((e) => e.points_to === "phishing" && e.strength !== "weak")) return "bad";
  if (es.some((e) => e.points_to === "phishing")) return "warn";
  if (es.some((e) => e.points_to === "genuine" && e.strength === "strong")) return "good";
  return "neutral";
}

/** The trick name, said plainly. */
export function trickName(v: Verdict): string {
  const c5 = ev1(v, "C5");
  if (c5) return c5.finding.replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase()).replace("Tld swap", "Ending swap");
  const c4 = ev1(v, "C4");
  if (c4?.finding === "far_from_all_brands") return "No trick in the name";
  return c4 ? "Look-alike" : "None found";
}

/** Find where the brand sits in the name (the C5 alias, the embedded genuine address, or C4's compared token). */
function brandSpan(v: Verdict): [number, number] | null {
  const d = v.domain;
  const c1 = ev1(v, "C1")?.details ?? {};
  const c5 = ev1(v, "C5")?.details ?? {};
  const c4 = ev1(v, "C4")?.details ?? {};
  for (const tok of [c1.embedded_domain, c5.brand_alias, c4.compared].filter((t): t is string => typeof t === "string" && !!t)) {
    const i = d.indexOf(tok);
    if (i >= 0) return [i, i + tok.length];
  }
  return null;
}

/** The domain cut into annotated pieces for the hero. */
export function segments(v: Verdict): Seg[] {
  const d = v.domain, owner = v.owner ?? d, bad = isBad(v.label);
  const brand = v.target_brand?.name;
  const c1 = ev1(v, "C1");
  if (owner !== d && d.endsWith(owner) && c1?.finding === "owner_differs") {
    return [{ text: d.slice(0, d.length - owner.length), kind: "dec", note: "decoration the attacker chose", up: true },
            { text: owner, kind: bad ? "own" : "proved", note: bad ? "real owner" : "owner, proven", up: false }];
  }
  const span = brandSpan(v);
  if (!span) return [{ text: d, kind: bad ? "plain" : "proved", note: bad ? "no brand anywhere in the name" : "owner", up: false }];
  const [a, b] = span, out: Seg[] = [];
  const c6 = ev1(v, "C6");
  if (a > 0) out.push({ text: d.slice(0, a), kind: bad ? "mut" : "plain", note: "added", up: true });
  out.push({ text: d.slice(a, b), kind: "brand", note: brand ? `brand: ${brand}` : "brand", up: false });
  if (b < d.length) {
    const ending = !bad ? "on the brand's own certificate" : c6 ? `${Math.round((c6.details.risk ?? 0) * 100)}% phishing ending` : "the rest";
    out.push({ text: d.slice(b), kind: bad ? "mut" : "proved", note: v.evidence.some((e) => e.criterion === "C16" && e.points_to === "genuine") ? "on the brand's own certificate" : ending, up: true });
  }
  return out;
}

/** Per-character heat: 0 = matches the brand, 1 = foreign. Spelling edits (twin letters, hidden letters) burn hottest. */
export function heat(v: Verdict): { ch: string; h: number }[] {
  const segs = segments(v);
  const base: Record<SegKind, number> = { dec: 0.12, own: 0.9, brand: 0.04, mut: 0.72, proved: 0.06, plain: 0.1 };
  const cells = segs.flatMap((s) => [...s.text].map((ch) => ({ ch, h: ch === "." || ch === "-" ? 0.25 : base[s.kind] })));
  for (const e of v.evidence) for (const ed of e.details?.edits ?? []) {
    const [i, j] = ed.candidate_span ?? [0, 0];
    for (let k = i; k < Math.max(j, i + 1) && k < cells.length; k++) cells[k].h = 0.97;
  }
  return cells;
}

export const heatColour = (h: number) =>
  `hsl(${h < 0.5 ? 160 - h * 240 : 40 - (h - 0.5) * 96} ${70 + h * 15}% ${90 - h * 10}%)`;

/** Generic methods on this name, from the verdict's own evidence (no hand-typed cells). `agrees` = same call as Doppel. */
export function generic(v: Verdict, brands: Record<string, BrandInfo>): { name: string; says: string; agrees: boolean | null }[] {
  const flagged = isBad(v.label);
  const rows: { name: string; says: string; agrees: boolean | null }[] = [];
  const aliases = Object.values(brands).flatMap((b) => b.aliases.map((a) => a.toLowerCase())).filter((a) => a.length >= 3);
  if (aliases.length) {
    const hit = aliases.find((a) => v.domain.includes(a));
    rows.push({ name: "Keyword filter", says: hit ? `flags '${hit}'` : "no brand word: passes", agrees: !!hit === flagged });
  }
  const c4 = ev1(v, "C4")?.details;
  if (c4?.levenshtein_similarity != null) {
    const s = Number(c4.levenshtein_similarity), hit = s >= 0.8;
    rows.push({ name: "Levenshtein ≥ 0.8", says: `${s.toFixed(2)} to ${c4.genuine ?? c4.compared}: ${hit ? "flags" : "passes"}`, agrees: hit === flagged });
  }
  const c8 = ev1(v, "C8")?.details;
  if (c8?.probability != null) {
    const p = Number(c8.probability), hit = p >= 0.5;
    rows.push({ name: "ML model alone", says: `${p.toFixed(2)}: ${hit ? "flags" : "passes"}, can't say why`, agrees: hit === flagged });
  }
  const armed = ev1(v, "C17"), proof = v.evidence.find((e) => e.criterion === "C16" && e.points_to === "genuine");
  if (armed || proof) rows.push({ name: "Padlock = safe", says: "valid certificate: passes", agrees: !flagged });
  return rows;
}

/** Simple round layout for one campaign island; the inspected domain sits in the middle when it's a member. */
export function islandLayout(c: Campaign, focus: string | null, w = 520, h = 200) {
  const ids = c.members_ids.slice(0, 9);
  const centre = focus && ids.includes(focus) ? focus : null;
  const ring = ids.filter((d) => d !== centre);
  const cx = w / 2, cy = h / 2, rx = w * 0.34, ry = h * 0.36;
  const pos: Record<string, [number, number]> = {};
  if (centre) pos[centre] = [cx, cy];
  ring.forEach((d, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / ring.length;
    pos[d] = [cx + rx * Math.cos(a), cy + ry * Math.sin(a)];
  });
  const edges: [string, string][] = [];
  ring.forEach((d, i) => { if (centre) edges.push([centre, d]); if (ring.length > 2) edges.push([d, ring[(i + 1) % ring.length]]); });
  if (!centre && ring.length === 2) edges.push([ring[0], ring[1]]);
  return { pos, edges, centre };
}

/** The campaign to show: the one this domain belongs to, else the strongest island of the same brand (labelled related). */
export function pickCampaign(v: Verdict, cs: Campaign[]): { c: Campaign; member: boolean } | null {
  const m = cs.find((c) => c.members_ids.includes(v.domain) || (v.owner != null && c.members_ids.includes(v.owner)));
  if (m) return { c: m, member: true };
  const b = v.target_brand?.id;
  if (!b) return null;
  const rel = cs.filter((c) => c.brands[b]).sort((x, y) => y.rank - x.rank)[0];
  return rel ? { c: rel, member: false } : null;
}

export const host = (u: unknown) => {
  if (typeof u !== "string") return null;
  try { return new URL(u).host; } catch { return u; }
};

/** Where typed data goes, as a chain for the Deep tile: you type → the page → every receiver → where the victim lands. */
export function exfilFlow(v: Verdict): { text: string; hot: boolean }[] {
  const c14 = ev(v, "C14");
  if (!c14.length) return [];
  const asks = ev1(v, "C13")?.details?.asks_for as string[] | undefined;
  const out = [{ text: `you type ${(asks ?? ["details"]).slice(0, 3).join(", ").replace(/_/g, " ")}`, hot: false },
               { text: v.owner ?? v.domain, hot: false }];
  const seen = new Set<string>([v.owner ?? v.domain]);
  for (const e of c14) {
    const h = (e.details.endpoint as string) ?? host(e.details.form?.action);
    if (h && !seen.has(h)) { seen.add(h); out.push({ text: h.includes("telegram") ? "Telegram bot" : h, hot: true }); }
  }
  const r = ev1(v, "C15")?.details?.redirect_to ?? ev(v, "C15").map((e) => e.details.redirect_to).find(Boolean);
  if (r) out.push({ text: `then the real ${host(r)}`, hot: false });
  return out;
}

export const isKit = (v: Verdict) => v.evidence.some((e) => e.criterion === "C9" && (e.details.mock || e.details.fixture));
