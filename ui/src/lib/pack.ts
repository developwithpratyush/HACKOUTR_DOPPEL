// P14 offline pack (demo/finale/build_pack.py): real recorded verdicts for the stage cases, loaded lazily only when the
// API is unreachable (or ?mock=1). Every screen built from it is labelled REPLAY. Not the P0 contract mocks.
import type { BrandInfo, LiveResponse, RadarResponse, Verdict } from "./types";

export interface BaselineRow { method: string; name: string; flagged: boolean | null; detail: string }
export interface PackCase { raw: string; source: string; verdict: Verdict; verdict_certs_off?: Verdict; baselines: BaselineRow[] }
export interface PackIndex {
  generated_at: string; engine: string;
  cases: Record<string, { file: string; label: string; risk: number; source: string }>;
  aliases: Record<string, string>;
}
export interface ArenaCell { flagged: number; of: number }
export interface PackContext {
  brands: { brands: BrandInfo[] }; campaigns: RadarResponse; live: LiveResponse | null; arena: Record<string, ArenaCell>;
}

const DIR = "../../../demo/finale/pack/";
const files = import.meta.glob("../../../demo/finale/pack/*.json", { import: "default" }) as Record<string, () => Promise<unknown>>;
const load = <T,>(name: string): Promise<T | null> => (files[DIR + name] ? files[DIR + name]().then((x) => x as T).catch(() => null) : Promise.resolve(null));

let idx: Promise<PackIndex | null> | null = null;
let ctx: Promise<PackContext | null> | null = null;
export const packIndex = () => (idx ??= load<PackIndex>("index.json"));
export const packContext = () => (ctx ??= load<PackContext>("context.json"));

const host = (s: string) => s.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/?#].*$/, "").replace(/^www\./, "");

/** The recorded case for what was typed (a raw URL, or the bare domain). */
export async function packCase(raw: string): Promise<PackCase | null> {
  const i = await packIndex();
  if (!i) return null;
  const k = raw.trim().toLowerCase();
  const d = i.aliases[k] ?? (i.cases[k] ? k : null) ?? i.aliases[host(k)] ?? (i.cases[host(k)] ? host(k) : null);
  return d && i.cases[d] ? load<PackCase>(i.cases[d].file) : null;
}
