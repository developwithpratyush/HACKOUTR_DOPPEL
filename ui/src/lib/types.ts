// TypeScript view of contracts/evidence.schema.json (v1.0.0). The schema is the source of truth;
// these types only cover what the UI reads.

export type Stage = "quick" | "standard" | "deep";
export type Label = "genuine" | "phishing" | "sleeper" | "needs_review" | "benign";
export type Provisional = Label | "suspicious";
export type PointsTo = "phishing" | "genuine" | "neutral";
export type Strength = "strong" | "medium" | "weak";
export type Source = "paste" | "api" | "fool_it" | "gallery" | "file" | "stdin" | "nrd_snapshot" | "ct_feed";

export interface BrandRef { id: string; name: string }

export interface Edit {
  op: string;
  candidate: string;
  genuine: string;
  candidate_span: [number, number];
  genuine_span: [number, number];
  cost: number;
  kind: string;
  codepoints?: string[];
}

export interface Artifact { kind: string; path: string; caption?: string }

export interface Evidence {
  evidence_id: string;
  tool: string;
  stage: Stage;
  criterion: string;
  finding: string;
  points_to: PointsTo;
  strength: Strength;
  score: number;
  target_brand: BrandRef | null;
  summary: string;
  details: Record<string, any> & { edits?: Edit[]; artifacts?: Artifact[] };
  duration_ms?: number;
}

export interface StageRecord {
  stage: Stage;
  status: "completed" | "skipped";
  skip_reason?: string;
  tools: string[];
  evidence_ids: string[];
  provisional: { label: Provisional; risk_score: number; reason: string } | null;
}

export type TraceKind = "case_opened" | "policy" | "tool" | "provisional_verdict" | "hard_rule" | "final_verdict";

export interface TraceStep {
  step: number;
  t_ms: number;
  kind: TraceKind;
  message: string;
  stage?: Stage;
  tool?: string;
  args?: Record<string, unknown>;
  duration_ms?: number;
  evidence_ids?: string[];
  risk_before?: number;
  risk_after?: number;
  label?: Provisional;
}

export interface HardRule { id: string; forces: Label; description: string; evidence_ids: string[]; also_fired?: string[] }

export interface Counterfactual {
  change: string;
  undone_evidence_ids: string[];
  counterfactual_domain?: string;
  label: Label;
  risk_score: number;
  summary: string;
}

export interface Verdict {
  schema_version: string;
  domain: string;
  input: { raw: string; display: string; source: Source };
  owner: string | null;
  target_brand: BrandRef | null;
  closeness: number | null;
  risk_score: number;
  confidence: "high" | "medium" | "low";
  label: Label;
  reason: string;
  hard_rule: HardRule | null;
  counterfactual: Counterfactual | null;
  timings_ms: { quick: number | null; standard: number | null; deep: number | null; total: number };
  stages: StageRecord[];
  evidence: Evidence[];
  trace: TraceStep[];
  meta: { generated_at: string; engine_version: string; mock: boolean; notes?: string; checks_off?: string[] };
}

export interface ScanResponse {
  schema_version: string;
  generated_at: string;
  verdicts: Verdict[];
  summary: { total: number; by_label: Partial<Record<Label, number>>; reached_stage: Partial<Record<Stage, number>>;
             elapsed_ms: number; inputs?: number; not_domains?: number };
  scan_id?: string;
  skipped?: { input: string; error: string }[];
}

export interface FamilyEntry { domain: string; include_subdomains: boolean; proof: string; source: string | null;
                               verified_on: string | null; note: string }
export interface BrandInfo { id: string; name: string; aliases: string[]; brand_tlds: string[];
                             restricted_suffixes: string[]; family: FamilyEntry[];
                             user_content: { host: string; what: string }[] }

export interface Health { ok: boolean; engine: string; version: string; contract: string;
                          built: Record<string, boolean>; warm_ms: number | null; max_batch: number;
                          fixtures: string; brands: string[]; cert_family_links?: number }

// ---- Live Hunt (P12): the collector's state file + catch store, via /api/live/* ----
export interface LiveTick { name: string; t: number; label: Label; brand: string | null; naive: string | null; risk: number }
export interface LiveCatch {
  name: string; owner: string; brand: string | null; label: Label; risk: number; tricks: string | null; reason: string;
  first_seen: number; last_seen: number; times_seen: number; naive: string | null; platform: string | null;
  stream_issuer: string | null; stream_not_before: number | null;
  ct_status: string | null; ct_count: number | null; ct_first: string | null; ct_cert_not_before: string | null;
  ct_issuers: string | null; ct_armed: number | null; ct_org: string | null;
  pdb_status: string | null; pdb_prev_poll: number | null; pdb_listed_poll: number | null; pdb_match: string | null;
  verdict?: Verdict;
}
export interface LiveCounts { certs?: number; names?: number; uniq?: number; flags?: number; naive?: number; genuine?: number;
  both_hit?: number; naive_only?: number; doppel_only?: number; dropped?: number; errors?: number; minutes?: number }
export interface LiveCollectorState {
  mode: "live" | "replay"; pid: number; started: number; written: number; stream_now: number | null; connected: boolean;
  rate_names_s: number; queue: number; reconnects: number; dropped: number; last_message_age_s: number | null;
  session_totals: LiveCounts; ticker: LiveTick[]; stopped?: boolean;
  ct: { enabled: boolean; daily_cap?: number; used_today?: number; pending?: number; every_s?: number | null };
  watch_size: number; replay: { first?: number; position?: number; messages?: number; finished?: boolean; speed: number } | null;
  pdb: { poll_t: number | null; size: number; every_h: number } | null;
}
export interface LiveArming { id: number; owner: string; name: string; t: number; watch_added: number; brand: string | null; risk: number | null; label: string | null }
export interface LiveAlarm { id: number; kind: string; t: number; message: string; resolved: number | null }
export interface LiveLeadRow { name: string; source: string; brand: string | null; flagged: number; lead_min_h: number; lead_max_h: number; match: string }
export interface LiveSummary {
  totals: LiveCounts; hours_watched: number; catches: Record<string, number>;
  watch: { watched: number; armed: number; cert_known_at_add: number };
  lead: { listed_after: number; median_min_h: number | null; rows: LiveLeadRow[]; by_status: Record<string, number> }; polls: number;
}
export interface LiveResponse {
  mode: "live" | "replay"; running: boolean; state: LiveCollectorState | null; summary: LiveSummary | Record<string, never>;
  catches: LiveCatch[]; armings: LiveArming[]; alarms_open: LiveAlarm[]; alarms_recent: LiveAlarm[]; now: number;
}

// ---- Campaign Radar (P13): data/campaigns/radar.json via /api/campaigns ----
export type LinkType = "shared_cert" | "cert_recipe" | "naming_template" | "nrd_week";
export interface CampaignMember { domain: string; names: string[]; risk: number; brand: string | null; sources: string[];
  first_seen: string | null; first_cert: string | null; subdomains: string[]; armed: boolean }
export interface Campaign {
  id: string; size: number; members_ids: string[]; members: CampaignMember[]; brands: Record<string, number>;
  templates: string[]; links: Partial<Record<LinkType, number>>; strength: string; sources: string[]; armed: string[];
  recipe: { shapes: string[]; issuers: Record<string, number>; first_cert: string | null; last_cert: string | null; span_h: number | null } | null;
  first_seen: string | null; last_seen: string | null; rank: number;
}
export interface CampaignGraph {
  nodes: { id: string; brand: string; risk: number; names: string[]; campaign: string | null; sources: string[] }[];
  edges: { source: string; target: string; weight: number; types: Partial<Record<LinkType, string>> }[];
}
export interface RadarResponse { generated_at: string | null; campaigns: Campaign[]; graph: CampaignGraph;
  stats: { items?: number; domains?: number; campaigns?: number; in_campaigns?: number; edges_by_type?: Record<string, number> };
  inputs?: { source: string; names?: number; flagged: number; watchlist?: number }[] }
