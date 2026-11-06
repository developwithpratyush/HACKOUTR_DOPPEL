// The visual vocabulary of demo/ideation-simulation.html: 9 questions in 3 stages, 15 checks, 5 labels.
// P11 adds two questions (Q4 certificate identity, S4 certificate history) and checks C16-C18.
import type { Evidence, Label, PointsTo, Provisional, Stage } from "./types";

export const CHECKS: Record<string, string> = {
  C1: "Real owner", C2: "Brand family proof", C3: "Hidden letters", C4: "Closeness to a brand",
  C5: "Trick pattern", C6: "Ending type", C7: "Human confusability", C8: "ML risk", C9: "Page status",
  C10: "Visual copy", C11: "Code changes", C12: "Claimed brand vs owner", C13: "What it asks for",
  C14: "Where the password goes", C15: "Behaviour after login",
  C16: "Certificate identity", C17: "Certificate history", C18: "Campaign link",
};

export interface Block { id: string; stage: Stage; title: string; tool: string; toolName: string; checks: string[];
                         phase?: string }

// `phase` = the build phase that brings a tool that doesn't exist yet (shown honestly as "not built yet").
export const BLOCKS: Block[] = [
  { id: "Q1", stage: "quick", title: "Who really owns it?", tool: "address_reader", toolName: "Address Reader", checks: ["C1", "C3"] },
  { id: "Q2", stage: "quick", title: "Is it the brand's own family?", tool: "family_verifier", toolName: "Family Verifier", checks: ["C2"] },
  { id: "Q3", stage: "quick", title: "Which trick is it using?", tool: "trick_detector", toolName: "Trick Detector", checks: ["C4", "C5", "C6"] },
  { id: "Q4", stage: "quick", title: "Does its certificate prove who it is?", tool: "cert_forensics", toolName: "Certificate Forensics", checks: ["C16"] },
  { id: "S1", stage: "standard", title: "Would a person notice?", tool: "human_eye_renderer", toolName: "Human-Eye Renderer", checks: ["C7"] },
  { id: "S2", stage: "standard", title: "What does the ML model say?", tool: "risk_model", toolName: "Risk Model", checks: ["C8"] },
  { id: "S3", stage: "standard", title: "Is there a live page?", tool: "page_probe", toolName: "Page Probe", checks: ["C9"] },
  { id: "S4", stage: "standard", title: "What do the CT logs say?", tool: "ct_history", toolName: "CT History", checks: ["C16", "C17"] },
  { id: "S5", stage: "standard", title: "Is it part of a campaign?", tool: "campaign_radar", toolName: "Campaign Radar", checks: ["C18"] },
  { id: "D1", stage: "deep", title: "Does it copy the real page?", tool: "page_inspector", toolName: "Page Inspector", checks: ["C10", "C11"] },
  { id: "D2", stage: "deep", title: "Who does it claim to be?", tool: "vision_ai", toolName: "Vision AI", checks: ["C12", "C13"] },
  { id: "D3", stage: "deep", title: "Where does the password go?", tool: "credential_tracker", toolName: "Credential Tracker", checks: ["C14", "C15"] },
];
export const BLOCK_BY_TOOL = Object.fromEntries(BLOCKS.map((b) => [b.tool, b])) as Record<string, Block>;

export const STAGES: { id: Stage; name: string; why: string; short: "q" | "s" | "d" }[] = [
  { id: "quick", name: "STAGE 1 · QUICK", why: "reads the name", short: "q" },
  { id: "standard", name: "STAGE 2 · STANDARD", why: "judges it like a human", short: "s" },
  { id: "deep", name: "STAGE 3 · DEEP", why: "opens the page safely", short: "d" },
];
export const STAGE_SHORT: Record<Stage, "q" | "s" | "d"> = { quick: "q", standard: "s", deep: "d" };

export const LABELS: { id: Label; text: string; sub: string; cls: string }[] = [
  { id: "genuine", text: "GENUINE", sub: "proven brand family", cls: "GENUINE" },
  { id: "phishing", text: "PHISHING", sub: "imitates + steals", cls: "PHISHING" },
  { id: "sleeper", text: "SLEEPER", sub: "look-alike, no page yet", cls: "SLEEPER" },
  { id: "needs_review", text: "NEEDS REVIEW", sub: "uncertain band", cls: "REVIEW" },
  { id: "benign", text: "BENIGN", sub: "not imitating anyone", cls: "BENIGN" },
];
export const LABEL_CLS: Record<Label, string> = Object.fromEntries(LABELS.map((l) => [l.id, l.cls])) as Record<Label, string>;
export const labelText = (l: Provisional) => (l === "needs_review" ? "NEEDS REVIEW" : l.toUpperCase());

export const PROOF_TEXT: Record<string, [string, string]> = {
  brand_tld: ["Brand-owned ending", "only the brand can register it (IANA)"],
  restricted_registry: ["Restricted registry", "only vetted entities can register"],
  official_list: ["Official list", "named on the brand's own pages (source recorded)"],
  certificate_san: ["Certificate", "on the brand's own certificate, next to a proven name (P11)"],
};

export const TRICK_TEXT: Record<string, string> = {
  homoglyph: "hidden look-alike letter", twin_letters: "twin letters", typo: "typo", bitsquat: "bit-flip",
  soundsquat: "sound-alike", combosquat: "brand + extra words", level_squat: "real address as a disguise",
  trust_signal_mimicry: "copied trust ending", tld_swap: "ending swap",
};

export type Tone = "bad" | "ok" | "warn" | "neutral";
export const ICON: Record<Tone, string> = { bad: "✗", ok: "✓", warn: "!", neutral: "–" };

/** Colour class for one evidence item: strong/likely phishing = bad, weak phishing = warn. */
export function tone(e: { points_to: PointsTo; score: number; strength: string }): Tone {
  if (e.points_to === "neutral") return "neutral";
  if (e.points_to === "genuine") return "ok";
  return e.strength === "weak" || e.score < 0.55 ? "warn" : "bad";
}

const swaps = (e: Evidence) =>
  (e.details.edits ?? []).map((x) => `${x.candidate || "∅"}→${x.genuine || "∅"}`).join(", ");

/** A short phrase for a pipeline block (the long one is `summary`). */
export function shortFinding(e: Evidence): string {
  const d = e.details;
  switch (e.finding) {
    case "owner_resolved": return `owner = ${d.owner ?? "?"}`;
    case "owner_differs": return `owner ${d.owner ?? ""}, not ${d.embedded_domain ?? "the brand"}`;
    case "free_hosting_owner": return `free hosting on ${d.platform ?? d.private_suffix ?? "a platform"}`;
    case "ip_address_host": return "a bare IP address";
    case "mixed_script": return `hidden ${(d.scripts ?? []).filter((s: string) => s !== "Latin").join("+") || "foreign"} letter`;
    case "whole_script_confusable": return "whole name in a look-alike script";
    case "single_script": return "no hidden letters";
    case "genuine_family": return `family proven (${d.family_entry ?? ""})`;
    case "brand_user_content_platform": return "brand's user-content platform";
    case "restricted_registry_unlisted": return "vetted registry, not on the list";
    case "restricted_registry_other_entity": return "vetted registry, another entity";
    case "imitates_trust_signal": return `borrows ${d.imitated ?? "a trusted address"}`;
    case "not_in_family": return `not in ${e.target_brand?.name ?? "the brand"}'s family`;
    case "no_brand_to_verify": return "no brand to match";
    case "brand_closeness": return `closeness ${Number(d.closeness ?? e.score).toFixed(2)} to ${d.genuine ?? "brand"}`;
    case "far_from_all_brands": return "far from every brand";
    case "in_family": return "in the family: no trick";
    case "no_trick": return "no naming trick";
    case "substring_not_token": return "brand only inside another word";
    case "abused_tld": return `.${d.tld ?? "?"}: often-abused ending (weak)`;
    case "combosquat": return `${d.brand_alias ?? "brand"} + ${(d.lure_words ?? []).map((w: any) => w.word).join(", ") || "extra words"}`;
    case "homoglyph": case "twin_letters": case "typo": case "bitsquat":
      return `${TRICK_TEXT[e.finding]} ${swaps(e)}`.trim();
    case "level_squat": return `real address ${d.genuine ?? ""} as a prefix`;
    case "trust_signal_mimicry": return `rebuilt trust ending (${d.genuine ?? ""})`;
    case "tld_swap": return `ending swap of ${d.genuine ?? "the brand"}`;
    case "soundsquat": return `sounds like ${d.genuine ?? "the brand"}`;
    case "sms_view_identical": return "identical in an SMS";
    case "sms_view_near_identical": return `reads as ${e.target_brand?.name ?? "the brand"} (SSIM ${fmt(d.ssim)})`;
    case "sms_view_prefix_match": return "starts with the real address";
    case "sms_view_brand_prominent": return "brand name stands out";
    case "sms_view_distinct": return `a reader could notice (SSIM ${fmt(d.ssim)})`;
    case "live_login_form": return `live login form${d.asks_for ? ` (${d.asks_for.join(", ")})` : ""}`;
    case "live_payment_form": return `live payment form${d.asks_for ? ` (${d.asks_for.join(", ")})` : ""}`;
    case "live_no_credentials": return "live page, asks for nothing";
    case "parked": return "parked: no page yet";
    case "no_page": return "no page at all";
    case "not_probed": return "not opened (names only)";
    case "ml_risk": return `ML risk ${fmt(d.probability)}`;
    case "visual_match": return `copies ${e.target_brand?.name ?? "a brand"}'s page (${pct(e.score)})`;
    case "matches_genuine_snapshot": return `matches the saved genuine page (${pct(e.score)})`;
    case "visual_mismatch": return "copies no saved genuine page";
    case "no_genuine_snapshot": return "no genuine snapshot to compare";
    case "form_target_changed": return `form now posts to ${host(d.suspect_action)}`;
    case "fields_added": return `fields added: ${list(d.added_inputs)}`;
    case "claimed_brand_mismatch": return `claims ${String(d.claimed_brand)}; owner isn't theirs`;
    case "claimed_brand_matches_owner": return `claims ${String(d.claimed_brand)}; owner matches`;
    case "claims_unprotected_brand": return `claims ${String(d.claimed_brand)} (not protected)`;
    case "no_brand_claim": return "claims no brand";
    case "asks_sensitive": return `asks for ${list(d.asks_for)}`;
    case "asks_nothing_sensitive": return "asks for nothing sensitive";
    case "direct_exfil_telegram": return "password → Telegram";
    case "direct_exfil_discord": return "password → Discord webhook";
    case "direct_exfil_google_forms": return "password → Google Forms";
    case "credentials_to_foreign_domain": return `password → ${leaving(d) || "outside the family"}`;
    case "credentials_stay_in_family": return "login stays in the family";
    case "credentials_to_page_owner": return "password → the page's own server";
    case "accepts_any_credentials": return "accepts any password";
    case "redirects_to_real_brand": return `then bounces to the real ${host(d.redirect_to)}`;
    case "rejects_wrong_credentials": return "rejects wrong logins";
    case "no_credential_form": return "no login form to test";
    case "no_credentials_sent": return "nothing left when submitted";
    case "certificate_san_link": return `on ${e.target_brand?.name ?? "the brand"}'s own certificate (${d.matched_san ?? ""})`;
    case "certificate_platform_only": return `padlock is ${d.platform ?? "the platform"}'s, not the tenant's`;
    case "no_certificate_link": return "no brand certificate lists it";
    case "certificate_organisation_match": return `validated: ${d.organisation ?? "the brand"}`;
    case "certificate_organisation_other": return `validated company: ${d.organisation ?? "?"}`;
    case "armed": return `armed: first certificate ${String(d.first_seen ?? "").slice(0, 10)}`;
    case "established_certificates": return `certificates since ${String(d.first_seen ?? "").slice(0, 10)}`;
    case "no_certificate_yet": return "no certificate yet: not armed";
    case "ct_not_checked": return "CT logs not checked";
    case "email_shaped_name": return `an email address (${d.email ?? ""})`;
    default: return e.finding.replace(/_/g, " ");
  }
}
/** Hosts outside the brand's family that a Credential Tracker item says the typed details went to. */
const leaving = (d: Record<string, any>): string => {
  const ds = Array.isArray(d.destinations) ? d.destinations : [];
  const out = ds.filter((x: any) => !x.in_brand_family && !["telegram", "discord", "google_forms"].includes(x.channel))
    .map((x: any) => (x.relation === "same_origin" || x.relation === "same_owner" ? "own server" : x.host));
  return [...new Set(out)].join(", ") || (d.first_hop ? host(d.first_hop) : "");
};
const fmt = (x: unknown) => (typeof x === "number" ? x.toFixed(2) : "–");
const pct = (x: unknown) => (typeof x === "number" ? `${Math.round(x * 100)}%` : "–");
const list = (x: unknown) => (Array.isArray(x) ? x.map((s) => String(s).replace(/_/g, " ")).join(", ") : "–");
const host = (u: unknown) => { try { return new URL(String(u)).hostname; } catch { return String(u ?? "–"); } };

/** The evidence item a block headlines: the one that moved the score most (fusion points). */
export const WEIGHT: Record<string, number> = { strong: 3, medium: 1.6, weak: 0.5 };
export const points = (e: Evidence) =>
  e.points_to === "neutral" ? 0 : (e.points_to === "phishing" ? 1 : -1) * WEIGHT[e.strength] * e.score;

export function headline(items: Evidence[]): Evidence | undefined {
  if (!items.length) return undefined;
  const ranked = [...items].sort((a, b) => Math.abs(points(b)) - Math.abs(points(a)));
  return Math.abs(points(ranked[0])) > 0 ? ranked[0] : items[0];
}
