import { describe, expect, it } from "vitest";
import type { Campaign, Evidence, Verdict } from "./types";
import { exfilFlow, generic, heat, islandLayout, nodeTone, pickCampaign, segments, trickName } from "./presenter";

const e = (criterion: string, tool: string, finding: string, points_to: Evidence["points_to"], details: Record<string, unknown> = {},
  strength: Evidence["strength"] = "medium"): Evidence =>
  ({ evidence_id: criterion + finding, tool, stage: "quick", criterion, finding, points_to, strength, score: 0, target_brand: null, summary: finding, details });

const verdict = (domain: string, owner: string, label: Verdict["label"], evidence: Evidence[]): Verdict => ({
  schema_version: "1", domain, input: { raw: domain, display: domain, source: "paste" }, owner, target_brand: { id: "parivahan", name: "Parivahan" },
  closeness: 0.75, risk_score: 1, confidence: "high", label, reason: "", hard_rule: null, counterfactual: null,
  timings_ms: { quick: 1, standard: 1, deep: null, total: 2 }, stages: [], evidence, trace: [],
  meta: { generated_at: "", engine_version: "t", mock: false },
});

const levelSquat = verdict("echallan.parivahan.gov.in.pay-fine.icu", "pay-fine.icu", "phishing", [
  e("C1", "address_reader", "owner_differs", "phishing", { embedded_domain: "parivahan.gov.in" }, "strong"),
  e("C4", "trick_detector", "brand_closeness", "phishing", { levenshtein_similarity: 0.188, genuine: "parivahan.gov.in" }),
  e("C5", "trick_detector", "level_squat", "phishing"),
  e("C8", "risk_model", "ml_risk", "phishing", { probability: 1.0 }),
  e("C13", "vision_ai", "asks_sensitive", "phishing", { asks_for: ["card_number", "otp"] }),
  e("C14", "credential_tracker", "credentials_to_foreign_domain", "phishing", { form: { action: "https://challan-pay-secure.xyz/pay.php" } }, "strong"),
]);

describe("presenter mapping", () => {
  it("splits a level-squat into decoration + real owner", () => {
    expect(segments(levelSquat).map((s) => [s.text, s.kind])).toEqual([["echallan.parivahan.gov.in.", "dec"], ["pay-fine.icu", "own"]]);
  });
  it("marks the brand token inside a combosquat", () => {
    const v = verdict("in-echallan.online", "in-echallan.online", "needs_review", [e("C5", "trick_detector", "combosquat", "phishing", { brand_alias: "echallan" })]);
    expect(segments(v).map((s) => s.kind)).toEqual(["mut", "brand", "mut"]);
    expect(heat(v).find((c) => c.ch === "h")!.h).toBeLessThan(0.1);
  });
  it("names the trick and tones the nodes from the evidence", () => {
    expect(trickName(levelSquat)).toBe("Level squat");
    expect(nodeTone(levelSquat, "address_reader")).toBe("bad");
    expect(nodeTone(levelSquat, "cert_forensics")).toBeNull();
  });
  it("computes the generic rows from the verdict, never typed", () => {
    const rows = generic(levelSquat, { parivahan: { id: "parivahan", name: "Parivahan", aliases: ["echallan"], brand_tlds: [], restricted_suffixes: [], family: [], user_content: [] } });
    expect(rows.find((r) => r.name === "Keyword filter")?.agrees).toBe(true);
    expect(rows.find((r) => r.name.startsWith("Levenshtein"))?.agrees).toBe(false);
  });
  it("follows the typed data to the receiver", () => {
    expect(exfilFlow(levelSquat).map((f) => f.text)).toEqual(["you type card number, otp", "pay-fine.icu", "challan-pay-secure.xyz"]);
  });
  it("picks the member campaign, else a related one by brand", () => {
    const c = { id: "C1", size: 3, members_ids: ["a.online", "b.online", "c.online"], brands: { parivahan: 3 }, rank: 2 } as unknown as Campaign;
    expect(pickCampaign(levelSquat, [c])).toEqual({ c, member: false });
    const m = verdict("a.online", "a.online", "needs_review", []);
    expect(pickCampaign(m, [c])?.member).toBe(true);
    expect(islandLayout(c, "a.online").centre).toBe("a.online");
  });
});
