// The Explorer's replay logic, on the contract's mock verdicts and on real brain verdicts.
// testdata/real-verdicts.json is a snapshot of doppel.brain output. Regenerate it when the brain changes:
// `.venv/Scripts/python.exe ui/scripts/make_testdata.py`.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { foreignChars, segment } from "./edits";
import { decisionIndex, replay, riskPath, shortGate } from "./replay";
import type { Verdict } from "./types";
import { BLOCKS, headline, shortFinding } from "./vocab";
import real from "./testdata/real-verdicts.json";

const EX = join(dirname(fileURLToPath(import.meta.url)), "../../../contracts/examples");
const mocks: Verdict[] = readdirSync(EX).filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(join(EX, f), "utf-8")));
const reals = real as unknown as Verdict[];
const all = [...mocks.map((v) => ["mock " + v.domain, v] as const), ...reals.map((v) => ["real " + v.domain, v] as const)];
const byDomain = (d: string) => reals.find((v) => v.domain === d)!;

describe.each(all)("%s", (_name, v) => {
  const last = v.trace.length - 1;
  it("ends on the verdict's label and risk", () => {
    const r = replay(v, last);
    expect(r.final).toBe(v.label);
    expect(r.risk).toBeCloseTo(v.risk_score, 3);
    expect(r.gates.a4.lit).toBe(true);
  });
  it("every block ends done, skipped or not-built, and done blocks ran", () => {
    const r = replay(v, last);
    const ran = new Set(v.trace.filter((s) => s.kind === "tool").map((s) => s.tool));
    for (const b of BLOCKS) {
      const st = r.blocks[b.id].state;
      expect(["done", "skipped", "notbuilt"]).toContain(st);
      expect(st === "done").toBe(ran.has(b.tool));
    }
  });
  it("nothing is revealed before the case opens, and tools light up in trace order", () => {
    const r0 = replay(v, -1);
    expect(Object.values(r0.blocks).every((b) => b.state === "idle" || b.state === "next")).toBe(true);
    expect(r0.final).toBeNull();
    v.trace.forEach((s, k) => {
      if (s.kind !== "tool") return;
      const id = BLOCKS.find((b) => b.tool === s.tool)!.id;
      expect(replay(v, k).blocks[id].state).toBe("active");
      if (k > 0) expect(["next", "idle"]).toContain(replay(v, k - 1).blocks[id].state);
    });
  });
  it("decision points are inside the trace and in stage order", () => {
    const q = decisionIndex(v, "standard"), d = decisionIndex(v, "deep");
    expect(q).toBeGreaterThanOrEqual(0);
    expect(d).toBeGreaterThanOrEqual(q);
    expect(d).toBeLessThanOrEqual(last);
  });
  it("risk path starts at the first tool and follows risk_after", () => {
    const p = riskPath(v);
    expect(p.length).toBeGreaterThan(0);
    expect(p[p.length - 1].risk).toBeCloseTo(v.risk_score, 3);
  });
  it("every evidence item has a short phrase", () => {
    for (const e of v.evidence) expect(shortFinding(e).length).toBeGreaterThan(2);
  });
});

describe("honest states", () => {
  it("no Deep tool is 'not built' any more (P9): a page with no login form still gets the Credential Tracker's answer", () => {
    const r = replay(byDomain("paytrn.com"), byDomain("paytrn.com").trace.length - 1);
    expect(r.blocks.D3.state).toBe("done");
    expect(r.blocks.D3.res?.text).toBe("no login form to test");
  });
  it("the Risk Model (P7) runs in Standard and its block shows the ML risk", () => {
    const v = byDomain("paytrn.com");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.S2.state).toBe("done");
    expect(r.blocks.S2.res?.text).toMatch(/^ML risk 0\.\d\d$/);
  });
  it("the Deep stage shows the Page Inspector, the Vision AI and the Credential Tracker (P9) results", () => {
    const v = byDomain("kx72-secure.top");
    const r = replay(v, v.trace.length - 1);
    expect(v.label).toBe("phishing");
    expect(r.blocks.D1.state).toBe("done");
    expect(r.blocks.D1.res?.text).toMatch(/copies State Bank of India's page/);
    expect(r.blocks.D2.state).toBe("done");
    expect(r.blocks.D2.res?.text).toMatch(/claims State Bank of India; owner isn't theirs/);
    expect(r.blocks.D3.state).toBe("done");
    expect(r.blocks.D3.res?.text).toBe("password → Telegram");
    expect(r.blocks.D3.res?.tone).toBe("bad");
  });
  it("the kit clone's hard rules: H2 decides, H3 and H4 also fired, and the rule step is marked as a phishing rule", () => {
    const v = byDomain("kx72-secure.top");
    expect(v.hard_rule?.id).toBe("H2_brand_claim_foreign_credentials");
    expect(v.hard_rule?.also_fired).toEqual(["H3_accepts_any_credentials", "H4_direct_exfil_channel"]);
    expect(replay(v, v.trace.length - 1).hardRule).toBe(true);
    const tokenShaped = /[0-9]{8,10}:[A-Za-z0-9_-]{35}/;
    expect(tokenShaped.test(JSON.stringify(v))).toBe(false);          // the bot token is redacted everywhere
  });
  it("a genuine page's login stays in the family, and H1 cites it", () => {
    const v = byDomain("onlinesbi.sbi.bank.in");
    const stay = v.evidence.find((e) => e.finding === "credentials_stay_in_family")!;
    expect(v.hard_rule?.evidence_ids).toContain(stay.evidence_id);
    expect(replay(v, v.trace.length - 1).blocks.D3.res?.text).toBe("login stays in the family");
  });
  it("the e-Challan clone's card details go to the foreign collector", () => {
    const v = byDomain("echallan.parivahan.gov.in.pay-fine.icu");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.D3.res?.text).toBe("password → challan-pay-secure.xyz");
  });
  it("a page-probe fixture that is a generated clone is never framed (it would load the real brand's assets)", () => {
    const v = byDomain("kx72-secure.top");
    const probe = v.evidence.find((e) => e.tool === "page_probe")!;
    expect(String(probe.details.fixture)).toMatch(/^generated\//);
  });
  it("a proven family member skips the Risk Model by choice (H1 decides), not 'not built'", () => {
    const v = byDomain("onlinesbi.sbi.bank.in");
    const r = replay(v, v.trace.length - 1);
    expect(v.label).toBe("genuine");
    expect(r.blocks.S2.state).toBe("skipped");
    expect(r.blocks.S2.note).toContain("ownership proven");
  });
  it("a sleeper's Deep stage is skipped by the brain (no page), not 'not built'", () => {
    const v = byDomain("sbi-kyc-update.in");
    expect(replay(v, v.trace.length - 1).blocks.D1.state).toBe("skipped");
  });
  it("a batch name with no brand stops after Quick", () => {
    const v = byDomain("thanksbitcoin.com");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.S3.state).toBe("skipped");
    expect(r.gates.a2.text).toBe("no signal → stop");
  });
  it("the renderer is skipped (no brand to compare) when Standard runs without a brand", () => {
    const v = byDomain("kx72-secure.top");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.S1.state).toBe("skipped");
    expect(r.blocks.S3.state).toBe("done");
  });
  it("H1 marks the hard rule on a genuine verdict", () => {
    const v = byDomain("onlinesbi.sbi.bank.in");
    expect(replay(v, v.trace.length - 1).hardRule).toBe(true);
  });
});

describe("headline and gates", () => {
  it("the trick block headlines the twin-letter swap", () => {
    const v = byDomain("paytrn.com");
    const step = v.trace.find((s) => s.tool === "trick_detector")!;
    const h = headline(v.evidence.filter((e) => step.evidence_ids!.includes(e.evidence_id)))!;
    expect(shortFinding(h)).toMatch(/rn→m|closeness/);
  });
  it("policy messages map to short gate labels", () => {
    expect(shortGate("Brand signal found, so go to Stage 2 (Standard).")[0]).toBe("brand signal → Standard");
    expect(shortGate("Skip Stage 3 (Deep): No live page (parked or empty): nothing to open.")[0]).toBe("no page → watch-list");
  });
});

describe("edit spans", () => {
  it("marks rn in paytrn.com and m in paytm.com", () => {
    const e = byDomain("paytrn.com").evidence.find((x) => x.finding === "twin_letters")!.details.edits!;
    expect(segment("paytrn.com", e)!.find((s) => s.edit)!.text).toBe("rn");
    expect(segment("paytm.com", e, "genuine")!.find((s) => s.edit)!.text).toBe("m");
  });
  it("marks the Cyrillic а by code point, not UTF-16 unit", () => {
    const v = byDomain("xn--pytm-53d.com");
    const e = v.evidence.find((x) => x.finding === "homoglyph")!.details.edits!;
    expect(segment(v.input.display, e)!.find((s) => s.edit)!.text).toBe("а");
    expect(foreignChars(v.input.display)).toEqual([{ ch: "а", at: 1, cp: "U+0430" }]);
  });
  it("gives up (null) rather than mark the wrong letters", () => {
    const e = byDomain("paytrn.com").evidence.find((x) => x.finding === "twin_letters")!.details.edits!;
    expect(segment("example.org", e)).toBeNull();
  });
});

describe("P11 Certificate Forensics blocks", () => {
  it("Q4 headlines the certificate proof for google.co.in, and the label is GENUINE", () => {
    const v = byDomain("google.co.in");
    expect(v.label).toBe("genuine");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.Q4.state).toBe("done");
    expect(r.blocks.Q4.res?.text).toContain("own certificate");
    expect(r.blocks.Q4.res?.tone).toBe("ok");
  });
  it("Q4 says the padlock belongs to the platform on a web.app scam", () => {
    const v = byDomain("hdfc-pan-up-date2.web.app");
    expect(replay(v, v.trace.length - 1).blocks.Q4.res?.text).toContain("web.app");
    expect(v.label).toBe("needs_review");
  });
  it("S4 shows the validated company from CT logs for sbicard.com", () => {
    const v = byDomain("sbicard.com");
    const r = replay(v, v.trace.length - 1);
    expect(r.blocks.S4.state).toBe("done");
    expect(v.evidence.some((e) => e.finding === "certificate_organisation_other")).toBe(true);
  });
});
