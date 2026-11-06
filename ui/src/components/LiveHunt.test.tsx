// P12 Live Hunt: the replay clock, and what a flag card says (rendered on the server, no DOM needed).
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { LiveCatch, LiveResponse } from "../lib/types";
import { FlagCard, streamNow, TickRow } from "./LiveHunt";

const state = (mode: "live" | "replay", running: boolean) => ({
  mode, running, now: 0, summary: {}, catches: [], armings: [], alarms_open: [], alarms_recent: [],
  state: { stream_now: 1000, written: 2000, replay: { speed: 2 } },
}) as unknown as LiveResponse;

describe("streamNow", () => {
  it("is the wall clock live, and the recording's own clock in a replay", () => {
    expect(streamNow(state("live", true), 2005)).toBe(2005);
    expect(streamNow(state("replay", true), 2005)).toBe(1010);      // 5 s of wall time at 2x
    expect(streamNow(state("replay", false), 2005)).toBe(1000);     // a finished replay stops its clock
    expect(streamNow(null, 7)).toBe(7);
  });
});

const card: LiveCatch = {
  name: "verificationgooglepaytramsaction729463.pages.dev", owner: "verificationgooglepaytramsaction729463.pages.dev",
  brand: "google", label: "needs_review", risk: 0.91, tricks: "combosquat,brand_closeness", reason: "x",
  first_seen: Date.parse("2026-11-06T03:44:22Z") / 1000, last_seen: 0, times_seen: 1, naive: null, platform: "pages.dev",
  stream_issuer: null, stream_not_before: null, ct_status: "looked_up", ct_count: 2, ct_first: "2026-11-06T03:43:41Z",
  ct_cert_not_before: "2026-11-06T03:43:41Z", ct_issuers: '{"Google Trust Services": 2}', ct_armed: 1, ct_org: null,
  pdb_status: "listed_after", pdb_prev_poll: null, pdb_listed_poll: null, pdb_match: "exact",
};

describe("FlagCard", () => {
  it("shows the stream timer, the trick, the CT facts and the lead", () => {
    const html = renderToString(<FlagCard c={card} now={card.first_seen + 75} busy={false} onOpen={() => undefined} />).replace(/<!-- -->/g, "");
    expect(html).toContain("in CT log 75 s ago");
    expect(html).toContain("brand + extra words");
    expect(html).toContain("no keyword would fire");
    expect(html).toContain("41 s before it reached the stream");
    expect(html).toContain("Doppel flagged it before Phishing.Database");
  });
  it("fades benign ticker rows and marks keyword hits", () => {
    const html = renderToString(<TickRow x={{ name: "lesbian-bills.com", t: 10, label: "benign", brand: null, naive: "sbi", risk: 0.1 }} now={12} />);
    expect(html).toContain("faded");
    expect(html.replace(/<!-- -->/g, "")).toContain("kw: sbi");
  });
});
