// P13 Campaign Radar: the island layout is deterministic and keeps every member inside its own island.
import { describe, expect, it } from "vitest";
import type { Campaign, CampaignGraph } from "../lib/types";
import { layout } from "./Campaigns";

const camp = (id: string, ids: string[]) => ({ id, members_ids: ids }) as unknown as Campaign;
const cs = [camp("A", ["in-echallan.online", "in-echallan.date", "in-echallan.party", "in-echallan.trade", "ln-echallan.bid"]),
            camp("B", ["x.top", "y.top"])];
const g: CampaignGraph = { nodes: [], edges: [{ source: "in-echallan.online", target: "in-echallan.date", weight: 1.2, types: { cert_recipe: "x" } }] };

describe("layout", () => {
  it("is deterministic and keeps islands apart", () => {
    const a = layout(cs, g), b = layout(cs, g);
    expect(a).toEqual(b);
    for (const id of cs[0].members_ids) expect(a[id].x).toBeLessThan(230);       // island A is the first cell
    for (const id of cs[1].members_ids) expect(a[id].x).toBeGreaterThan(230);    // island B the second
  });
});
