// Campaign Radar (P13): flagged domains linked by C18 edges; each island is a campaign. Click an island for its
// card; click a member to investigate it (source "gallery": no live lookups). Names only: nothing is visited.
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { Campaign, CampaignGraph, LinkType, RadarResponse, Verdict } from "../lib/types";

export const LINK: Record<LinkType, { text: string; color: string; dash?: string }> = {
  shared_cert: { text: "shared certificate", color: "var(--bad)" },
  cert_recipe: { text: "same certificate recipe", color: "var(--d)" },
  naming_template: { text: "same naming template", color: "var(--q)" },
  nrd_week: { text: "same NRD week", color: "var(--faint)", dash: "3 3" },
};
const CELL = 230, W = 4 * CELL;

type P = { x: number; y: number };

/** Islands on a grid (ranked), members relaxed inside each island by a small force simulation. Deterministic. */
export function layout(campaigns: Campaign[], graph: CampaignGraph): Record<string, P> {
  const pos: Record<string, P> = {};
  const cols = Math.max(1, Math.floor(W / CELL));
  campaigns.forEach((c, i) => {
    const cx = (i % cols) * CELL + CELL / 2, cy = Math.floor(i / cols) * CELL + CELL / 2;
    const ids = c.members_ids;
    const r = Math.min(CELL / 2 - 28, 18 + ids.length * 6);
    ids.forEach((id, j) => {
      const a = (2 * Math.PI * j) / ids.length;
      pos[id] = { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
    });
    const set = new Set(ids);
    const es = graph.edges.filter((e) => set.has(e.source) && set.has(e.target));
    for (let it = 0; it < 80; it++) {
      const f: Record<string, P> = Object.fromEntries(ids.map((id) => [id, { x: 0, y: 0 }]));
      for (const a of ids) for (const b of ids) {                    // repulsion
        if (a === b) continue;
        const dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y, d2 = Math.max(dx * dx + dy * dy, 1);
        f[a].x += (dx / d2) * 600; f[a].y += (dy / d2) * 600;
      }
      for (const e of es) {                                          // springs
        const a = pos[e.source], b = pos[e.target], dx = b.x - a.x, dy = b.y - a.y;
        f[e.source].x += dx * 0.02; f[e.source].y += dy * 0.02; f[e.target].x -= dx * 0.02; f[e.target].y -= dy * 0.02;
      }
      for (const id of ids) {                                        // gravity to the island centre, clamp
        f[id].x += (cx - pos[id].x) * 0.05; f[id].y += (cy - pos[id].y) * 0.05;
        pos[id] = { x: Math.min(cx + CELL / 2 - 14, Math.max(cx - CELL / 2 + 14, pos[id].x + f[id].x)),
                    y: Math.min(cy + CELL / 2 - 24, Math.max(cy - CELL / 2 + 14, pos[id].y + f[id].y)) };
      }
    }
  });
  return pos;
}

export default function Campaigns({ live, active, onOpen }: { live: boolean; active: boolean; onOpen: (v: Verdict) => void }) {
  const [r, setR] = useState<RadarResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    if (!active || !live || r) return;
    api.campaigns().then((x) => { setR(x); setSel(x.campaigns[0]?.id ?? null); })
      .catch((e) => setErr(e instanceof ApiError ? e.message : String(e)));
  }, [active, live, r]);

  const shown = useMemo(() => (r?.campaigns ?? []).slice(0, 20), [r]);
  const pos = useMemo(() => (r ? layout(shown, r.graph) : {}), [r, shown]);
  const card = shown.find((c) => c.id === sel) ?? null;
  const height = Math.ceil(shown.length / Math.floor(W / CELL)) * CELL;
  const open = async (domain: string) => {
    setBusy(domain);
    try { onOpen(await api.investigate(domain, "gallery")); }
    catch (e) { setErr(e instanceof ApiError ? e.message : String(e)); }
    finally { setBusy(null); }
  };

  return (
    <section className="pt-4 pb-8">
      <h2>Campaign Radar</h2>
      <p className="lead">Per-domain tools see N unrelated alerts. Doppel links flagged domains by evidence of a common maker: <b>a shared certificate</b> (certain), <b>the same certificate recipe</b> issued close in time, and <b>the same naming template</b> learned from the names (never a hand-written rule). Each island is a campaign. A campaign raises review priority; it never convicts a name on its own. Names only: nothing here is visited.</p>
      {!live && <div className="err mb-3">The API is offline, so the radar can't be shown.</div>}
      {err && <div className="err mb-3">{err}</div>}
      {r && (
        <p className="text-sm text-[var(--muted)] mb-2">
          {(r.stats.domains ?? 0).toLocaleString()} flagged domains → <b>{r.stats.campaigns} campaigns</b> ({r.stats.in_campaigns} domains). Inputs: {(r.inputs ?? []).map((i) => `${i.source} ${(i.names ?? i.flagged).toLocaleString()}${i.names ? ` names → ${i.flagged} flagged` : " flags"}${i.watchlist ? ` + ${i.watchlist} sleepers` : ""}`).join(" · ")}. Run {r.generated_at?.slice(0, 16).replace("T", " ")} UTC.
          {" "}{Object.entries(LINK).map(([k, l]) => <span key={k} className="legend"><svg width="22" height="8"><line x1="1" y1="4" x2="21" y2="4" stroke={l.color} strokeWidth="2.5" strokeDasharray={l.dash} /></svg>{l.text}</span>)}
        </p>)}
      <div className="radargrid">
        <div className="panel" style={{ padding: 6, overflowX: "auto" }}>
          <svg viewBox={`0 0 ${W} ${height}`} width="100%" style={{ minWidth: 640 }} role="img" aria-label="Campaign islands">
            {shown.map((c, i) => {
              const cols = Math.floor(W / CELL), cx = (i % cols) * CELL + CELL / 2, cy = Math.floor(i / cols) * CELL + CELL / 2;
              return (
                <g key={c.id} className={"island" + (sel === c.id ? " sel" : "")} onClick={() => setSel(c.id)}>
                  <rect x={cx - CELL / 2 + 5} y={cy - CELL / 2 + 5} width={CELL - 10} height={CELL - 10} rx={16} />
                  <text x={cx} y={cy + CELL / 2 - 12} textAnchor="middle" className="islandlbl">{Object.keys(c.brands)[0]} ×{c.size}{c.armed.length ? " · armed" : ""}</text>
                </g>);
            })}
            {r?.graph.edges.map((e) => {
              const a = pos[e.source], b = pos[e.target];
              if (!a || !b) return null;
              const t = (["shared_cert", "cert_recipe", "naming_template", "nrd_week"] as LinkType[]).find((k) => e.types[k]) ?? "naming_template";
              return <line key={e.source + e.target} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={LINK[t].color} strokeWidth={t === "naming_template" ? 1.5 : 2.5} strokeDasharray={LINK[t].dash} opacity={0.85} />;
            })}
            {r?.graph.nodes.filter((n) => pos[n.id]).map((n) => (
              <g key={n.id} onClick={() => setSel(n.campaign)} style={{ cursor: "pointer" }}>
                <circle cx={pos[n.id].x} cy={pos[n.id].y} r={5 + n.risk * 4} className={"rnode" + (n.sources.includes("pdb") ? " listed" : "")}><title>{n.names.join("\n")}</title></circle>
              </g>))}
          </svg>
        </div>
        <div className="panel">
          {card ? <Card c={card} busy={busy} open={open} /> : <p className="neutral">{r ? "Click an island." : "Loading…"}</p>}
        </div>
      </div>
    </section>);
}

function Card({ c, busy, open }: { c: Campaign; busy: string | null; open: (d: string) => void }) {
  return (
    <div>
      <h3>{Object.keys(c.brands).join(", ")}: {c.size} domains, one {c.links.shared_cert || c.links.cert_recipe ? "operator" : "naming habit"}</h3>
      <p className="ph">{c.strength}{c.templates[0] && <> · template <code>{c.templates[0]}</code></>}</p>
      <div className="flex flex-wrap gap-1.5 mb-2">
        {(Object.keys(c.links) as LinkType[]).map((k) => <span key={k} className="c" style={{ color: LINK[k].color }}>{LINK[k].text} ×{c.links[k]}</span>)}
        {c.sources.map((s) => <span key={s} className="c">{s === "pdb" ? "on Phishing.Database" : s === "nrd" ? "NRD sleeper" : s === "live" ? "live catch" : s}</span>)}
      </div>
      {c.recipe && (
        <p className="text-sm">Certificate recipe <code>{c.recipe.shapes.join(" / ")}</code> from {Object.keys(c.recipe.issuers).join(" + ")}; first certificates {c.recipe.first_cert?.slice(0, 16).replace("T", " ")} → {c.recipe.last_cert?.slice(0, 16).replace("T", " ")} UTC{c.recipe.span_h != null ? ` (${c.recipe.span_h} h)` : ""}.{c.armed.length ? ` Armed: ${c.armed.length} of ${c.size}.` : ""}</p>)}
      <table className="w-full text-sm mt-2"><thead><tr><th className="text-left">Member</th><th>First cert</th><th>Sub</th><th>Risk</th></tr></thead>
        <tbody>{c.members.map((m) => (
          <tr key={m.domain} className="cursor-pointer" onClick={() => open(m.names[0] ?? m.domain)} title="Investigate (no live lookups)">
            <td className="mono">{busy === (m.names[0] ?? m.domain) ? "opening…" : m.names[0] ?? m.domain}{m.names.length > 1 ? ` +${m.names.length - 1}` : ""}</td>
            <td className="mono text-xs">{m.first_cert?.slice(5, 16).replace("T", " ") ?? "-"}</td>
            <td className="mono text-xs">{m.subdomains.slice(0, 2).join(", ") || "-"}</td>
            <td>{m.risk.toFixed(2)}</td></tr>))}</tbody></table>
      <p className="text-xs text-[var(--muted)] mt-2">{c.links.shared_cert || c.links.cert_recipe
        ? "Block the recipe, not the domain: the next ending they rotate to matches it the moment its certificate appears."
        : "A naming habit alone suggests one maker; it doesn't prove it. Treat it as a review lead."}</p>
    </div>);
}
