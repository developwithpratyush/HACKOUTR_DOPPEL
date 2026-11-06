// Evidence visuals: each one draws a fact a judge can check by eye.
import { useState } from "react";
import { artifactUrl } from "../lib/api";
import { foreignChars, segment } from "../lib/edits";
import { riskPath } from "../lib/replay";
import type { BrandInfo, Edit, Evidence, Verdict } from "../lib/types";
import { PROOF_TEXT } from "../lib/vocab";

/** A name with its edit spans marked (red on the fake side, green on the genuine side). */
export function Marked({ text, edits, side = "candidate", reveal = true }:
  { text: string; edits?: Edit[]; side?: "candidate" | "genuine"; reveal?: boolean }) {
  const segs = reveal ? segment(text, edits, side) : null;
  return (
    <span className="edstr">
      {(segs ?? [{ text }]).map((s, k) => s.edit
        ? <mark key={k} className={side === "genuine" ? "g" : ""} title={`${s.edit.kind}, cost ${s.edit.cost}`}>{s.text}</mark>
        : <span key={k}>{s.text}</span>)}
    </span>
  );
}

const KIND_TEXT: Record<string, string> = {
  homoglyph: "look-alike letter from another script", twin_letters: "twin letters (reads as one)", typo: "ordinary typo",
  keyboard: "keyboard neighbour", phonetic: "sound-alike", bitflip: "one flipped bit", hyphen: "hyphen", other: "other",
};

/** The aligned swaps: fake → real, with the glyph cost (0 = identical to the eye). */
export function EditTable({ ev, verdict }: { ev: Evidence; verdict: Verdict }) {
  const edits = ev.details.edits ?? [];
  if (!edits.length) return null;
  const real = String(ev.details.genuine ?? ev.details.compared ?? "");
  const cand = verdict.input.display;
  return (
    <div className="mt-2 mb-1">
      <div className="flex flex-wrap items-center gap-2">
        <Marked text={cand} edits={edits} />
        <span className="text-[var(--muted)] font-bold">vs the real</span>
        <Marked text={real} edits={edits} side="genuine" />
      </div>
      <table className="grid mt-2" style={{ maxWidth: 620 }}>
        <thead><tr><th>fake</th><th>real</th><th>what it is</th><th title="Glyph cost from the confusability matrix: 0 = indistinguishable, 1 = obviously different">cost to the eye</th></tr></thead>
        <tbody>{edits.map((e, k) => (
          <tr key={k} style={{ cursor: "default" }}>
            <td className="mono font-bold bad">{e.candidate || "∅"}{e.codepoints?.length ? <span className="meta"> {e.codepoints.join(" ")}</span> : null}</td>
            <td className="mono font-bold ok">{e.genuine || "∅"}</td>
            <td>{KIND_TEXT[e.kind] ?? e.kind} <span className="meta">({e.op})</span></td>
            <td className="num">{e.cost.toFixed(2)}{e.cost < 0.2 ? <span className="bad"> · invisible</span> : null}</td>
          </tr>))}
        </tbody>
      </table>
    </div>
  );
}

/** Host split into the parts a browser reads: everything left of the owner is just labels the owner chose. */
export function OwnerSplit({ verdict }: { verdict: Verdict }) {
  const host = verdict.input.display;
  const owner = verdict.owner ?? "";
  const at = owner ? host.toLowerCase().lastIndexOf(owner.toLowerCase()) : -1;
  const foreign = foreignChars(host);
  return (
    <div className="mt-3">
      <div className="section-t">How the address really reads</div>
      {at > 0 ? (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="edstr"><span className="text-[var(--faint)]">{host.slice(0, at)}</span><b className="ok" style={{ color: "var(--ink)" }}>{host.slice(at)}</b></span>
          <span className="text-[var(--muted)]">← everything before <b className="mono">{owner}</b> is a label its owner typed</span>
        </div>
      ) : (
        <div className="text-sm"><span className="edstr">{host}</span> <span className="text-[var(--muted)]">owner: <b className="mono">{owner || "–"}</b></span></div>
      )}
      {foreign.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-2">
          {foreign.map((f) => (
            <span key={f.at} className="err mono" style={{ padding: "4px 9px" }}>
              position {f.at}: “{f.ch}” is <b>{f.cp}</b>, not ASCII
            </span>))}
          {verdict.domain !== host && <span className="meta self-center">punycode: {verdict.domain}</span>}
        </div>
      )}
    </div>
  );
}

const MATCH_NOTE: Record<string, string> = {
  level_squat: "starts with the real address, but", trust_signal: "copies the trust ending, but",
  skeleton: "looks identical to a family address, but", alias_token: "uses the brand's name, but",
};

/** The brand's genuine family, grouped by proof, with the candidate placed in it (or outside it). */
export function FamilyTree({ brand, ev, verdict }: { brand?: BrandInfo; ev: Evidence; verdict: Verdict }) {
  if (!brand) return null;
  const hit = ev.finding === "genuine_family" ? String(ev.details.family_entry ?? "") : "";
  const groups = ["brand_tld", "restricted_registry", "official_list"]
    .map((p) => ({ p, items: brand.family.filter((f) => f.proof === p) })).filter((g) => g.items.length);
  const ucg = brand.user_content.map((u) => u.host);
  const inUcg = ev.finding === "brand_user_content_platform";
  const imitation = ev.points_to === "phishing" || ev.finding === "restricted_registry_unlisted";
  return (
    <div className="tree">
      <div className="section-t" style={{ marginTop: 0 }}>Brand family tree (from data/brands/registry.yaml)</div>
      <span className="troot">{brand.name} · official family</span>
      <div className="tbranches">
        {groups.map((g) => (
          <div className="tbr" key={g.p}>
            <div className="bt">{PROOF_TEXT[g.p]?.[0] ?? g.p}</div>
            <div className="proof">{PROOF_TEXT[g.p]?.[1]}</div>
            {g.items.map((f) => (
              <span key={f.domain} className={"leaf" + (f.domain === hit ? " hit" : "")}
                    title={`${f.include_subdomains ? "*." : ""}${f.domain}\nsource: ${f.source ?? "–"}\nverified: ${f.verified_on ?? "not yet"}${f.note ? "\n" + f.note : ""}`}>
                {f.include_subdomains ? "*." : ""}{f.domain}{f.domain === hit ? " ✓" : ""}
              </span>))}
          </div>))}
      </div>
      {ucg.length > 0 && (
        <div className="imp">
          <span className="text-[var(--muted)] text-xs font-bold">USER CONTENT (never auto-genuine):</span>
          {ucg.map((h) => <span key={h} className="leaf ucg" style={{ display: "inline-block" }}>{h}{inUcg && verdict.input.display.endsWith(h) ? " ←" : ""}</span>)}
        </div>
      )}
      {imitation && !hit && (
        <div className="imp">
          <span className="leaf">✗ {verdict.input.display}</span>
          <span>{MATCH_NOTE[String(ev.details.matched_by)] ?? "names the brand, but"} is <b>not anywhere in the tree</b>.</span>
        </div>
      )}
      <div className="tnote">Every entry carries the URL of the brand page that proves it (hover a leaf).</div>
    </div>
  );
}

/** Closeness to each protected brand (top 3), one hue. */
export function ClosenessBars({ perBrand, names }: { perBrand: Record<string, number>; names: Record<string, string> }) {
  const rows = Object.entries(perBrand).sort((a, b) => b[1] - a[1]);
  if (!rows.length) return null;
  return (
    <div className="mt-3">
      <div className="section-t">Closeness to each protected brand</div>
      <div className="flex flex-col gap-1.5" style={{ maxWidth: 520 }}>
        {rows.map(([id, v], k) => (
          <div key={id} className="grid items-center gap-2" style={{ gridTemplateColumns: "130px 1fr 44px" }}
               title={`${names[id] ?? id}: closeness ${v.toFixed(3)}`}>
            <span className="text-[13px] truncate" style={{ fontWeight: k === 0 ? 700 : 500 }}>{names[id] ?? id}</span>
            <span style={{ background: "var(--soft2)", borderRadius: 4, height: 10, position: "relative" }}>
              <span style={{ position: "absolute", inset: 0, width: `${Math.max(1, v * 100)}%`, borderRadius: 4,
                             background: k === 0 ? "var(--q)" : "var(--q-mid)" }} />
            </span>
            <span className="num text-right">{v.toFixed(2)}</span>
          </div>))}
      </div>
      <div className="tnote">Visual edit distance: look-alike swaps cost less than ordinary typos.</div>
    </div>
  );
}

/** What the victim sees: the link inside a message, in a phone font, next to the real address. */
export function SmsView({ verdict, ev, message }: { verdict: Verdict; ev?: Evidence; message?: string }) {
  const [reveal, setReveal] = useState(false);
  const trick = verdict.evidence.find((e) => e.tool === "trick_detector" && e.details.edits?.length);
  const edits = trick?.details.edits;
  const genuine = String(trick?.details.genuine ?? verdict.evidence.find((e) => e.details.genuine)?.details.genuine ?? "");
  const link = verdict.input.display;
  const owner = verdict.owner ?? "";
  const ownerAt = owner && owner !== link ? link.toLowerCase().lastIndexOf(owner.toLowerCase()) : -1;
  const brand = verdict.target_brand?.name ?? "your bank";
  const msg = message ?? `Dear customer, your ${brand} account needs re-verification today. Tap:`;
  const segs = reveal ? segment(link, edits) : null;
  const art = ev?.details.artifacts?.[0];
  const src = art ? artifactUrl(art.path) : null;
  return (
    <div className="mt-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="section-t" style={{ margin: 0 }}>What a person sees (SMS, Roboto 16 px)</div>
        <button className="btn sm" onClick={() => setReveal((r) => !r)}>{reveal ? "Hide the trick" : "Can you spot it? Reveal"}</button>
      </div>
      <div className="grid gap-3 mt-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
        <div className="phone">
          <div className="text-xs font-bold text-[var(--muted)] mb-1.5">Received</div>
          <div className="bubble phonefont">
            <div className="sender">VM-ALERTS</div>
            {msg}{" "}
            <span className="link">
              {segs ? segs.map((s, k) => s.edit ? <mark key={k}>{s.text}</mark> : <span key={k}>{s.text}</span>)
                : reveal && ownerAt > 0 ? <><span>{link.slice(0, ownerAt)}</span><mark>{link.slice(ownerAt)}</mark></>
                : link}
            </span>
          </div>
        </div>
        {genuine && (
          <div className="phone">
            <div className="text-xs font-bold text-[var(--muted)] mb-1.5">The real address</div>
            <div className="bubble phonefont"><span className="link">{genuine}</span></div>
          </div>)}
      </div>
      {ev && (
        <div className="flex flex-wrap gap-2 mt-2">
          {typeof ev.details.ssim === "number" && <span className="c" title="Structural similarity of the two renders (1 = identical)">SSIM {ev.details.ssim.toFixed(3)}</span>}
          {typeof ev.details.visual_edit_distance === "number" && <span className="c" title="0 = reads identically">visual edit distance {ev.details.visual_edit_distance.toFixed(3)}</span>}
          {typeof ev.details.matching_prefix_chars === "number" && <span className="c">first {ev.details.matching_prefix_chars} characters identical</span>}
        </div>)}
      {src && (
        <figure className="mt-3 mb-0">
          <img src={src} alt={art?.caption ?? "Human-Eye Renderer output"} style={{ maxWidth: "100%", border: "1px solid var(--line)", borderRadius: 8, imageRendering: "pixelated" }} />
          <figcaption className="tnote">Measured by the Human-Eye Renderer: {art?.caption ?? "render"} ({art?.path}).</figcaption>
        </figure>)}
    </div>
  );
}

/** The local mock page the Page Probe read, in a sandboxed frame (no scripts, no network). */
export function PagePreview({ ev }: { ev: Evidence }) {
  const d = ev.details;
  if (ev.finding === "not_probed") {
    return <div className="tnote mt-2">Doppel never opens a domain it is judging. Only names listed in <code>demo/fixtures/sites.yaml</code> (our own local pages) have page evidence; everything else is judged by name.</div>;
  }
  return (
    <div className="mt-3">
      <div className="section-t">The page (local fixture)</div>
      <div className="flex flex-wrap gap-2 mb-2">
        <span className="c">status {String(d.status ?? "–")}</span>
        {d.title && <span className="c">title “{String(d.title)}”</span>}
        {Array.isArray(d.asks_for) && d.asks_for.length > 0 && <span className="c ink">asks for {d.asks_for.join(", ")}</span>}
        {Array.isArray(d.form_actions) && d.form_actions.length > 0 && <span className="c">form → {d.form_actions.join(", ")}</span>}
        {d.mock && <span className="pill mock">mock page, made by us</span>}
      </div>
      {typeof d.fixture === "string" && /^pages\/[\w.-]+\.html$/.test(d.fixture) && (
        <iframe title="fixture page" sandbox="" src={`/fixtures/${d.fixture}`}
                style={{ width: "100%", maxWidth: 520, height: 170, border: "1px solid var(--line)", borderRadius: 10, background: "#fff" }} />)}
      {typeof d.fixture === "string" && d.fixture.startsWith("generated/") && (
        <div className="tnote">A clone generated from the saved genuine page ({d.fixture}). It isn't framed here: its styles point at the real brand's servers. The Deep stage shows it as rendered in the sandbox.</div>)}
    </div>
  );
}

const pctOf = (x: unknown) => (typeof x === "number" ? `${Math.round(x * 100)}%` : "–");
const hostOf = (u: unknown) => { try { return new URL(String(u)).hostname; } catch { return String(u ?? ""); } };

/** Page Inspector (C10/C11): the heatmap of what a kit changed, the two renders, and the DOM diff. */
export function PageInspectorView({ items }: { items: Evidence[] }) {
  const c10 = items.find((e) => e.criterion === "C10") ?? items[0];
  const d = c10.details;
  const arts = (d.artifacts ?? []) as { kind: string; path: string; caption?: string }[];
  const heat = arts.find((a) => a.kind === "heatmap");
  const shots = arts.filter((a) => a.kind === "screenshot");
  const c11 = items.filter((e) => e.criterion === "C11");
  const sb = d.sandbox as { served_fixture?: number; served_from_har?: number; blocked?: number } | undefined;
  return (
    <div className="mt-3">
      <div className="section-t">Does it copy the real page? (content-masked SSIM, threshold {String(d.threshold ?? "")})</div>
      <div className="flex flex-wrap gap-2 mb-2">
        <span className="c ink">match {pctOf(d.masked_ssim)}</span>
        <span className="c" title="Plain SSIM counts shared white space as similar">plain SSIM {pctOf(d.ssim)}</span>
        <span className="c">pHash distance {String(d.phash_distance ?? "–")}</span>
        {Array.isArray(d.regions) && <span className="c">{d.regions.length} changed region(s)</span>}
        {Array.isArray(d.kit_edits) && d.kit_edits.length > 0 && <span className="c" title="What the fixture's kit actually changed (ground truth)">kit edits: {(d.kit_edits as string[]).join(", ").replace(/_/g, " ")}</span>}
      </div>
      {heat && artifactUrl(heat.path) && (
        <figure className="m-0">
          <img src={artifactUrl(heat.path)!} alt={heat.caption ?? "difference heatmap"} style={{ maxWidth: "100%", border: "1px solid var(--line)", borderRadius: 8 }} />
          <figcaption className="tnote">Red marks where the suspect page differs from the genuine one{Array.isArray(d.regions) && d.regions.length === 0 ? ": nothing visible (an invisible edit, such as the form target, can't show here; see the DOM diff)" : ""}.</figcaption>
        </figure>)}
      {shots.length > 0 && (
        <div className="grid gap-2 mt-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
          {shots.map((s) => artifactUrl(s.path) && (
            <figure key={s.path} className="m-0">
              <img src={artifactUrl(s.path)!} alt={s.caption ?? "screenshot"} style={{ width: "100%", border: "1px solid var(--line)", borderRadius: 8 }} />
              <figcaption className="tnote">{s.caption}</figcaption>
            </figure>))}
        </div>)}
      {c11.length > 0 && (
        <div className="mt-2">
          <div className="section-t">What they changed (DOM diff)</div>
          {c11.map((e) => (
            <div key={e.evidence_id} className="tnote" style={{ color: "var(--ink)" }}>
              {e.finding === "form_target_changed"
                ? <>Form target: <b>{String(e.details.genuine_action ?? "none")}</b> → <b>{hostOf(e.details.suspect_action)}</b> (structure {pctOf(e.details.structure_similarity)} the same)</>
                : <>Added fields: <b>{((e.details.added_inputs ?? []) as string[]).join(", ").replace(/_/g, " ")}</b></>}
            </div>))}
        </div>)}
      {sb && <div className="tnote mt-2">Sandbox: {sb.served_fixture ?? 0} page(s) from the fixture, {sb.served_from_har ?? 0} files from the genuine snapshot, {sb.blocked ?? 0} request(s) refused. No DNS: every hostname is unresolvable.</div>}
    </div>
  );
}

/** Vision AI (C12/C13): the claimed brand vs the owner, what the page asks for, and the injection guard. */
export function VisionView({ items }: { items: Evidence[] }) {
  const c12 = items.find((e) => e.criterion === "C12") ?? items[0];
  const c13 = items.find((e) => e.criterion === "C13");
  const d = c12.details;
  return (
    <div className="mt-3">
      <div className="section-t">Who does it claim to be?</div>
      <div className="flex flex-wrap gap-2 mb-2">
        <span className="c ink">claims {d.claimed_brand ? String(d.claimed_brand) : "no brand"}</span>
        <span className="c">{d.method === "offline_text" ? "offline fallback (page text)" : `${String(d.model)} · temperature 0`}{d.method === "cache" ? " · recorded answer" : ""}</span>
        {Array.isArray(d.claim_evidence) && <span className="c">from {(d.claim_evidence as string[]).join(", ").replace(/_/g, " ")}</span>}
        {c13 && Array.isArray(c13.details.asks_for) && c13.details.asks_for.length > 0 && <span className="c ink">asks for {(c13.details.asks_for as string[]).join(", ").replace(/_/g, " ")}</span>}
      </div>
      <div className="tnote">The model sees the screenshot and the page's visible text, never the address, and is asked only which brand the page presents itself as. Doppel compares that claim with the owner's family.</div>
      {typeof d.hidden_text_removed === "number" && d.hidden_text_removed > 0 && (
        <div className="tnote">Prompt-injection guard: {d.hidden_text_removed} hidden text fragment(s) removed before the model saw the page{d.injection_attempt ? ", some of them addressed to AI models" : ""}.</div>)}
    </div>
  );
}

interface Dest { host: string; relation?: string; channel?: string | null; platform?: string | null;
                 in_brand_family?: boolean; via?: string[]; fields?: string[] }
interface Outcome { state: string; why?: string; bounce?: string | null }
const CHANNEL_NAME: Record<string, string> = { telegram: "Telegram bot API", discord: "Discord webhook", google_forms: "Google Forms" };

function destTag(d: Dest, brand?: string): [string, string] {
  if (d.channel && CHANNEL_NAME[d.channel]) return [CHANNEL_NAME[d.channel], "bad"];
  if (d.in_brand_family) return [`inside ${brand ?? "the brand"}'s family`, "ok"];
  if (d.platform) return [`free-hosting relay (${d.platform})`, "bad"];
  if (d.channel === "relay") return ["form / webhook relay", "bad"];
  if (d.relation === "same_origin" || d.relation === "same_owner") return ["the page's own server", brand ? "bad" : "neutral"];
  return ["another domain", "bad"];
}

/** Credential Tracker (C14/C15): what we typed, where each value went, and what the page did after the login. */
export function CredentialTrackerView({ items }: { items: Evidence[] }) {
  const main = items.find((e) => Array.isArray(e.details.destinations)) ?? items[0];
  const d = main.details;
  const brand = items.find((e) => e.target_brand)?.target_brand?.name;
  const canaries = (d.canaries ?? []) as { field: string; value: string; traceable: boolean }[];
  const dests = (d.destinations ?? []) as Dest[];
  const outs = (d.outcomes ?? []) as Outcome[];
  const direct = items.filter((e) => e.finding.startsWith("direct_exfil_"));
  const c15 = items.filter((e) => e.criterion === "C15");
  const sbx = d.sandbox as { answered_locally?: number; refused?: number } | undefined;
  if (main.finding === "no_credential_form") {
    return <div className="tnote mt-2">Nothing to test: no visible field asks for a password, OTP, card or ID.</div>;
  }
  return (
    <div className="mt-3">
      {canaries.length > 0 && (<>
        <div className="section-t">What we typed (made-up values, new every run{d.confirm_only ? "; one session: a genuine site is only confirmed" : ""})</div>
        <div className="flex flex-wrap gap-1.5 mb-2">
          {canaries.map((c, k) => (
            <span key={k} className={"c" + (c.traceable ? " ink" : "")} title={c.traceable ? "searched for in every request" : "too short to trace reliably"}>
              {c.field.replace(/_/g, " ")} = {c.value}</span>))}
        </div></>)}
      <div className="section-t">Where it went{d.basis === "form_target_only" ? " (the form's target: no value travelled with the saved copy)" : ""}</div>
      {dests.length > 0 ? (
        <table className="grid" style={{ maxWidth: 720 }}>
          <thead><tr><th>Destination</th><th>What it is</th><th>How</th><th>Carried</th></tr></thead>
          <tbody>{dests.map((x) => {
            const [tag, tn] = destTag(x, brand);
            return (<tr key={x.host} style={{ cursor: "default" }}>
              <td className="mono"><b>{x.host}</b></td>
              <td className={tn}>{tag}</td>
              <td>{(x.via ?? []).join(", ")}</td>
              <td>{(x.fields ?? []).join(", ").replace(/_/g, " ") || "–"}</td></tr>);
          })}</tbody>
        </table>)
        : d.first_hop ? <div className="tnote">First hop: <b>{hostOf(d.first_hop)}</b></div>
        : <div className="tnote">No request carried what was typed.</div>}
      {direct.map((e) => (
        <div key={e.evidence_id} className="tnote mt-1" style={{ color: "var(--bad)" }}>
          Straight to {CHANNEL_NAME[String(e.details.channel)] ?? String(e.details.channel)}
          {e.details.token_redacted ? <> · bot token <b className="mono">{String(e.details.token_redacted)}</b></> : null}
          {" "}· answered inside the sandbox; never contacted.
        </div>))}
      {outs.length > 0 && (<>
        <div className="section-t mt-2">After the login{outs.length > 1 ? " (two different made-up logins)" : ""}</div>
        <div className="flex flex-wrap gap-1.5">
          {outs.map((o, k) => (
            <span key={k} className="c" style={o.state === "accepted" ? { background: "var(--bad-soft)", color: "var(--bad)" }
              : o.state === "rejected" ? { background: "var(--ok-soft)", color: "var(--ok)" } : undefined}>
              session {k + 1}: {o.state.replace(/_/g, " ")}{o.why ? ` (${o.why})` : ""}</span>))}
        </div>
        {c15.map((e) => <div key={e.evidence_id} className="tnote mt-1">{e.summary}</div>)}
      </>)}
      {typeof d.limitation === "string" && <div className="tnote mt-2"><b>Blind spot:</b> {d.limitation}</div>}
      {sbx && <div className="tnote">Sandbox: {sbx.answered_locally ?? 0} call(s) answered inside the sandbox, {sbx.refused ?? 0} refused; no hostname resolves, so nothing left this machine.</div>}
    </div>
  );
}

/** Risk after each step of the trace. Single series; the dashed line is fusion's phishing threshold. */
export function RiskPath({ verdict, idx, onPick }: { verdict: Verdict; idx: number; onPick: (i: number) => void }) {
  const pts = riskPath(verdict);
  if (pts.length < 2) return null;
  const n = verdict.trace.length - 1 || 1;
  const W = 400, H = 70, P = 6;
  const x = (s: number) => P + (s / n) * (W - 2 * P);
  const y = (r: number) => H - P - r * (H - 2 * P);
  const seen = pts.filter((p) => p.step <= idx);
  const line = (ps: typeof pts) => ps.map((p, k) => `${k ? "L" : "M"}${x(p.step).toFixed(1)},${y(p.risk).toFixed(1)}`).join("");
  return (
    <div className="mb-3">
      <div className="flex justify-between text-[11.5px] text-[var(--muted)]"><span>risk score after each step</span><span>dashed: 0.85, needed for PHISHING</span></div>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} role="img" aria-label="Risk path">
        <rect x={P} y={P} width={W - 2 * P} height={H - 2 * P} fill="var(--soft)" rx="6" />
        <line x1={P} x2={W - P} y1={y(0.85)} y2={y(0.85)} stroke="var(--faint)" strokeDasharray="3 3" strokeWidth="1" />
        <path d={line(pts)} fill="none" stroke="var(--line)" strokeWidth="2" />
        {seen.length > 1 && <path d={line(seen)} fill="none" stroke="var(--ink)" strokeWidth="2" />}
        {pts.filter((p) => p.kind === "tool").map((p) => (
          <g key={p.step} onClick={() => onPick(p.step)} style={{ cursor: "pointer" }}>
            <circle cx={x(p.step)} cy={y(p.risk)} r="12" fill="transparent" />
            <circle cx={x(p.step)} cy={y(p.risk)} r={p.step === idx ? 5 : 4} fill={p.step <= idx ? "var(--ink)" : "#fff"}
                    stroke={p.step <= idx ? "#fff" : "var(--faint)"} strokeWidth="2" />
            <title>{`step ${p.step + 1} · ${p.tool ?? p.kind}: risk ${p.risk.toFixed(3)}`}</title>
          </g>))}
      </svg>
    </div>
  );
}
