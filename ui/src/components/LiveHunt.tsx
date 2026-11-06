// Live Hunt (P12): the world's new certificates, judged as they appear. The collector is its own process
// (`doppel live run`); this screen polls /api/live/state once a second. REPLAY mode re-feeds recorded stream hours
// at 1x with their real timestamps and says so on screen. Names only: Doppel never visits any of these.
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../lib/api";
import type { LiveCatch, LiveResponse, LiveSummary, LiveTick, Verdict } from "../lib/types";
import { LABEL_CLS, labelText, TRICK_TEXT } from "../lib/vocab";

type Mode = "live" | "replay";
const n = (x?: number | null) => (x ?? 0).toLocaleString();
const clock = (t: number) => new Date(t * 1000).toLocaleTimeString("en-IN", { hour12: false });
const ago = (s: number) => (s < 0 ? "0 s" : s < 90 ? `${Math.floor(s)} s` : s < 5400 ? `${Math.floor(s / 60)} min` :
  s < 172800 ? `${(s / 3600).toFixed(1)} h` : `${Math.floor(s / 86400)} d`);
const iso = (s: string | null) => (s ? Date.parse(s.endsWith("Z") ? s : s + "Z") / 1000 : null);
const PDB: Record<string, string> = {
  listed_before: "already on Phishing.Database when flagged", listed_after: "Doppel flagged it before Phishing.Database",
  listed_same_window: "listed within the same poll window", not_listed: "not on Phishing.Database",
};

export function streamNow(r: LiveResponse | null, wallNow: number): number {
  // live: the wall clock. replay: the recording's clock, advanced since the collector last wrote its state.
  const st = r?.state;
  if (!st || r?.mode !== "replay" || st.stream_now == null) return wallNow;
  return st.stream_now + (r!.running ? Math.max(0, wallNow - st.written) * (st.replay?.speed ?? 1) : 0);
}

export default function LiveHunt({ live, active, onOpen }: { live: boolean; active: boolean; onOpen: (v: Verdict) => void }) {
  const [mode, setMode] = useState<Mode>("live");
  const [r, setR] = useState<LiveResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [wall, setWall] = useState(Date.now() / 1000);
  const [opening, setOpening] = useState<string | null>(null);

  useEffect(() => {
    if (!active || !live) return;
    let stop = false;
    const poll = () => api.live(mode).then((x) => { if (!stop) { setR(x); setErr(null); } })
      .catch((e) => !stop && setErr(e instanceof ApiError ? e.message : String(e)));
    poll();
    const t = setInterval(() => { poll(); setWall(Date.now() / 1000); }, 1000);
    return () => { stop = true; clearInterval(t); };
  }, [active, live, mode]);

  const open = async (name: string) => {
    setOpening(name);
    try { const c = await api.liveCatch(name, mode); if (c.verdict) onOpen(c.verdict); }
    catch (e) { setErr(e instanceof ApiError ? e.message : String(e)); }
    finally { setOpening(null); }
  };

  const st = r?.state ?? null;
  const sum = r?.summary && "totals" in r.summary ? (r.summary as LiveSummary) : null;
  const now = streamNow(r, wall);
  const session = st?.session_totals ?? {};
  const stale = !!r && !r.running;
  const ticker = useMemo(() => [...(st?.ticker ?? [])].reverse().slice(0, 28), [st]);

  return (
    <section className="pt-4 pb-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2>Live Hunt {mode === "replay" && <span className="replaybadge">REPLAY</span>}</h2>
          <p className="lead">Every new HTTPS certificate on the planet is logged in Certificate Transparency. Doppel reads that public stream, judges every new name as it appears, and keeps a queue an analyst can work. A naive keyword alert runs on the same names, side by side. <b>Names only:</b> Doppel never opens any of these sites.</p>
        </div>
        <div className="flex gap-1.5 items-center">
          {(["live", "replay"] as Mode[]).map((m) => (
            <button key={m} className={"btn sm" + (mode === m ? " go" : "")} onClick={() => { setR(null); setMode(m); }}>{m === "live" ? "Live stream" : "Recorded replay"}</button>))}
        </div>
      </div>
      {!live && <div className="err mb-3">The API is offline, so the Live Hunt can't be shown.</div>}
      {err && <div className="err mb-3">{err}</div>}
      <StatusBar r={r} mode={mode} now={now} />
      {mode === "replay" && <ReplayControls r={r} />}
      {(r?.alarms_open ?? []).map((a) => (
        <div key={a.id} className="alarm"><b>⚠ {a.kind.replace("_", " ")}</b> {a.message} <span className="mono">since {clock(a.t)}</span></div>))}

      <div className="livecounts">
        <div className="tile big naive"><span>Naive keyword alerts</span><b>{n(session.naive)}</b><small>a brand name anywhere in the name</small></div>
        <div className="tile big doppel"><span>Doppel flags</span><b>{n(session.flags)}</b><small>{session.naive && session.flags ? `${(session.naive / session.flags).toFixed(1)}× fewer than the keyword alert` : "an analyst's queue"}</small></div>
        <div className="tile"><b>{n(session.certs)}</b><span>certificates watched</span></div>
        <div className="tile"><b>{n(session.uniq)}</b><span>unique names judged</span></div>
        <div className="tile"><b className="ok">{n(session.genuine)}</b><span>proven genuine (brands' own new names)</span></div>
        <div className="tile"><b>{n(session.naive_only)}</b><span>keyword alerts Doppel cleared (noise)</span></div>
        <div className="tile"><b className="bad">{n(session.doppel_only)}</b><span>caught with no brand spelled out (no keyword fires)</span></div>
        <div className="tile"><b>{st ? `${st.rate_names_s.toLocaleString()}/s` : "-"}</b><span>names per second{st?.queue ? ` · backlog ${n(st.queue)}` : ""}</span></div>
      </div>
      <p className="text-xs text-[var(--muted)] -mt-1 mb-3">Counters since this {mode === "replay" ? "replay" : "collector run"} started{st ? ` (${clock(st.started)})` : ""}.
        {sum && <> All time: <b>{sum.hours_watched.toFixed(1)} h</b> watched, {n(sum.totals.certs)} certificates, {n(sum.totals.uniq)} unique names, {n(sum.totals.flags)} Doppel flags vs {n(sum.totals.naive)} keyword alerts.</>}</p>

      <div className="livegrid">
        <div className="panel">
          <h3>The stream</h3>
          <p className="ph">Real names as they arrive (a sample of benign ones, every flag, every proven genuine name).</p>
          <ul className="ticker">
            {ticker.map((x) => <TickRow key={x.name + x.t} x={x} now={now} />)}
            {!ticker.length && <li className="neutral">{stale ? "The collector isn't running." : "Waiting for the stream…"}</li>}
          </ul>
        </div>
        <div className="panel">
          <h3>Flagged, newest first</h3>
          <p className="ph">Click a card for its Decision Trace (the verdict as judged at that moment).</p>
          {(r?.armings ?? []).slice(0, 3).map((a) => (
            <button key={a.id} className="flagcard armed" onClick={() => open(a.name)}>
              <div className="flex justify-between gap-2"><b>ARMED</b><span className="mono">{ago(now - a.t)} ago</span></div>
              <div className="mono dom">{a.name}</div>
              <div className="text-xs">A watched sleeper (<span className="mono">{a.owner}</span>, on the watch list since {new Date(a.watch_added * 1000).toLocaleDateString("en-IN")}) just got a certificate: it's getting ready to go live.</div>
            </button>))}
          <div className="cards">
            {(r?.catches ?? []).slice(0, 14).map((c) => <FlagCard key={c.name} c={c} now={now} busy={opening === c.name} onOpen={() => open(c.name)} />)}
            {r && !r.catches.length && <p className="neutral text-sm">No flags yet.</p>}
          </div>
        </div>
      </div>
      {sum && <Lead sum={sum} />}
    </section>
  );
}

function StatusBar({ r, mode, now }: { r: LiveResponse | null; mode: Mode; now: number }) {
  const st = r?.state;
  if (!r) return <div className="statusbar"><span className="pill off"><span className="dot" />connecting…</span></div>;
  if (!st) return (
    <div className="statusbar"><span className="pill off"><span className="dot" />no {mode} collector has run yet</span>
      <span className="text-sm text-[var(--muted)]">{mode === "live" ? <>Start it: <code>doppel live run</code></> : "Start a replay below."}</span></div>);
  const stale = !r.running;
  return (
    <div className="statusbar">
      {stale ? <span className="pill off"><span className="dot" />{mode === "replay" && st.replay?.finished ? "replay finished" : `collector not running · last update ${clock(st.written)}`}</span>
        : mode === "replay" ? <span className="pill mock"><span className="dot" />REPLAY of {st.replay?.first ? new Date(st.replay.first * 1000).toLocaleString("en-IN") : "a recording"} · {st.replay?.speed ?? 1}× · now {clock(now)}</span>
        : st.connected ? <span className="pill live"><span className="dot" />LIVE · wss://api.certstream.dev · {st.rate_names_s.toLocaleString()} names/s</span>
        : <span className="pill off"><span className="dot" />reconnecting…</span>}
      <span className="text-xs text-[var(--muted)]">
        {st.reconnects ? `${st.reconnects} reconnect${st.reconnects > 1 ? "s" : ""} · ` : ""}
        {st.ct?.enabled ? `CT lookups ${st.ct.used_today}/${st.ct.daily_cap} today (flagged names only) · ` : ""}
        {st.watch_size ? `${n(st.watch_size)} sleepers watched · ` : ""}
        {st.pdb?.poll_t ? `Phishing.Database polled ${clock(st.pdb.poll_t)} (${n(st.pdb.size)} names)` : ""}
      </span>
    </div>);
}

function ReplayControls({ r }: { r: LiveResponse | null }) {
  const [msg, setMsg] = useState<string | null>(null);
  const running = !!r?.running;
  return (
    <div className="flex flex-wrap gap-2 items-center mb-3">
      {running ? <button className="btn sm" onClick={() => api.stopReplay().then(() => setMsg("Stopping…"))}>Stop replay</button>
        : <button className="btn sm go" onClick={() => api.startReplay().then((x) => setMsg(`Replay started (pid ${x.pid}): the latest complete recorded hour, at 1×.`)).catch((e) => setMsg(String(e.message ?? e)))}>Replay the latest recorded hour</button>}
      <span className="text-xs text-[var(--muted)]">{msg ?? "Recorded stream hours re-fed at 1× with their real timestamps. No network: works with the internet off."}</span>
    </div>);
}

export function TickRow({ x, now }: { x: LiveTick; now: number }) {
  const cls = x.label === "benign" ? "faded" : LABEL_CLS[x.label];
  return (
    <li className={"tick " + cls}>
      <span className="mono nm">{x.name}</span>
      <span className="flex gap-1.5 items-center shrink-0">
        {x.naive && <span className="c" title="the naive keyword alert fired">kw: {x.naive}</span>}
        {x.label !== "benign" && <span className={"lab " + LABEL_CLS[x.label]}>{labelText(x.label)}</span>}
        <span className="mono t">{ago(now - x.t)}</span>
      </span>
    </li>);
}

export function FlagCard({ c, now, busy, onOpen }: { c: LiveCatch; now: number; busy: boolean; onOpen: () => void }) {
  const tricks = (c.tricks ?? "").split(",").filter((t) => TRICK_TEXT[t]);
  const nb = iso(c.ct_cert_not_before);
  const issuers = c.ct_issuers ? Object.keys(JSON.parse(c.ct_issuers) as Record<string, number>) : [];
  return (
    <button className={"flagcard " + LABEL_CLS[c.label]} onClick={onOpen} disabled={busy}>
      <div className="flex justify-between gap-2 items-center">
        <span className={"lab " + LABEL_CLS[c.label]}>{labelText(c.label)}{c.brand ? ` · ${c.brand}` : ""}</span>
        <span className="mono timer" title="time since the name first appeared in the CT stream (a certificate is logged as it's issued)">in CT log {ago(now - c.first_seen)} ago</span>
      </div>
      <div className="mono dom">{c.name}</div>
      <div className="text-xs text-[var(--muted)]">
        {tricks.map((t) => TRICK_TEXT[t]).join(" · ") || "brand signal"} · risk {c.risk.toFixed(2)}
        {c.naive ? ` · keyword "${c.naive}" fired too` : " · no keyword would fire"}
      </div>
      {c.ct_count != null && (
        <div className="text-xs mt-1">CT: {c.ct_count} certificate{c.ct_count === 1 ? "" : "s"}{c.ct_first ? `, first ${c.ct_first.slice(0, 10)}` : ""}
          {nb != null && <>; this one issued {nb <= c.first_seen ? `${ago(c.first_seen - nb)} before it reached the stream` : clock(nb)}</>}
          {issuers.length ? ` (${issuers.slice(0, 2).join(", ")})` : ""}{c.ct_armed ? " · armed" : ""}</div>)}
      {c.pdb_status && c.pdb_status !== "not_listed" && <div className="text-xs mt-1 warn">{PDB[c.pdb_status] ?? c.pdb_status}</div>}
      {busy && <div className="text-xs">opening…</div>}
    </button>);
}

function Lead({ sum: s }: { sum: LiveSummary }) {
  return (
    <div className="panel mt-3.5">
      <h3>Ahead of the blocklist</h3>
      <p className="ph">Each flagged name is checked against Phishing.Database ACTIVE (one public list, polled every hour; not Google Safe Browsing). Sleepers: {n(s.watch.watched)} NRD look-alikes watched, {n(s.watch.armed)} armed.</p>
      {s.lead.listed_after ? (
        <table className="w-full text-sm"><thead><tr><th className="text-left">Name</th><th>From</th><th>Flagged</th><th>Doppel was ahead by</th></tr></thead>
          <tbody>{s.lead.rows.map((x) => (
            <tr key={x.name}><td className="mono">{x.name}</td><td>{x.source}</td><td>{new Date(x.flagged * 1000).toLocaleString("en-IN")}</td>
              <td>{x.lead_min_h.toFixed(1)}–{x.lead_max_h.toFixed(1)} h</td></tr>))}</tbody></table>
      ) : <p className="text-sm neutral">No flagged name has been listed after Doppel flagged it yet ({s.polls} polls so far). The lead-time table fills as the list catches up.</p>}
    </div>);
}
