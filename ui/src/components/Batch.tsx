// Batch view: many names at once (batch sources escalate per domain on evidence), a ranked table, exports.
import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, download } from "../lib/api";
import { BATCH_SAMPLE } from "../lib/gallery";
import { reachedStage, tricksOf } from "../lib/replay";
import type { Label, ScanResponse, Source, Verdict } from "../lib/types";
import { LABEL_CLS, LABELS, labelText, TRICK_TEXT } from "../lib/vocab";

export default function Batch({ live, autoSample = false, result, setResult, onOpen }: {
  live: boolean; autoSample?: boolean; result: ScanResponse | null; setResult: (r: ScanResponse | null) => void; onOpen: (v: Verdict) => void;
}) {
  const [text, setText] = useState("");
  const [source, setSource] = useState<Source>("file");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Label | null>(null);
  const [wall, setWall] = useState<number | null>(null);
  const file = useRef<HTMLInputElement>(null);

  const run = async (p: Promise<ScanResponse>) => {
    setBusy(true); setErr(null); setFilter(null);
    const t0 = performance.now();
    try { setResult(await p); setWall(performance.now() - t0); }
    catch (e) { setErr(e instanceof ApiError ? e.message : String(e)); }
    finally { setBusy(false); }
  };
  const auto = useRef(autoSample);
  useEffect(() => {                         // ?tab=batch&sample=1: scan the sample once the API is up
    if (!auto.current || !live) return;
    auto.current = false;
    setText(BATCH_SAMPLE);
    run(api.scan(BATCH_SAMPLE.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")), source));
  }, [live]);  // eslint-disable-line react-hooks/exhaustive-deps
  const items = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const rows = useMemo(() => (result?.verdicts ?? []).filter((v) => !filter || v.label === filter), [result, filter]);
  const s = result?.summary;

  return (
    <section className="pt-4 pb-8">
      <h2>Batch scan</h2>
      <p className="lead">Paste or upload many names (one per line, or a CSV with a <code>domain</code>/<code>url</code> column). Batch input escalates per domain: Quick for everyone, Standard only on a brand signal. Results are ranked phishing → sleeper → needs review → benign → genuine, then by risk. Up to {(5000).toLocaleString()} names here; the CLI (<code>doppel scan</code>) handles millions.</p>
      {!live && <div className="err mb-3">The API is offline, so batch scanning is unavailable.</div>}
      <div className="panel">
        <textarea className="field w-full" rows={7} value={text} onChange={(e) => setText(e.target.value)} disabled={!live}
                  placeholder={"paytrn.com\nsbi-kyc-update.in\nhttps://example.com/login"} aria-label="Domains, one per line" />
        <div className="flex flex-wrap gap-2 mt-2 items-center">
          <button className="btn go" disabled={!live || busy || !items.length} onClick={() => run(api.scan(items, source))}>
            {busy ? "Scanning…" : `Scan ${items.length || ""} name${items.length === 1 ? "" : "s"}`}</button>
          <button className="btn" onClick={() => setText(BATCH_SAMPLE)} disabled={!live}>Load sample</button>
          <button className="btn" onClick={() => file.current?.click()} disabled={!live || busy}>Upload .txt / .csv</button>
          <input ref={file} type="file" accept=".txt,.csv,text/plain,text/csv" hidden
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) run(api.upload(f, source)); e.target.value = ""; }} />
          <label className="text-sm text-[var(--muted)] flex items-center gap-1.5">source
            <select className="btn sm" value={source} onChange={(e) => setSource(e.target.value as Source)}>
              <option value="file">file</option><option value="nrd_snapshot">nrd_snapshot</option><option value="ct_feed">ct_feed</option>
            </select></label>
        </div>
        {err && <div className="err mt-2">{err}</div>}
      </div>

      {result && s && (
        <div className="panel mt-3.5">
          <div className="flex flex-wrap gap-2 items-stretch mb-3">
            {LABELS.map((l) => (
              <button key={l.id} className={"tile" + (filter === l.id ? " sel" : "")} onClick={() => setFilter(filter === l.id ? null : l.id)}>
                <b className={"lab " + l.cls} style={{ fontSize: 22 }}>{(s.by_label[l.id] ?? 0).toLocaleString()}</b><span>{l.text.toLowerCase()}</span>
              </button>))}
            <div className="tile" style={{ cursor: "default" }}>
              <b>{(s.elapsed_ms / 1000).toFixed(2)} s</b>
              <span>{s.total.toLocaleString()} judged{s.total ? ` · ${(s.elapsed_ms / s.total).toFixed(1)} ms each` : ""}{wall ? ` · ${(wall / 1000).toFixed(2)} s round trip` : ""}</span>
            </div>
            <div className="tile" style={{ cursor: "default" }}>
              <b>{s.reached_stage.quick ?? 0} / {s.reached_stage.standard ?? 0} / {s.reached_stage.deep ?? 0}</b>
              <span>stopped at Quick / Standard / Deep</span>
            </div>
          </div>
          {!!s.not_domains && <p className="text-sm text-[var(--muted)]">{s.not_domains} input{s.not_domains === 1 ? "" : "s"} weren't domains: {result.skipped?.slice(0, 5).map((x) => x.input).join(", ")}</p>}
          <div className="flex flex-wrap gap-1.5 mb-3 items-center">
            <span className="text-xs font-bold text-[var(--muted)] mr-1">Export:</span>
            {result.scan_id ? (<>
              <a className="btn sm" href={api.exportUrl(result.scan_id, "json")}>JSON (contract)</a>
              <a className="btn sm" href={api.exportUrl(result.scan_id, "csv")}>CSV</a>
              <a className="btn sm" href={api.exportUrl(result.scan_id, "blocklist")}>Blocklist</a>
              <a className="btn sm" href={api.exportUrl(result.scan_id, "blocklist", true)}>Blocklist + review</a>
              <a className="btn sm" href={api.exportUrl(result.scan_id, "html")}>HTML report</a>
            </>) : <button className="btn sm" onClick={() => download("doppel-scan.json", JSON.stringify(result, null, 1))}>JSON</button>}
            {filter && <button className="btn sm ml-auto" onClick={() => setFilter(null)}>Show all labels</button>}
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="grid">
              <thead><tr><th>#</th><th>Domain (as displayed)</th><th>Label</th><th>Risk</th><th>Target</th><th>Trick</th><th>Stage</th><th>Why</th></tr></thead>
              <tbody>
                {rows.map((v, k) => (
                  <tr key={v.domain + k} onClick={() => onOpen(v)} title="Open in the Decision Trace Explorer">
                    <td className="num text-[var(--faint)]">{k + 1}</td>
                    <td className="mono text-[13px] break-all">{v.input.display}{v.owner && v.owner !== v.domain && <span className="meta block">owner {v.owner}</span>}</td>
                    <td><span className={"lab " + LABEL_CLS[v.label]}>{labelText(v.label)}</span></td>
                    <td className="num">{v.risk_score.toFixed(2)}</td>
                    <td>{v.target_brand?.name ?? "–"}{v.closeness != null && <span className="meta block">closeness {v.closeness.toFixed(2)}</span>}</td>
                    <td className="text-[13px]">{tricksOf(v).map((t) => TRICK_TEXT[t] ?? t).join(", ") || "–"}</td>
                    <td className="text-[13px]">{reachedStage(v)}</td>
                    <td className="text-[13px]" style={{ minWidth: 260 }}>{v.reason}</td>
                  </tr>))}
              </tbody>
            </table>
          </div>
          <p className="tnote">Click a row to replay its decision trace. Risk is a score for ranking, not a calibrated probability (fusion v1; P11 calibrates it).</p>
        </div>)}
    </section>
  );
}
