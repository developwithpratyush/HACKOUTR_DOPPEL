import { useCallback, useEffect, useRef, useState } from "react";
import Batch from "./components/Batch";
import Explorer, { type Loaded } from "./components/Explorer";
import FoolIt, { type Attempt } from "./components/FoolIt";
import Campaigns from "./components/Campaigns";
import LiveHunt from "./components/LiveHunt";
import Presenter from "./components/Presenter";
import { api, ApiError, MOCKS } from "./lib/api";
import { packCase } from "./lib/pack";
import { BrandsCtx } from "./lib/context";
import { GALLERY, type Case } from "./lib/gallery";
import type { BrandInfo, Health, ScanResponse, Source, Verdict } from "./lib/types";

type Tab = "presenter" | "explore" | "fool" | "batch" | "live" | "radar";
// Deep links (for the pitch, the backup video and screenshots):
//   ?case=02&step=7   a gallery case, opened at trace step 7 (1-based)   ?q=paytrn.com   any domain
//   ?tab=fool&q=…     the fool-it box, prefilled    ?tab=batch&sample=1   the batch sample, scanned
//   ?mock=1           force the offline fallback (rehearse the demo without the API)
//   ?tab=live         the Live Hunt screen (P12)    ?tab=radar   Campaign Radar (P13)
//   (no tab)          the Presenter view (P14): search bar -> the space    ?tab=explore   the Analyst view
const PARAMS = new URLSearchParams(location.search);
const FORCE_MOCK = PARAMS.has("mock");
const START_STEP = PARAMS.get("step") ? Math.max(0, parseInt(PARAMS.get("step")!, 10) - 1) : undefined;
const START_TAB = (["presenter", "explore", "fool", "batch", "live", "radar"] as const).find((t) => t === PARAMS.get("tab"))
  ?? (PARAMS.has("q") || PARAMS.has("case") ? "explore" : "presenter");

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [checked, setChecked] = useState(false);
  const [brands, setBrands] = useState<Record<string, BrandInfo>>({});
  const [tab, setTab] = useState<Tab>(START_TAB);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attempts, setAttempts] = useState<Attempt[]>([]);
  const [batch, setBatch] = useState<ScanResponse | null>(null);
  const live = !!health?.ok && !FORCE_MOCK;
  const started = useRef(false);

  useEffect(() => {
    if (FORCE_MOCK) { setChecked(true); return; }
    let stop = false;
    const ping = () => api.health().then((h) => !stop && setHealth(h)).catch(() => !stop && setHealth(null))
      .finally(() => !stop && setChecked(true));
    ping();
    const t = setInterval(ping, 8000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    if (live && !Object.keys(brands).length) {
      api.brands().then((bs) => setBrands(Object.fromEntries(bs.map((b) => [b.id, b])))).catch(() => undefined);
    }
  }, [live, brands]);

  const run = useCallback(async (raw: string, source: Source, c?: Case, startAt?: number) => {
    setError(null);
    if (!live) {                                       // P14: a real recorded verdict first, the P0 mock last
      const rec = await packCase(raw);
      const mock = c?.mock ? MOCKS[c.mock] : undefined;
      if (rec) setLoaded({ verdict: rec.verdict, caseId: c?.id, story: c?.input, startAt });
      else if (mock) setLoaded({ verdict: mock, caseId: c?.id, story: c?.input, startAt });
      else setError("The API is offline: only the recorded stage cases can be shown.");
      return;
    }
    setBusy(true);
    try {
      const verdict = await api.investigate(raw, source);
      setLoaded({ verdict, caseId: c?.id, story: c?.input, startAt });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [live]);

  useEffect(() => {                                  // open on the first gallery case
    if (!checked || started.current) return;
    started.current = true;
    const q = START_TAB === "explore" ? PARAMS.get("q") : null;
    const c = GALLERY.find((g) => g.id === PARAMS.get("case")) ?? GALLERY[0];
    if (q && live) run(q, "paste", undefined, START_STEP);
    else run(c.raw, c.source, c, START_STEP);
  }, [checked, run]);

  const openInExplorer = (verdict: Verdict) => { setLoaded({ verdict }); setTab("explore"); window.scrollTo({ top: 0 }); };

  return (
    <BrandsCtx.Provider value={brands}>
      <div hidden={tab !== "presenter"}>
        <Presenter live={live} ready={checked} offline={!!health?.offline} onNav={(t) => { setTab(t); window.scrollTo({ top: 0 }); }} />
      </div>
      <div className="wrap" hidden={tab === "presenter"}>
        <header className="pt-6 pb-2 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1><em>Doppel</em>: analyst console</h1>
            <p className="sub">Paste any domain. A deterministic <b>central brain</b> sends it through <b>Quick → Standard → Deep</b> by itself, records every step, and ends with <b>one verdict</b> you can replay, question and try to fool.</p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            {!checked ? <span className="pill off">checking the API…</span>
              : live ? <span className="pill live" title={`warm-up ${health?.warm_ms} ms`}><span className="dot" />live brain · engine {health?.engine}</span>
              : <span className="pill off" title="Start the API: python -m doppel.cli serve"><span className="dot" />API offline · gallery shows mock verdicts</span>}
            <span className="pill honest" title={health?.fixtures}>pages: local fixtures · made-up credentials only</span>
          </div>
        </header>
        <nav className="tabs">
          <button onClick={() => { setTab("presenter"); window.scrollTo({ top: 0 }); }}>← Presenter</button>
          <button className={tab === "explore" ? "on" : ""} onClick={() => setTab("explore")}>① Decision Trace Explorer</button>
          <button className={tab === "fool" ? "on" : ""} onClick={() => setTab("fool")}>② Try to fool it{attempts.length ? ` (${attempts.length})` : ""}</button>
          <button className={tab === "batch" ? "on" : ""} onClick={() => setTab("batch")}>③ Batch scan</button>
          <button className={tab === "live" ? "on" : ""} onClick={() => setTab("live")}>④ Live Hunt</button>
          <button className={tab === "radar" ? "on" : ""} onClick={() => setTab("radar")}>⑤ Campaign Radar</button>
        </nav>
        <div hidden={tab !== "explore"}>
          <Explorer loaded={loaded} busy={busy} error={error} live={live} onRun={run} active={tab === "explore"} />
        </div>
        <div hidden={tab !== "fool"}>
          <FoolIt live={live} initial={START_TAB === "fool" ? PARAMS.get("q") ?? "" : ""} attempts={attempts} setAttempts={setAttempts} onReplay={openInExplorer} />
        </div>
        <div hidden={tab !== "batch"}>
          <Batch live={live} autoSample={START_TAB === "batch" && PARAMS.has("sample")} result={batch} setResult={setBatch} onOpen={openInExplorer} />
        </div>
        <div hidden={tab !== "live"}>
          <LiveHunt live={live} active={tab === "live"} onOpen={openInExplorer} />
        </div>
        <div hidden={tab !== "radar"}>
          <Campaigns live={live} active={tab === "radar"} onOpen={openInExplorer} />
        </div>
        <footer>Doppel · PS-08 phishing domain detection. Verdicts come from the real brain (<code>doppel.brain</code>) through the API; when the API is down the gallery falls back to the contract's mock verdicts and says so. Doppel never opens a domain it judges: page evidence comes only from our own local fixture pages. Risk is a ranking score, not a calibrated probability.</footer>
      </div>
    </BrandsCtx.Provider>
  );
}
