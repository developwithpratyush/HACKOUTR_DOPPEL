"""The HTTP API around the brain (P6). The analyst UI (``ui/``) is its only client today.

    GET  /api/health                         engine/contract versions, what's built, what's mocked
    GET  /api/brands                         the registry, for the UI's brand family tree
    POST /api/investigate  {raw, source, certs}  one verdict (contract `verdict`); certs=false: C16/C17 off (P11)
    POST /api/scan         {items, source}   a batch (contract `scan_result` + scan_id + skipped inputs)
    POST /api/scan/upload  file (.txt/.csv)  the same, from an uploaded file
    GET  /api/scan/{id}/export/{fmt}         json | csv | blocklist | html, as a download
    POST /api/report       {verdict, lang}   the case file (P10): printable HTML, narration grounded in evidence IDs
    POST /api/baselines    {verdict}         what generic methods say on the same name (P14): keyword, Levenshtein,
                                             dnstwist, phishing_catcher, ML alone, padlock, public blocklist

Static, for the UI: ``/runs/renders/*`` (Human-Eye Renderer PNGs), ``/runs/deep/*`` (Deep-stage screenshots and
heatmaps, P8), ``/fixtures/*`` (our local mock pages,
shown in a sandboxed iframe), and the built UI (``ui/dist``) at ``/`` when it exists, so one process serves
the whole demo: ``python -m doppel.cli serve``.

One Brain per process (it's expensive to build), warmed at start-up, and one lock around it: the brain's
Standard stage already runs its tools in threads, and the renderer's fonts aren't shared across calls.
A warm single investigation takes ~3–40 ms, so the lock costs nothing at demo scale. Batches release the
lock between domains, so a single investigation never waits for a whole batch.

Doppel never contacts the domains it judges; nothing here changes that (the Page Probe reads local fixtures).
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter, OrderedDict
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from doppel import CONTRACT_VERSION, __version__
from doppel.address import AddressError
from doppel.brain.brain import ENGINE, Brain
from doppel.brain.probe import FIXTURES
from doppel.brain.scan import items_from_text
from doppel.contract import REPO_ROOT
from doppel.export.formats import EXT, FORMATS, WRITERS, scan_result

RENDER_DIR = REPO_ROOT / "runs" / "renders"
DEEP_DIR = REPO_ROOT / "runs" / "deep"
UI_DIST = REPO_ROOT / "ui" / "dist"
MAX_BATCH = 5000          # bigger runs belong to the CLI (`doppel scan`, process pool)
MAX_UPLOAD_BYTES = 2_000_000
KEEP_SCANS = 10
WARMUP = ("paytrn.com", "sbi-kyc-update.in")
BUILT = {"quick": True, "human_eye_renderer": True, "page_probe": True, "risk_model": True,
         "page_inspector": False, "vision_ai": False, "credential_tracker": False}
NOT_DOMAIN = (AddressError, ValueError, UnicodeError)


class Engine:
    """The process's brain, its lock, and the recent scans (for export links)."""

    def __init__(self) -> None:
        RENDER_DIR.mkdir(parents=True, exist_ok=True)
        self.brain = Brain(render_dir=RENDER_DIR)
        self.lock = threading.Lock()
        self.scans: OrderedDict[str, tuple[list[dict], dict]] = OrderedDict()
        self.warm_ms: float | None = None

    def warm(self) -> None:
        t = time.perf_counter()
        for d in WARMUP:          # loads the glyph table, fonts and word lists before the first visitor
            self.investigate(d, "api")
        if self.brain.deep:       # start the sandboxed browser now, not on the first Deep case
            from doppel.deep.sandbox import sandbox

            sb = sandbox()
            sb._ex.submit(sb._ensure).result(60)
        self.warm_ms = round((time.perf_counter() - t) * 1000, 1)
        from doppel.baselines import generic                 # dnstwist's index (~3 s) off the request path
        threading.Thread(target=generic, args=(self.brain.reg,), daemon=True).start()

    def investigate(self, raw: str, source: str, certs: bool | None = None) -> dict:
        with self.lock:
            return self.brain.investigate(raw, source, certs=certs)

    def scan(self, items: list[str], source: str) -> tuple[str, list[dict], dict]:
        t0 = time.perf_counter()
        verdicts: list[dict] = []
        errors: list[dict] = []
        for raw in items:
            try:
                verdicts.append(self.investigate(raw, source))
            except NOT_DOMAIN as exc:
                errors.append({"input": raw, "error": f"{type(exc).__name__}: {exc}"})
        stats = {"total": len(items), "errors": len(errors), "error_samples": errors[:50],
                 "by_label": dict(Counter(v["label"] for v in verdicts)),
                 "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1)}
        sid = uuid.uuid4().hex[:12]
        self.scans[sid] = (verdicts, stats)
        while len(self.scans) > KEEP_SCANS:
            self.scans.popitem(last=False)
        return sid, verdicts, stats


ENGINE_STATE: Engine | None = None


def engine() -> Engine:
    global ENGINE_STATE
    if ENGINE_STATE is None:
        ENGINE_STATE = Engine()
    return ENGINE_STATE


@asynccontextmanager
async def lifespan(_app: FastAPI):
    engine().warm()
    yield


app = FastAPI(title="Doppel API", version=__version__, lifespan=lifespan,
              description="Explainable look-alike phishing-domain detection. Every response follows "
                          "contracts/evidence.schema.json.")
# The Vite dev server (5173) proxies /api, but allow it directly too. Local only: the demo binds 127.0.0.1.
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])


class InvestigateIn(BaseModel):
    raw: str = Field(..., min_length=1, max_length=2048, description="A domain, URL or SMS link.")
    source: Literal["paste", "api", "fool_it", "gallery"] = "paste"
    certs: bool = Field(True, description="false = the ablation switch: Certificate Forensics (C16/C17) off.")


class ScanIn(BaseModel):
    items: list[str] = Field(..., min_length=1, max_length=MAX_BATCH)
    source: Literal["file", "stdin", "nrd_snapshot", "ct_feed"] = "file"


# ------------------------------------------------------------------ endpoints ---

@app.get("/api/health")
def health() -> dict:
    e = engine()
    return {"ok": True, "engine": ENGINE, "version": __version__, "contract": CONTRACT_VERSION,
            "built": {**BUILT, "page_inspector": e.brain.deep, "vision_ai": e.brain.deep,
                      "credential_tracker": e.brain.deep, "cert_forensics": e.brain.certs, "ct_history": e.brain.certs},
            "cert_family_links": len(e.brain.cert_index),
            "warm_ms": e.warm_ms, "max_batch": MAX_BATCH,
            "fixtures": ("Pages are local fixtures only (demo/fixtures; clones generated from saved genuine pages), "
                         "rendered in a sandbox with no DNS; Doppel never visits a domain it judges."),
            "brands": [b.id for b in e.brain.reg.brands],
            "offline": _offline(), "network": _net(), "stale_fixtures": _stale()}


def _net() -> dict:
    from doppel import net

    return net.state()


def _offline() -> bool:
    from doppel.certs.store import offline

    return offline()


def _stale() -> list[str]:
    from doppel.deep.pages import stale_clones

    return stale_clones()


@app.get("/api/brands")
def brands() -> dict:
    reg = engine().brain.reg
    return {"restricted_registries": reg.restricted, "brands": [{
        "id": b.id, "name": b.name, "aliases": list(b.aliases), "brand_tlds": list(b.brand_tlds),
        "restricted_suffixes": list(b.restricted_suffixes),
        "family": [{"domain": f.domain, "include_subdomains": f.include_subdomains, "proof": f.proof,
                    "source": f.source, "verified_on": f.verified_on, "note": f.note} for f in b.family],
        "user_content": [{"host": u.host, "what": u.what} for u in b.user_content],
    } for b in reg.brands]}


@app.post("/api/investigate")
def investigate(body: InvestigateIn) -> dict:
    raw = body.raw.strip()
    try:
        return engine().investigate(raw, body.source, certs=body.certs)
    except NOT_DOMAIN as exc:
        raise HTTPException(422, detail=f"Not a domain Doppel can read: {exc}") from exc


class BaselinesIn(BaseModel):
    verdict: dict


@app.post("/api/baselines")
def baselines(body: BaselinesIn) -> dict:
    """The generic methods on the verdict's name (the ML row reads the verdict's own C8). Never looks anything up."""
    from doppel.baselines import generic

    d = body.verdict.get("domain")
    if not isinstance(d, str) or not d:
        raise HTTPException(422, detail="verdict.domain missing")
    try:
        rows = generic(engine().brain.reg).compare(d, body.verdict)
    except NOT_DOMAIN as exc:
        raise HTTPException(422, detail=f"{type(exc).__name__}: {exc}") from exc
    return {"domain": d, "rows": rows}


class ReportIn(BaseModel):
    verdict: dict
    lang: Literal["en", "hi"] = "en"
    llm: bool = True


@app.post("/api/report")
def report(body: ReportIn) -> Response:
    """The case file (P10) for a verdict the client already has: printable HTML. No lock needed: no browser."""
    from doppel.casefile import CaseFileRefused
    from doppel.casefile.report import case_file_html

    try:
        html, _ = case_file_html(body.verdict, body.lang, use_llm=body.llm)
    except CaseFileRefused as exc:
        raise HTTPException(422, detail=f"No case file: {exc}") from exc
    return Response(html, media_type="text/html; charset=utf-8")


def _scan_response(items: list[str], source: str, skipped_lines: int = 0) -> dict:
    if not items:
        raise HTTPException(422, detail="No domains found in the input.")
    if len(items) > MAX_BATCH:
        raise HTTPException(413, detail=f"{len(items):,} domains: the UI takes up to {MAX_BATCH:,}. "
                                        "Use `doppel scan <file>` for big runs.")
    sid, verdicts, stats = engine().scan(items, source)
    out = scan_result(verdicts, stats)
    out["scan_id"] = sid
    out["skipped"] = stats["error_samples"]
    out["summary"]["inputs"] = stats["total"]
    out["summary"]["not_domains"] = stats["errors"]
    return out


@app.post("/api/scan")
def scan(body: ScanIn) -> dict:
    items = [i.strip() for i in body.items if i.strip() and not i.strip().startswith("#")]
    return _scan_response(items, body.source)


@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...), source: str = Query("file")) -> dict:
    if source not in ("file", "stdin", "nrd_snapshot", "ct_feed"):
        raise HTTPException(422, detail=f"unknown batch source {source!r}")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail="File too large for the UI (2 MB). Use `doppel scan <file>`.")
    text = data.decode("utf-8-sig", errors="replace")
    name = (file.filename or "").lower()
    return _scan_response(items_from_text(text, csv_text=name.endswith(".csv")), source)


@app.get("/api/scan/{scan_id}/export/{fmt}")
def export(scan_id: str, fmt: str, include_review: bool = False) -> Response:
    if fmt not in FORMATS:
        raise HTTPException(404, detail=f"format must be one of {', '.join(FORMATS)}")
    found = engine().scans.get(scan_id)
    if found is None:
        raise HTTPException(404, detail="Scan not found (the server keeps the last 10). Run it again.")
    verdicts, stats = found
    kw = {"include_review": include_review} if fmt == "blocklist" else {}
    text = WRITERS[fmt](verdicts, stats, **kw)
    media = {"json": "application/json", "csv": "text/csv", "blocklist": "text/plain", "html": "text/html"}[fmt]
    name = f"doppel-scan-{scan_id}.{EXT[fmt]}"
    return Response(text, media_type=f"{media}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ------------------------------------------------------------------ campaign radar (P13) ---

@app.get("/api/campaigns")
def campaigns_view(limit: int = Query(60, ge=1, le=500)) -> dict:
    """The latest Campaign Radar run (`doppel campaigns` -> data/campaigns/radar.json): cards + the island graph."""
    import json as _json

    from doppel.campaign import CAMPAIGN_DIR

    p = CAMPAIGN_DIR / "radar.json"
    if not p.is_file():
        return {"campaigns": [], "graph": {"nodes": [], "edges": []}, "stats": {}, "generated_at": None}
    r = _json.loads(p.read_text(encoding="utf-8"))
    keep = {c["id"] for c in r["campaigns"][:limit]}
    r["campaigns"] = r["campaigns"][:limit]
    r["graph"]["nodes"] = [n for n in r["graph"]["nodes"] if n["campaign"] in keep]
    ids = {n["id"] for n in r["graph"]["nodes"]}
    r["graph"]["edges"] = [e for e in r["graph"]["edges"] if e["source"] in ids and e["target"] in ids]
    return r


# ------------------------------------------------------------------ live hunt (P12) ---
# The collector is its own process (`doppel live run`); these endpoints only read its state file and catch store,
# so the API never slows the stream down and a restarted API loses nothing.

LiveMode = Literal["live", "replay"]


def _live_store(mode: str):
    from doppel.live import mode_dir
    from doppel.live.store import Store

    db = mode_dir(mode) / "catches.db"
    return Store(db, readonly=True) if db.is_file() else None


@app.get("/api/live/state")
def live_state(mode: LiveMode = "live", limit: int = Query(30, ge=1, le=200)) -> dict:
    """Everything the Live Hunt screen polls once a second: the collector's state, all-time numbers, latest catches."""
    from doppel.live.collector import running
    from doppel.live.report import summary

    st = running(mode, within_s=15)
    out = {"mode": mode, "running": st is not None, "state": st, "summary": summary(mode=mode), "catches": [],
           "armings": [], "alarms_open": [], "alarms_recent": [], "now": time.time()}
    if st is None:                       # the last state the collector wrote, labelled stale by the UI
        from doppel.live import mode_dir
        import json as _json

        try:
            out["state"] = _json.loads((mode_dir(mode) / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    s = _live_store(mode)
    if s is not None:
        try:
            out.update(catches=s.recent_catches(limit), armings=s.armings(10), alarms_open=s.alarms(open_only=True),
                       alarms_recent=s.alarms(limit=10))
        finally:
            s.close()
    return out


@app.get("/api/live/catches")
def live_catches(mode: LiveMode = "live", limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                 brand: str | None = None, label: str | None = None) -> dict:
    s = _live_store(mode)
    if s is None:
        return {"catches": [], "total": 0}
    try:
        return {"catches": s.recent_catches(limit, offset, brand, label), "total": sum(s.count_catches().values())}
    finally:
        s.close()


@app.get("/api/live/catch")
def live_catch(name: str, mode: LiveMode = "live") -> dict:
    """One catch with its stored verdict (the Decision Trace opens it as judged at that moment; no re-run, no CT)."""
    s = _live_store(mode)
    c = s.catch(name.strip().lower()) if s is not None else None
    if s is not None:
        s.close()
    if c is None:
        raise HTTPException(404, detail=f"{name} is not in the {mode} catch store.")
    return c


@app.get("/api/live/recordings")
def live_recordings() -> dict:
    from doppel.live import LIVE_DIR

    rec = LIVE_DIR / "recordings"
    files = sorted((rec / "keep").glob("stream-*.jsonl.gz")) + sorted(rec.glob("stream-*.jsonl.gz"))
    return {"recordings": [{"name": f.relative_to(rec).as_posix(), "bytes": f.stat().st_size, "modified": f.stat().st_mtime,
                            "kept": f.parent.name == "keep"} for f in files]}


class ReplayIn(BaseModel):
    files: list[str] = Field(default_factory=list, description="Recording names; empty = the latest complete hours.")
    hours: int = Field(1, ge=1, le=12)
    speed: float = Field(1.0, gt=0, le=100)


@app.post("/api/live/replay")
def live_replay(body: ReplayIn) -> dict:
    """Start a replay process (`doppel live replay`): recorded stream hours at 1x, labelled REPLAY. No network."""
    import subprocess
    import sys

    from doppel.live import LIVE_DIR
    from doppel.live.collector import running

    if (st := running("replay")) is not None:
        raise HTTPException(409, detail=f"A replay is already running (pid {st.get('pid')}).")
    rec = LIVE_DIR / "recordings"
    paths = []
    for name in body.files:
        p = (rec / name).resolve()
        if p.parent not in (rec.resolve(), (rec / "keep").resolve()) or not p.is_file() or not p.name.startswith("stream-"):
            raise HTTPException(422, detail=f"Unknown recording {name!r}.")
        paths.append(str(p))
    cmd = [sys.executable, "-m", "doppel.cli", "live", "replay", *paths, "--hours", str(body.hours),
           "--speed", str(body.speed)]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=flags)
    return {"started": True, "pid": proc.pid}


@app.post("/api/live/replay/stop")
def live_replay_stop() -> dict:
    from doppel.live import mode_dir

    d = mode_dir("replay")
    d.mkdir(parents=True, exist_ok=True)
    (d / "STOP").write_text("stop", encoding="utf-8")
    return {"stopping": True}


@app.exception_handler(404)
async def _not_found(request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": getattr(exc, "detail", "Not found")}, status_code=404)
    index = UI_DIST / "index.html"     # client-side routes fall back to the UI
    if index.is_file() and request.method == "GET":
        return Response(index.read_text(encoding="utf-8"), media_type="text/html")
    return JSONResponse({"detail": "Not found"}, status_code=404)


# ------------------------------------------------------------------ static ---

RENDER_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/runs/renders", StaticFiles(directory=RENDER_DIR), name="renders")
DEEP_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/runs/deep", StaticFiles(directory=DEEP_DIR), name="deep")
app.mount("/fixtures", StaticFiles(directory=FIXTURES.parent), name="fixtures")   # /fixtures/pages/*.html
if UI_DIST.is_dir():
    app.mount("/", StaticFiles(directory=UI_DIST, html=True), name="ui")


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")
