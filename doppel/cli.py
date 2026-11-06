"""The `doppel` command line: `version`, `validate` (P0), `scan` (P5), `serve` (P6), `report` (P10),
`cert-diff` and `discover-family` (P11), `live run|replay|stop|status|ingest-nrd|report` (P12)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import typer

from doppel import CONTRACT_VERSION, __version__
from doppel.contract import load_yaml, validate_document, validate_registry

app = typer.Typer(help="Doppel: explainable look-alike phishing domain detection.", no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the engine and contract versions."""
    typer.echo(f"doppel {__version__} (contract {CONTRACT_VERSION})")


@app.command()
def validate(
    files: List[Path] = typer.Argument(..., exists=True, dir_okay=False, help="Verdict/scan JSON files, or registry.yaml."),
) -> None:
    """Check files against the contracts in contracts/."""
    failed = 0
    for path in files:
        if path.suffix in (".yaml", ".yml"):
            problems = validate_registry(load_yaml(path))
        else:
            problems = validate_document(json.loads(path.read_text(encoding="utf-8")))
        if problems:
            failed += 1
            typer.echo(f"FAIL {path}")
            for p in problems:
                typer.echo(f"  - {p}")
        else:
            typer.echo(f"ok   {path}")
    raise typer.Exit(code=1 if failed else 0)


@app.command()
def scan(
    inputs: List[str] = typer.Argument(..., help="Domains, URLs, a .txt/.csv file, or - for stdin."),
    fmt: str = typer.Option("json", "--format", "-f", help="json, csv, blocklist, html, or all."),
    out: Path = typer.Option(None, "--out", "-o", help="Output file (or folder for --format all). Default: stdout."),
    source: str = typer.Option(None, "--source", help="Override the input source (e.g. nrd_snapshot, gallery)."),
    workers: int = typer.Option(None, "--workers", "-j", help="Processes for batch input (default: CPUs - 1)."),
    renders: bool = typer.Option(False, "--renders", help="Save the SMS-view PNGs to runs/renders/."),
    include_review: bool = typer.Option(False, "--include-review", help="Blocklist: add needs_review domains."),
    no_cert: bool = typer.Option(False, "--no-cert", help="Ablation: Certificate Forensics (C16/C17) off."),
) -> None:
    """Investigate domains. No mode flag: the brain escalates through the stages by itself."""
    from doppel.brain.scan import read_inputs
    from doppel.brain.scan import scan as run_scan
    from doppel.export.formats import EXT, FORMATS, WRITERS
    from doppel.perception.renderer import RENDER_DIR

    items, src = read_inputs(inputs)
    if not items:
        raise typer.BadParameter("no domains to scan")
    formats = list(FORMATS) if fmt == "all" else [fmt]
    if any(f not in FORMATS for f in formats):
        raise typer.BadParameter(f"--format must be one of {', '.join(FORMATS)} or all")
    verdicts, stats = run_scan(items, source or src, workers=1 if len(items) < 200 else workers,
                               render_dir=RENDER_DIR if renders else None, certs=False if no_cert else None)
    for err in stats["error_samples"]:
        typer.echo(f"skipped {err['input']!r}: {err['error']}", err=True)
    for f in formats:
        kw = {"include_review": include_review} if f == "blocklist" else {}
        text = WRITERS[f](verdicts, stats, **kw)
        if out is None and len(formats) == 1:
            typer.echo(text, nl=False)
            continue
        target = (out or Path("runs/scan")) / f"doppel-scan.{EXT[f]}" if len(formats) > 1 else out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {target}", err=True)
    by = ", ".join(f"{k} {n}" for k, n in sorted(stats["by_label"].items()))
    typer.echo(f"{stats['total']} scanned in {stats['elapsed_ms'] / 1000:.2f} s: {by}", err=True)


@app.command()
def report(
    target: str = typer.Argument(..., help="A domain/URL to investigate, or a verdict .json file."),
    lang: str = typer.Option("en", "--lang", "-l", help="en or hi (Hindi)."),
    out: Path = typer.Option(None, "--out", "-o", help="HTML file (default: runs/casefile/<domain>.<lang>.html)."),
    source: str = typer.Option("paste", "--source", help="Input source for a domain (paste, gallery, ...)."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Template only: never call the language model."),
    no_cert: bool = typer.Option(False, "--no-cert", help="Ablation: Certificate Forensics (C16/C17) off."),
) -> None:
    """Write the case file for one verdict: grounded narration (every sentence cites evidence), actions, appendix."""
    import json

    from doppel.casefile import CaseFileRefused
    from doppel.casefile.report import case_file_html

    p = Path(target)
    if p.suffix == ".json" and p.exists():
        verdict = json.loads(p.read_text(encoding="utf-8"))
    else:
        from doppel.brain.brain import investigate

        verdict = investigate(target, source, certs=False if no_cert else None)
    try:
        html, cf = case_file_html(verdict, lang, use_llm=not no_llm)
    except CaseFileRefused as exc:
        typer.echo(f"Refused: {exc}", err=True)
        raise typer.Exit(2) from exc
    out = out or Path("runs") / "casefile" / f"{verdict['domain']}.{lang}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    n = cf.narration
    typer.echo(f"{verdict['label'].upper()} {verdict['domain']}: {out} (narration: {n['model'] or 'template'}, "
               f"{n['accepted']} sentences kept, {n['rejected']} rejected)", err=True)


@app.command("cert-diff")
def cert_diff(
    target: str = typer.Argument(..., help="A domain or URL."),
    source: str = typer.Option("paste", "--source", help="Input source (paste looks CT up live when not cached)."),
    as_json: bool = typer.Option(False, "--json", help="Print both verdicts' differences as JSON."),
) -> None:
    """The ablation switch (P11): the same name with Certificate Forensics off, then on, and what changed."""
    from doppel.brain.brain import investigate
    from doppel.certs.diff import diff, render

    off = investigate(target, source, certs=False)
    on = investigate(target, source, certs=True)
    d = diff(off, on)
    typer.echo(json.dumps(d, indent=1, ensure_ascii=False) if as_json else render(d))


@app.command("discover-family")
def discover_family(
    ct: bool = typer.Option(False, "--ct", help="Also search CT logs for certificates naming each seed apex."),
    refresh: bool = typer.Option(False, "--refresh", help="Re-read certificates even when cached."),
) -> None:
    """Family auto-discovery (P11): read the proven seeds' own certificates; write data/brands/discovered.yaml."""
    from doppel.certs.discover import main

    main((["--ct"] if ct else []) + (["--refresh"] if refresh else []))


live_app = typer.Typer(help="Live Hunt (P12): judge the world's new certificates as they appear.", no_args_is_help=True)
app.add_typer(live_app, name="live")


@live_app.command("run")
def live_run(
    ct_daily_cap: int = typer.Option(20, "--ct-daily-cap", help="CT lookups per UTC day for flagged names (0 = none)."),
    pdb_every_h: float = typer.Option(1.0, "--pdb-every-h", help="Hours between Phishing.Database polls."),
    nrd_every_h: float = typer.Option(24.0, "--nrd-every-h", help="Hours between NRD ingests (0 = never)."),
    keep_hours: int = typer.Option(96, "--keep-hours", help="Hours of stream recordings kept for replay."),
    duration: float = typer.Option(None, "--duration", help="Stop after this many seconds (default: run until stopped)."),
    url: str = typer.Option("wss://api.certstream.dev/", "--url", help="The certstream websocket."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", help="Log to runs/live/live/collector.log only (background service)."),
) -> None:
    """The collector: a background service that keeps running (reconnects, alarms on silence). Stop: `doppel live stop`."""
    from doppel.live import mode_dir
    from doppel.live.collector import Collector, running, setup_logging

    if (st := running("live")) is not None:
        typer.echo(f"A live collector is already running (pid {st.get('pid')}). Stop it first: doppel live stop", err=True)
        raise typer.Exit(3)                     # the supervisor script stops on 3 instead of restarting
    setup_logging(mode_dir("live"), verbose, quiet)
    Collector("live", url=url, ct_daily_cap=ct_daily_cap, pdb_every_h=pdb_every_h, nrd_every_h=nrd_every_h,
              keep_hours=keep_hours).run(duration)


@live_app.command("replay")
def live_replay(
    files: List[Path] = typer.Argument(None, help="Recordings (runs/live/recordings/stream-*.jsonl.gz). Default: the latest full hour."),
    hours: int = typer.Option(1, "--hours", help="With no files: how many of the latest complete hours to replay."),
    speed: float = typer.Option(1.0, "--speed", help="1 = real time, with the recording's own timestamps."),
    fresh: bool = typer.Option(True, "--fresh/--keep", help="Start the replay store from zero (default)."),
) -> None:
    """Re-feed recorded stream hours at 1x through the same pipeline. The UI labels it REPLAY. No network at all."""
    import os
    import shutil

    from doppel.live import LIVE_DIR, mode_dir
    from doppel.live.collector import Collector, running, setup_logging

    os.environ["DOPPEL_OFFLINE"] = "1"          # a replay never looks anything up
    if (st := running("replay")) is not None:
        typer.echo(f"A replay is already running (pid {st.get('pid')}). Stop it: doppel live stop --mode replay", err=True)
        raise typer.Exit(1)
    if not files:
        rec = sorted((LIVE_DIR / "recordings").glob("stream-*.jsonl.gz"))
        files = rec[-hours - 1:-1] if len(rec) > hours else rec[-hours:]   # skip the hour still being written
    if not files:
        typer.echo("No recordings yet: run the live collector first (doppel live run).", err=True)
        raise typer.Exit(1)
    d = mode_dir("replay")
    if fresh and d.exists():
        for name in ("catches.db", "catches.db-wal", "catches.db-shm", "state.json"):
            (d / name).unlink(missing_ok=True)
        shutil.rmtree(d / "pdb", ignore_errors=True)
    setup_logging(d)
    typer.echo(f"Replaying {', '.join(f.name for f in files)} at {speed}x", err=True)
    Collector("replay", recording=list(files), speed=speed, ct_daily_cap=0).run()


@live_app.command("stop")
def live_stop(mode: str = typer.Option("live", "--mode", help="live or replay.")) -> None:
    """Ask a running collector to stop (it finishes the queue and closes its run cleanly)."""
    from doppel.live import mode_dir

    d = mode_dir(mode)
    d.mkdir(parents=True, exist_ok=True)
    (d / "STOP").write_text("stop", encoding="utf-8")
    typer.echo(f"Asked the {mode} collector to stop.")


@live_app.command("reconnect")
def live_reconnect() -> None:
    """Make the running collector drop its stream connection; it must reconnect by itself (a resilience check)."""
    from doppel.live import mode_dir

    (mode_dir("live") / "RECONNECT").write_text("reconnect", encoding="utf-8")
    typer.echo("Asked the live collector to drop its connection; `doppel live status` shows the reconnect.")


@live_app.command("status")
def live_status(mode: str = typer.Option("live", "--mode")) -> None:
    """Is the collector alive, and what has it seen?"""
    from doppel.live.collector import running
    from doppel.live.report import summary

    st = running(mode, within_s=30)
    s = summary(mode=mode)
    if st is None:
        typer.echo(f"{mode} collector: NOT RUNNING (no state written in the last 30 s)")
    else:
        typer.echo(f"{mode} collector: running, pid {st['pid']}, connected={st['connected']}, "
                   f"{st['rate_names_s']} names/s, queue {st['queue']}, reconnects {st['reconnects']}")
    if s:
        t = s["totals"]
        typer.echo(f"all time: {s['hours_watched']:.2f} h watched, {t['certs']:,} certificates, {t['uniq']:,} unique names, "
                   f"{t['flags']:,} Doppel flags vs {t['naive']:,} keyword alerts, {t['genuine']:,} genuine; "
                   f"watch list {s['watch']['watched']:,} ({s['watch']['armed']} armed); "
                   f"{s['lead']['listed_after']} flagged before Phishing.Database listed them")


@live_app.command("ingest-nrd")
def live_ingest_nrd(
    local: Path = typer.Option(None, "--file", help="Use this NRD list instead of downloading hagezi's nrd7."),
    workers: int = typer.Option(None, "--workers", "-j"),
    limit: int = typer.Option(None, "--limit", help="Judge at most this many new names (testing)."),
) -> None:
    """Daily sleeper ingest: new NRD names -> the brain -> flagged look-alikes go on the watch list."""
    from doppel.live import mode_dir
    from doppel.live.sleepers import ingest

    out = ingest(mode_dir("live"), local=local, workers=workers, limit=limit)
    typer.echo(json.dumps(out))


@live_app.command("report")
def live_report(
    out: Path = typer.Option(Path("docs/eval/p12-live.md"), "--out", "-o"),
    mode: str = typer.Option("live", "--mode"),
) -> None:
    """Regenerate the eval file from the catch store."""
    from doppel.live.report import write

    typer.echo(f"wrote {write(out, mode=mode)}")


@app.command()
def campaigns(
    raw: List[str] = typer.Option(None, "--raw", help="FILE[:tag] of raw names, judged by the brain (repeatable). "
                                                     "Default: Phishing.Database ACTIVE as 'pdb'."),
    live: bool = typer.Option(True, "--live/--no-live", help="Add the P12 catch store and its NRD watch list."),
    out: Path = typer.Option(None, "--out", "-o", help="Folder for radar.json + index.json (default data/campaigns)."),
    workers: int = typer.Option(None, "--workers", "-j"),
    top: int = typer.Option(10, "--top", help="Campaign cards to print."),
) -> None:
    """Campaign Radar (P13): flagged domains -> C18 links -> campaigns. CT records come from the cache only."""
    import os

    from doppel.campaign import CAMPAIGN_DIR
    from doppel.campaign.radar import build, save
    from doppel.campaign.sources import from_live, from_raw
    from doppel.contract import REPO_ROOT
    from doppel.family import load_registry
    from doppel.live import mode_dir

    os.environ["DOPPEL_OFFLINE"] = "1"            # the radar never looks anything up
    pdb = REPO_ROOT / "data" / "raw" / "phishing_database" / "phishing-domains-ACTIVE.txt"
    specs = raw if raw is not None else ([f"{pdb}:pdb"] if pdb.is_file() else [])
    items, report = [], []
    for spec in specs:
        path, _, tag = spec.rpartition(":") if ":" in Path(spec).name or spec.count(":") > 1 else (spec, "", "raw")
        got, st = from_raw(Path(path or spec), tag or "raw", workers)
        items += got
        report.append(st)
    if live:
        got, st = from_live(mode_dir("live") / "catches.db")
        items += got
        report.append(st)
    result = build(items, load_registry())
    result["inputs"] = report
    radar_p, index_p = save(result, out or CAMPAIGN_DIR)
    for st in report:
        typer.echo(f"input {st}", err=True)
    s = result["stats"]
    typer.echo(f"{s['domains']:,} flagged domains -> {s['campaigns']} campaigns ({s['in_campaigns']} domains), "
               f"edges {s['edges_by_type']}; wrote {radar_p} and {index_p}")
    for c in result["campaigns"][:top]:
        typer.echo(f"  {c['id']} x{c['size']:<3} {c['strength']:<38} {','.join(c['brands'])[:20]:<20} "
                   f"{(c['templates'] or ['-'])[0][:40]:<40} {', '.join(m['domain'] for m in c['members'][:3])}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address. Keep it local for the demo."),
    port: int = typer.Option(8000, help="Port."),
) -> None:
    """Run the API and (once `npm run build` has made ui/dist) the analyst UI at http://HOST:PORT."""
    from doppel.api.app import UI_DIST, run

    if not UI_DIST.is_dir():
        typer.echo("ui/dist not found: API only. Build the UI with `npm run build` in ui/, "
                   "or run `npm run dev` there (http://localhost:5173).", err=True)
    run(host, port)


if __name__ == "__main__":
    app()
