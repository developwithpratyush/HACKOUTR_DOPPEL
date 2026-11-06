"""Batch scanning: many domains, in parallel processes (stages stay sequential within each domain).

``read_inputs`` accepts domains, URLs, SMS links, a text file (one per line), a CSV (a ``domain``,
``url``, ``host`` or ``candidate`` column, else the first column) or ``-`` for stdin.
"""

from __future__ import annotations

import csv
import io
import os
import sys
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from doppel.address import AddressError

# One BLAS thread per process: numpy's OpenBLAS otherwise starts a thread pool (and buffers) per core in every
# worker, which ran a 20-worker NRD run out of memory. Set before numpy loads; spawned workers inherit it.
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_var, "1")

COLUMNS = ("domain", "url", "host", "candidate")


def read_inputs(args: list[str]) -> tuple[list[str], str]:
    """(items, source). One bare domain/URL on the command line is a single investigation ("paste")."""
    items: list[str] = []
    batch = False
    for a in args:
        if a == "-":
            items += _lines(sys.stdin.read())
            batch = True
        elif Path(a).is_file():
            items += _from_file(Path(a))
            batch = True
        else:
            items.append(a)
    source = "file" if batch else ("paste" if len(items) == 1 else "file")
    if any(a == "-" for a in args):
        source = "stdin"
    return [i for i in items if i], source


def _lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _from_file(path: Path) -> list[str]:
    return items_from_text(path.read_text(encoding="utf-8-sig", errors="replace"), csv_text=path.suffix.lower() == ".csv")


def items_from_text(text: str, csv_text: bool = False) -> list[str]:
    """Domains from pasted or uploaded text: one per line, or a CSV (same column rules as a .csv file)."""
    text = text.lstrip("\ufeff")
    if not csv_text:
        return _lines(text)
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    col = next((header.index(c) for c in COLUMNS if c in header), None)
    body = rows[1:] if col is not None else rows
    return [r[col or 0].strip() for r in body if r and r[col or 0].strip()]


# ------------------------------------------------------------------ workers ---

_W = None
_KEEP: frozenset[str] | None = None


def _init(render_dir: str | None, keep_labels: tuple[str, ...] | None = None, certs: bool | None = None) -> None:
    global _W, _KEEP
    from doppel.brain.brain import Brain

    _W = Brain(render_dir=Path(render_dir) if render_dir else None, certs=certs)
    _KEEP = frozenset(keep_labels) if keep_labels else None


def _one(item_source: tuple[str, str]) -> dict:
    raw, source = item_source
    try:
        v = _W.investigate(raw, source)
    except (AddressError, ValueError, UnicodeError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "input": raw}
    if _KEEP is not None and v["label"] not in _KEEP:   # don't ship millions of benign verdicts between processes
        return {"compact": True, "label": v["label"],
                "reached": [s["stage"] for s in v["stages"] if s["status"] == "completed"][-1]}
    return v


IN_FLIGHT = 3


def _many(chunk: list[tuple[str, str]]) -> list[dict]:
    return [_one(x) for x in chunk]


def _chunks(it: Iterable, n: int) -> Iterator[list]:
    batch: list = []
    for x in it:
        batch.append(x)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch


def scan(items: Iterable[str], source: str = "file", workers: int | None = None, render_dir: Path | None = None,
         keep_labels: tuple[str, ...] | None = None, chunksize: int = 256,
         on_progress: Callable[[int], None] | None = None, certs: bool | None = None) -> tuple[list[dict], dict]:
    """Investigate every item. Returns (verdicts, stats). ``keep_labels`` limits which verdicts come back in
    full (e.g. drop benign in a 2-million-name run); the stats always count everything."""
    t0 = time.perf_counter()
    stats = {"total": 0, "errors": 0, "by_label": Counter(), "reached_stage": Counter(), "error_samples": []}
    out: list[dict] = []
    workers = workers if workers is not None else max(1, (os.cpu_count() or 2) - 1)
    jobs = ((i, source) for i in items)

    def results() -> Iterator[dict]:
        if workers <= 1:
            _init(str(render_dir) if render_dir else None, keep_labels, certs)
            yield from map(_one, jobs)
            return
        # Bounded submission: at most IN_FLIGHT chunks per worker exist at once. (Executor.map would submit
        # all 2.3M names up front and hold every pending result in memory.)
        with ProcessPoolExecutor(workers, initializer=_init,
                                 initargs=(str(render_dir) if render_dir else None, keep_labels, certs)) as pool:
            pending: deque = deque()
            chunks = _chunks(jobs, chunksize)
            for chunk in chunks:
                pending.append(pool.submit(_many, chunk))
                if len(pending) >= workers * IN_FLIGHT:
                    yield from pending.popleft().result()
            while pending:
                yield from pending.popleft().result()

    for v in results():
        stats["total"] += 1
        if on_progress and stats["total"] % 50_000 == 0:
            on_progress(stats["total"])
        if "error" in v:
            stats["errors"] += 1
            if len(stats["error_samples"]) < 20:
                stats["error_samples"].append(v)
            continue
        stats["by_label"][v["label"]] += 1
        reached = v["reached"] if v.get("compact") else [s["stage"] for s in v["stages"] if s["status"] == "completed"][-1]
        stats["reached_stage"][reached] += 1
        if not v.get("compact"):
            out.append(v)
    stats["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    stats["by_label"] = dict(stats["by_label"])
    stats["reached_stage"] = dict(stats["reached_stage"])
    return out, stats
