// The one place the UI talks to the API. If the API is down, the gallery falls back to the contract's
// mock verdicts (contracts/examples, imported at build time), and the UI says so in the header.
import type { BrandInfo, Health, LiveCatch, LiveResponse, RadarResponse, ScanResponse, Source, Verdict } from "./types";

const mockFiles = import.meta.glob("../../../contracts/examples/*.json", { eager: true, import: "default" }) as
  Record<string, Verdict>;
/** Mock verdicts by file stem ("02-twin-letters"). `meta.mock = true`: illustrative numbers. */
export const MOCKS: Record<string, Verdict> = Object.fromEntries(
  Object.entries(mockFiles).map(([path, v]) => [path.split("/").pop()!.replace(/\.json$/, ""), v]),
);

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

async function call<T>(path: string, init?: RequestInit, timeoutMs = 30000): Promise<T> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(path, { ...init, signal: ctl.signal });
    if (!r.ok) {
      let detail = r.statusText;
      try { const j = await r.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not JSON */ }
      throw new ApiError(detail || `HTTP ${r.status}`, r.status);
    }
    return (await r.json()) as T;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError("The Doppel API isn't reachable (start it with `python -m doppel.cli serve`).", 0);
  } finally {
    clearTimeout(timer);
  }
}

const json = (body: unknown): RequestInit => ({
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});

export const api = {
  health: () => call<Health>("/api/health", undefined, 2500),
  brands: () => call<{ brands: BrandInfo[] }>("/api/brands").then((r) => r.brands),
  /** One verdict. ``certs = false`` is the P11 ablation switch: Certificate Forensics (C16/C17) off. */
  investigate: (raw: string, source: Source = "paste", certs = true) =>
    call<Verdict>("/api/investigate", json({ raw, source, certs })),
  scan: (items: string[], source: Source = "file") => call<ScanResponse>("/api/scan", json({ items, source }), 180000),
  upload: (file: File, source: Source = "file") => {
    const fd = new FormData();
    fd.append("file", file);
    return call<ScanResponse>(`/api/scan/upload?source=${source}`, { method: "POST", body: fd }, 180000);
  },
  /** The case file (P10) for a verdict: printable HTML (grounded narration, actions, evidence appendix). */
  report: async (verdict: Verdict, lang: "en" | "hi" = "en"): Promise<string> => {
    const r = await fetch("/api/report", json({ verdict, lang }));
    if (!r.ok) {
      let detail = r.statusText;
      try { detail = (await r.json()).detail ?? detail; } catch { /* not JSON */ }
      throw new ApiError(String(detail), r.status);
    }
    return r.text();
  },
  /** Campaign Radar (P13): campaign cards + the island graph from the latest `doppel campaigns` run. */
  campaigns: () => call<RadarResponse>("/api/campaigns"),
  /** Live Hunt (P12): the collector's state, all-time numbers and latest catches. Polled once a second. */
  live: (mode: "live" | "replay") => call<LiveResponse>(`/api/live/state?mode=${mode}`, undefined, 5000),
  /** One catch with the verdict stored when it was flagged (opened in the Decision Trace as is). */
  liveCatch: (name: string, mode: "live" | "replay") =>
    call<LiveCatch>(`/api/live/catch?mode=${mode}&name=${encodeURIComponent(name)}`),
  recordings: () => call<{ recordings: { name: string; bytes: number; modified: number }[] }>("/api/live/recordings"),
  startReplay: (files: string[] = [], speed = 1) => call<{ started: boolean; pid: number }>("/api/live/replay", json({ files, speed })),
  stopReplay: () => call<{ stopping: boolean }>("/api/live/replay/stop", json({})),
  exportUrl: (scanId: string, fmt: string, includeReview = false) =>
    `/api/scan/${scanId}/export/${fmt}${includeReview ? "?include_review=true" : ""}`,
};

/** Artifact paths in evidence are repo-relative ("runs/renders/x_sms.png"); the API serves them as-is. */
export const artifactUrl = (path: string) => (/^[a-z]:|^\//i.test(path) ? null : "/" + path.replace(/^\.?\//, ""));

export function download(name: string, text: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
