"""Validate data against the Doppel contracts in ``contracts/``.

Two layers:

1. JSON Schema (``contracts/evidence.schema.json``, ``contracts/registry.schema.json``).
2. Cross-field invariants that a schema can't express (evidence IDs that resolve,
   stage order, hard rule <-> label, a trace that replays cleanly). These are
   listed in ``contracts/README.md`` and are part of the contract.

Every ``validate_*`` function returns a list of human-readable problems; an
empty list means valid.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = REPO_ROOT / "contracts"
EVIDENCE_SCHEMA_PATH = CONTRACTS_DIR / "evidence.schema.json"
REGISTRY_SCHEMA_PATH = CONTRACTS_DIR / "registry.schema.json"

STAGE_ORDER = ("quick", "standard", "deep")
GENUINE_RULE = "H1_genuine_family"
RULE_FORCES = {
    "H1_genuine_family": "genuine",
    "H2_brand_claim_foreign_credentials": "phishing",
    "H3_accepts_any_credentials": "phishing",
    "H4_direct_exfil_channel": "phishing",
}


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. doppel.contract reads the repo's contracts/ folder, "
            "so install with `pip install -e .` from the repo root."
        )
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def load_schema() -> dict[str, Any]:
    return _load_json(EVIDENCE_SCHEMA_PATH)


@lru_cache(maxsize=None)
def _validator(definition: str | None) -> Draft202012Validator:
    """A validator for the whole schema (definition=None) or one ``$defs`` entry."""
    schema = load_schema()
    if definition is not None:
        schema = {**schema, "$ref": f"#/$defs/{definition}"}
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_errors(obj: Any, definition: str | None) -> list[str]:
    errors = sorted(_validator(definition).iter_errors(obj), key=lambda e: list(e.absolute_path))
    out = []
    for err in errors:
        where = "/".join(str(p) for p in err.absolute_path) or "(root)"
        out.append(f"schema: {where}: {err.message}")
    return out


# ---------------------------------------------------------------- evidence ---

def _evidence_semantics(ev: dict[str, Any], where: str = "evidence") -> list[str]:
    errs = []
    if ev.get("points_to") == "neutral" and ev.get("score") != 0:
        errs.append(f"{where} {ev.get('evidence_id')}: a neutral finding must have score 0")
    return errs


def validate_evidence_item(obj: Any) -> list[str]:
    errs = _schema_errors(obj, "evidence_item")
    return errs or _evidence_semantics(obj)


# ----------------------------------------------------------------- verdict ---

def _verdict_semantics(v: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    evidence = v["evidence"]
    by_id: dict[str, dict[str, Any]] = {}
    for ev in evidence:
        eid = ev["evidence_id"]
        if eid in by_id:
            errs.append(f"duplicate evidence_id {eid}")
        by_id[eid] = ev
        errs += _evidence_semantics(ev)

    def unknown(ids: list[str], where: str) -> None:
        for eid in ids:
            if eid not in by_id:
                errs.append(f"{where} cites unknown evidence {eid}")

    # Stages: fixed order, quick always runs, a skipped stage ends the run.
    stages = v["stages"]
    names = [s["stage"] for s in stages]
    if tuple(names) != STAGE_ORDER:
        errs.append(f"stages must be {list(STAGE_ORDER)} in order, got {names}")
        return errs
    if stages[0]["status"] != "completed":
        errs.append("the quick stage always runs")
    for earlier, later in zip(stages, stages[1:]):
        if earlier["status"] == "skipped" and later["status"] == "completed":
            errs.append(f"{later['stage']} ran after {earlier['stage']} was skipped")

    listed: dict[str, str] = {}
    for s in stages:
        unknown(s["evidence_ids"], f"stage {s['stage']}")
        tools_seen = set()
        for eid in s["evidence_ids"]:
            if eid in listed:
                errs.append(f"evidence {eid} is listed in both {listed[eid]} and {s['stage']}")
            listed[eid] = s["stage"]
            ev = by_id.get(eid)
            if ev is None:
                continue
            tools_seen.add(ev["tool"])
            if ev["stage"] != s["stage"]:
                errs.append(f"evidence {eid} has stage {ev['stage']} but is listed under {s['stage']}")
        if s["status"] == "completed" and tools_seen != set(s["tools"]):
            errs.append(
                f"stage {s['stage']}: tools {sorted(s['tools'])} don't match the tools "
                f"in its evidence {sorted(tools_seen)}"
            )
        timing = v["timings_ms"][s["stage"]]
        if s["status"] == "skipped" and timing is not None:
            errs.append(f"timings_ms.{s['stage']} must be null for a skipped stage")
        if s["status"] == "completed" and timing is None:
            errs.append(f"timings_ms.{s['stage']} is missing for a completed stage")
    for eid in by_id:
        if eid not in listed:
            errs.append(f"evidence {eid} isn't listed under any stage")

    # Brand and closeness go together.
    if (v["target_brand"] is None) != (v["closeness"] is None):
        errs.append("target_brand and closeness must both be null or both be set")

    # Hard rule <-> label.
    rule = v["hard_rule"]
    label = v["label"]
    if rule is not None:
        unknown(rule["evidence_ids"], "hard_rule")
        if rule["forces"] != RULE_FORCES[rule["id"]]:
            errs.append(f"hard rule {rule['id']} forces {RULE_FORCES[rule['id']]}, not {rule['forces']}")
        if label != rule["forces"]:
            errs.append(f"hard rule {rule['id']} fired but the label is {label}")
        also = rule.get("also_fired", [])
        if also and rule["id"] == GENUINE_RULE:
            errs.append("H1_genuine_family can't fire together with phishing rules")
        priority = list(RULE_FORCES)
        for other in also:
            if priority.index(other) <= priority.index(rule["id"]):
                errs.append(f"hard_rule.id must be the highest-priority rule; {other} outranks {rule['id']}")
    if label == "genuine" and (rule is None or rule["id"] != GENUINE_RULE):
        errs.append("a genuine label needs the H1_genuine_family hard rule (proven ownership)")
    if label == "sleeper" and stages[2]["status"] != "skipped":
        errs.append("a sleeper has no live page, so the deep stage must be skipped")

    cf = v["counterfactual"]
    if cf is not None:
        unknown(cf["undone_evidence_ids"], "counterfactual")
        if cf["label"] == label:
            errs.append("the counterfactual must flip the label")

    # Trace: replayable in order, starts with the case, ends with the verdict.
    trace = v["trace"]
    for i, step in enumerate(trace, start=1):
        if step["step"] != i:
            errs.append(f"trace steps must be numbered 1..n in order (step {i} is {step['step']})")
            break
    for prev, cur in zip(trace, trace[1:]):
        if cur["t_ms"] < prev["t_ms"]:
            errs.append(f"trace step {cur['step']} starts before step {prev['step']}")
    if trace[0]["kind"] != "case_opened":
        errs.append("the trace must start with case_opened")
    last = trace[-1]
    if last["kind"] != "final_verdict":
        errs.append("the trace must end with final_verdict")
    else:
        if last.get("label") != label:
            errs.append(f"final trace step label {last.get('label')} != verdict label {label}")
        if last.get("risk_after") != v["risk_score"]:
            errs.append("final trace step risk_after must equal risk_score")

    completed = {s["stage"] for s in stages if s["status"] == "completed"}
    traced: set[str] = set()
    for step in trace:
        unknown(step.get("evidence_ids", []), f"trace step {step['step']}")
        if step["kind"] == "hard_rule" and rule is None:
            errs.append(f"trace step {step['step']} shows a hard rule but hard_rule is null")
        if step["kind"] != "tool":
            continue
        if step["stage"] not in completed:
            errs.append(f"trace step {step['step']} calls a tool in skipped stage {step['stage']}")
        for eid in step["evidence_ids"]:
            ev = by_id.get(eid)
            if ev is not None and (ev["tool"] != step["tool"] or ev["stage"] != step["stage"]):
                errs.append(f"trace step {step['step']} ({step['tool']}) cites {eid} from {ev['tool']}")
            traced.add(eid)
    for eid in by_id:
        if eid not in traced:
            errs.append(f"evidence {eid} never appears in a tool step of the trace")

    return errs


def validate_verdict(obj: Any) -> list[str]:
    errs = _schema_errors(obj, "verdict")
    return errs or _verdict_semantics(obj)


def validate_scan_result(obj: Any) -> list[str]:
    errs = _schema_errors(obj, "scan_result")
    if errs:
        return errs
    for i, v in enumerate(obj["verdicts"]):
        errs += [f"verdicts[{i}] ({v['domain']}): {e}" for e in _verdict_semantics(v)]
    if obj["summary"]["total"] != len(obj["verdicts"]):
        errs.append("summary.total doesn't match the number of verdicts")
    return errs


def validate_document(obj: Any) -> list[str]:
    """Validate a verdict, a scan result or a single evidence item, by its shape."""
    if isinstance(obj, dict) and "verdicts" in obj:
        return validate_scan_result(obj)
    if isinstance(obj, dict) and "evidence_id" in obj:
        return validate_evidence_item(obj)
    return validate_verdict(obj)


# ---------------------------------------------------------------- registry ---

def validate_registry(obj: Any) -> list[str]:
    errs = [
        f"schema: {'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
        for e in Draft202012Validator(_load_json(REGISTRY_SCHEMA_PATH)).iter_errors(obj)
    ]
    if errs:
        return errs
    restricted = {r["suffix"] for r in obj["restricted_registries"]}
    shared_lures = [w["word"] for w in obj["lure_words"]]
    for word in {w for w in shared_lures if shared_lures.count(w) > 1}:
        errs.append(f"lure word {word} is listed twice")
    all_aliases = {a: b["id"] for b in obj["brands"] for a in b["aliases"]}
    for word in shared_lures:
        if word in all_aliases:
            errs.append(f"lure word {word} is also an alias of {all_aliases[word]} (a token can't be both)")
    tld_rows = {row["tld"]: row["brand"] for row in obj.get("brand_tld_registry", [])}
    seen_ids: set[str] = set()
    owner_of: dict[str, str] = {}
    for brand in obj["brands"]:
        bid = brand["id"]
        if bid in seen_ids:
            errs.append(f"duplicate brand id {bid}")
        seen_ids.add(bid)
        if "brand_tld_registry" in obj:
            for tld in brand["brand_tlds"]:
                if tld_rows.get(tld) != bid:
                    errs.append(f"{bid}: brand TLD .{tld} needs a brand_tld_registry row for {bid}")
        for w in brand["lure_words"]:
            if w["word"] in all_aliases:
                errs.append(f"{bid}: lure word {w['word']} is also an alias of {all_aliases[w['word']]}")
            if w["word"] in shared_lures:
                errs.append(f"{bid}: lure word {w['word']} is already in the shared lexicon")
        for a in brand.get("exact_aliases", []):
            if a not in brand["aliases"]:
                errs.append(f"{bid}: exact alias {a} isn't one of its aliases")
        family = [e["domain"] for e in brand["genuine_family"]]
        for uc in brand.get("user_content_hosts", []):
            host = uc["host"]
            # A user-content host may sit inside the family (sites.google.com) or outside it
            # (forms.gle); either way it must never be a genuine_family entry itself.
            if host in family:
                errs.append(f"{bid}: {host} is listed as both genuine family and user content")
        for suffix in brand["restricted_suffixes"]:
            if suffix not in restricted:
                errs.append(f"{bid}: restricted suffix {suffix} isn't in restricted_registries")
        for entry in brand["genuine_family"]:
            dom = entry["domain"]
            if dom in owner_of and owner_of[dom] != bid:
                errs.append(f"{dom} is in the family of both {owner_of[dom]} and {bid}")
            owner_of[dom] = bid
            if entry["proof"] == "brand_tld" and dom.rsplit(".", 1)[-1] not in brand["brand_tlds"]:
                errs.append(f"{bid}: {dom} claims brand_tld proof but its TLD isn't in brand_tlds")
            if entry["proof"] == "restricted_registry" and not any(
                dom.endswith("." + s) for s in brand["restricted_suffixes"]
            ):
                errs.append(f"{bid}: {dom} claims restricted_registry proof but isn't under its restricted_suffixes")
    return errs


def load_yaml(path: Path) -> Any:
    """Load YAML, keeping dates such as 2026-11-04 as ISO strings (as the schema expects)."""
    import yaml

    class _Loader(yaml.SafeLoader):
        pass

    _Loader.add_constructor(
        "tag:yaml.org,2002:timestamp", lambda loader, node: loader.construct_scalar(node)
    )
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
