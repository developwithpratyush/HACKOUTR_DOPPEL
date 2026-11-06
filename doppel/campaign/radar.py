"""The radar: flagged domains -> typed edges (C18) -> weighted components -> campaign cards.

Nodes are registered owners (what an attacker buys: ``ftry.click`` for ``www-googleapis.ftry.click`` and
``fonts-googleapis.ftry.click``; the tenant on a hosting platform). Each node keeps its names, brand, risk,
sources (``nrd``, ``pdb``, ``live``) and first-seen time.

``build(items)`` returns ``{"campaigns": [card...], "graph": {"nodes", "edges"}, "stats"}``. Cards are ranked by
size and by how many independent kinds of link hold them together (a naming habit alone is the weakest).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx

from doppel.campaign.recipe import recipe, same_recipe
from doppel.campaign.template import Templater

JOIN = 0.5
WEIGHT = {"shared_cert": 1.0, "cert_recipe": 0.6, "naming_template": 0.6, "nrd_week": 0.15}
CLIQUE_MAX = 8                  # bigger template groups are drawn as a star (the links are the same)
ARMED_DAYS = 90
STRENGTH = {"shared_cert": "certain (one certificate names them)", "cert_recipe": "strong (same certificate recipe)",
            "naming_template": "naming habit only"}


def _node_key(item: dict) -> str:
    return (item.get("owner") or item["name"]).lower()


def build(items: list[dict], reg, templater: Templater | None = None, use_ct: bool = True) -> dict:
    t0 = time.perf_counter()
    tpl = templater or Templater(reg)
    nodes: dict[str, dict] = {}
    for it in items:
        k = _node_key(it)
        n = nodes.setdefault(k, {"id": k, "names": [], "brands": Counter(), "risk": 0.0, "sources": set(),
                                 "first_seen": None, "labels": Counter(), "templates": set(), "tricks": Counter()})
        if it["name"] not in n["names"]:
            n["names"].append(it["name"])
        if it.get("brand"):
            n["brands"][it["brand"]] += 1
        n["risk"] = max(n["risk"], float(it.get("risk") or 0))
        n["sources"].add(it.get("source", "?"))
        n["labels"][it.get("label", "?")] += 1
        for tr in filter(None, (it.get("tricks") or "").split(",")):
            n["tricks"][tr] += 1
        fs = it.get("first_seen")
        if fs is not None and (n["first_seen"] is None or fs < n["first_seen"]):
            n["first_seen"] = fs
        try:
            template, _ = tpl.of(it["name"])
        except Exception:                                  # noqa: BLE001 - an odd name just gets no template
            continue
        if tpl.specific(template):
            n["templates"].add(template)

    g = nx.Graph()
    g.add_nodes_from(nodes)
    pair_w: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)

    def link(a: str, b: str, kind: str, w: float, detail: str) -> None:
        if a == b:
            return
        key = (a, b) if a < b else (b, a)
        if w > pair_w[key].get(kind, (0.0, ""))[0]:       # keep the strongest edge of each kind
            pair_w[key][kind] = (w, detail)

    # 1. naming templates, per brand
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for k, n in nodes.items():
        brand = n["brands"].most_common(1)[0][0] if n["brands"] else "?"
        for tp in n["templates"]:
            groups[(brand, tp)].append(k)
    for (brand, tp), members in groups.items():
        if len(members) < 2:
            continue
        pairs = itertools.combinations(members, 2) if len(members) <= CLIQUE_MAX else ((members[0], m) for m in members[1:])
        for a, b in pairs:
            link(a, b, "naming_template", WEIGHT["naming_template"], tp)

    # 2. certificate recipes and shared certificates (CT cache only)
    recipes = {k: r for k in nodes if use_ct and (r := recipe(k))} if use_ct else {}
    by_shape: dict[str, list[str]] = defaultdict(list)
    by_sha: dict[str, list[str]] = defaultdict(list)
    for k, r in recipes.items():
        by_shape["|".join(r["shapes"])].append(k)
        for sha in r["shas"]:
            by_sha[sha].append(k)
        for san in r["sans"]:                       # a certificate of k that names another flagged owner
            for other in nodes:
                if other != k and (san == other or san.endswith("." + other)):
                    link(k, other, "shared_cert", WEIGHT["shared_cert"], f"{k}'s certificate names {san}")
    for sha, owners in by_sha.items():
        for a, b in itertools.combinations(sorted(set(owners)), 2):
            link(a, b, "shared_cert", WEIGHT["shared_cert"], f"certificate {sha[:12]}")
    for members in by_shape.values():
        for a, b in itertools.combinations(members, 2):
            w = same_recipe(recipes[a], recipes[b])
            if w:
                gap = abs(recipes[a]["first"] - recipes[b]["first"]) / 60
                link(a, b, "cert_recipe", w, f"{' / '.join(recipes[a]['shapes'])}; first certificates {gap:.0f} min apart")

    # 3. the same NRD snapshot: an annotation on pairs that are already linked
    for (a, b), kinds in pair_w.items():
        if "nrd" in nodes[a]["sources"] and "nrd" in nodes[b]["sources"]:
            kinds["nrd_week"] = (WEIGHT["nrd_week"], "both in the same 7-day NRD snapshot")

    edges = []
    for (a, b), kinds in pair_w.items():
        total = sum(w for w, _ in kinds.values())
        edges.append({"source": a, "target": b, "weight": round(total, 2),
                      "types": {k: d for k, (w, d) in kinds.items()}})
        if total >= JOIN:
            g.add_edge(a, b, weight=total)

    cards = []
    for comp in nx.connected_components(g):
        if len(comp) < 2:
            continue
        cards.append(_card(sorted(comp), nodes, recipes, [e for e in edges if e["source"] in comp and e["target"] in comp]))
    cards.sort(key=lambda c: (-c["rank"], -c["size"], c["id"]))
    in_campaign = {m for c in cards for m in c["members_ids"]}
    graph_nodes = [{"id": k, "brand": (nodes[k]["brands"].most_common(1) or [("?", 0)])[0][0], "risk": nodes[k]["risk"],
                    "names": nodes[k]["names"][:5], "campaign": next((c["id"] for c in cards if k in c["members_ids"]), None),
                    "sources": sorted(nodes[k]["sources"])} for k in sorted(in_campaign)]
    graph_edges = [e for e in edges if e["source"] in in_campaign and e["target"] in in_campaign and e["weight"] >= JOIN]
    return {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "campaigns": cards, "graph": {"nodes": graph_nodes, "edges": graph_edges},
            "stats": {"items": len(items), "domains": len(nodes), "with_recipe": len(recipes),
                      "campaigns": len(cards), "in_campaigns": len(in_campaign),
                      "edges_by_type": dict(Counter(t for e in graph_edges for t in e["types"])),
                      "elapsed_s": round(time.perf_counter() - t0, 2)}}


def _card(members: list[str], nodes: dict, recipes: dict, edges: list[dict]) -> dict:
    types = Counter(t for e in edges if e["weight"] >= JOIN for t in e["types"])
    brands = Counter()
    for m in members:
        brands.update(nodes[m]["brands"])
    templates = Counter(tp for e in edges for t, tp in e["types"].items() if t == "naming_template")
    rec = [recipes[m] for m in members if m in recipes]
    firsts = [r["first"] for r in rec if r["first"]]
    seen = [nodes[m]["first_seen"] for m in members if nodes[m]["first_seen"] is not None]
    armed = []
    for r in rec:
        fetched = r.get("fetched_at")
        if r["first"] and fetched:
            age = (dt.datetime.strptime(fetched[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
                   - r["first"]) / 86400
            if age <= ARMED_DAYS:
                armed.append(r["owner"])
    strength = next((STRENGTH[k] for k in ("shared_cert", "cert_recipe", "naming_template") if types.get(k)), "linked")
    iso = lambda x: dt.datetime.fromtimestamp(x, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if x else None  # noqa: E731
    cid = "C" + hashlib.sha1("|".join(members).encode()).hexdigest()[:8]
    shapes = Counter(s for r in rec for s in r["shapes"])
    issuers = Counter(i for r in rec for i in r["issuers"])
    return {
        "id": cid, "size": len(members), "members_ids": members,
        "members": [{"domain": m, "names": nodes[m]["names"][:6], "risk": nodes[m]["risk"],
                     "brand": (nodes[m]["brands"].most_common(1) or [(None, 0)])[0][0],
                     "sources": sorted(nodes[m]["sources"]), "first_seen": iso(nodes[m]["first_seen"]),
                     "first_cert": iso(recipes[m]["first"]) if m in recipes else None,
                     "subdomains": recipes[m]["subdomains"] if m in recipes else [],
                     "armed": m in armed} for m in members],
        "brands": dict(brands.most_common()), "templates": [t for t, _ in templates.most_common(3)],
        "links": dict(types), "strength": strength,
        "recipe": {"shapes": [s for s, _ in shapes.most_common()], "issuers": dict(issuers.most_common()),
                   "first_cert": iso(min(firsts)) if firsts else None, "last_cert": iso(max(firsts)) if firsts else None,
                   "span_h": round((max(firsts) - min(firsts)) / 3600, 1) if len(firsts) > 1 else None} if rec else None,
        "first_seen": iso(min(seen)) if seen else None, "last_seen": iso(max(seen)) if seen else None,
        "armed": armed, "sources": sorted({s for m in members for s in nodes[m]["sources"]}),
        "rank": round(len(members) * (1 + 0.5 * (len(types) - 1)) + (2 if types.get("shared_cert") or types.get("cert_recipe") else 0), 2),
    }


def index(result: dict) -> dict:
    """owner -> its campaign (for the brain's weak C18 signal)."""
    out = {}
    for c in result["campaigns"]:
        for m in c["members_ids"]:
            out[m] = {"campaign": c["id"], "size": c["size"], "links": sorted(c["links"]), "strength": c["strength"],
                      "template": (c["templates"] or [None])[0],
                      "peers": [x for x in c["members_ids"] if x != m][:5]}
    return out


def save(result: dict, folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    radar_p, index_p = folder / "radar.json", folder / "index.json"
    radar_p.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    index_p.write_text(json.dumps({"generated_at": result["generated_at"], "members": index(result)}, indent=1,
                                  ensure_ascii=False), encoding="utf-8")
    return radar_p, index_p
