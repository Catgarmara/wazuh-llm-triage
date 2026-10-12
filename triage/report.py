"""Hourly report. Numbers come from fixed queries; Claude only writes the summary on top."""
import json
from datetime import datetime, timezone

from . import guard, store
from .wazuh import bool_filter, qs

WINDOW = 60  # minutes


def _search(c, p, budget, query, aggs=None, include_hidden=False):
    body = {"size": 0, "track_total_hits": True,
            "query": bool_filter(p, query, WINDOW, include_hidden=include_hidden)}
    if aggs:
        body["aggs"] = aggs
    return c.indexer(f"{p.index}/_search", body, budget)


def _clusters(p):
    return {"filters": {"filters": {k: qs(v) for k, v in p.cluster_filter.items()}}}


def _terms(field, size, **sub):
    t = {"terms": {"field": field, "size": size}}
    if sub:
        t["aggs"] = sub
    return t


def _buckets(agg):
    return [{"value": b["key"], "count": b["doc_count"]} for b in agg["buckets"]]


def build(c, p):
    """Returns a dict of computed sections. <= p.limits.max_queries_per_run indexer queries."""
    b = guard.Budget(p.limits.max_queries_per_run)
    noise_q = " OR ".join(f"({n['query']})" for n in p.noise) or "NOT *"
    r = {"window_min": WINDOW, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

    # 1. scoreboard: every named section + noise rows, split by cluster (one query)
    filt = {k: qs(v) for k, v in p.sections.items()}
    filt["l10_clean"] = qs(f"({p.sections['l10']}) AND NOT ({noise_q})")
    for n in p.noise:
        filt[f"noise: {n['label']} (L10+)"] = qs(f"({n['query']}) AND ({p.sections['l10']})")
    d = _search(c, p, b, "*", {"s": {"filters": {"filters": filt}, "aggs": {"cl": _clusters(p)}}})
    r["total"] = d["hits"]["total"]["value"]
    r["scoreboard"] = {k: {"all": v["doc_count"], **{cl: x["doc_count"] for cl, x in v["cl"]["buckets"].items()}}
                       for k, v in d["aggregations"]["s"]["buckets"].items()}
    sb = r["scoreboard"]

    # 2. attack table: successes + external web attacks + JSON-stream web attacks
    from .attacks import attack_rows
    aq = " OR ".join(f"({p.sections[k]})" for k in ("success", "web_attack_ext", "web_attack_json") if k in p.sections)
    r["attack_rows"], _ = attack_rows(c, p, aq or "rule.groups:attack", WINDOW, budget=b)

    # 3. L10+ top rules (noise excluded; noise has its own scoreboard rows)
    d = _search(c, p, b, f"({p.sections['l10']}) AND NOT ({noise_q})",
                {"rule": _terms("rule.id", 10, desc=_terms("rule.description", 1), ip=_terms("data.srcip", 3))})
    r["l10_top"] = [{"rule": x["key"], "count": x["doc_count"],
                     "desc": (x["desc"]["buckets"] or [{"key": "-"}])[0]["key"], "srcip": _buckets(x["ip"])}
                    for x in d["aggregations"]["rule"]["buckets"]]

    # 4. severity bands x cluster
    bands = {"0-6": "rule.level:<=6", "7-9": "rule.level:>=7 AND rule.level:<=9",
             "10-12": "rule.level:>=10 AND rule.level:<=12", "13+": "rule.level:>=13"}
    d = _search(c, p, b, "*", {"bands": {"filters": {"filters": {k: qs(v) for k, v in bands.items()}},
                                         "aggs": {"cl": _clusters(p)}}})
    r["bands"] = {k: {"all": v["doc_count"], **{cl: x["doc_count"] for cl, x in v["cl"]["buckets"].items()}}
                  for k, v in d["aggregations"]["bands"]["buckets"].items()}

    # 5. health: per-node volume (unfiltered), watch checks (expect 0), agents per cluster
    d = _search(c, p, b, "*", {"node": _terms("manager.name", 20)}, include_hidden=True)
    r["nodes"] = _buckets(d["aggregations"]["node"])
    if p.watch:
        d = _search(c, p, b, "*", {"w": {"filters": {"filters": {w["label"]: qs(w["query"]) for w in p.watch}}}},
                    include_hidden=True)
        r["watch_nonzero"] = {k: v["doc_count"] for k, v in d["aggregations"]["w"]["buckets"].items() if v["doc_count"]}
    r["agents"] = {}
    for cl in p.clusters:
        try:
            r["agents"][cl] = c.api_get(cl, "/agents/summary/status").get("data", {}).get("connection")
        except Exception as e:
            r["agents"][cl] = f"error: {e}"

    # 6. dynamic: quiet L10+ -> pull in lower levels
    r["dynamic"] = None
    if sb["l10_clean"]["all"] < p.dynamic_threshold:
        dyn = {"reason": f"L10+ (clean) = {sb['l10_clean']['all']} < {p.dynamic_threshold}"}
        d = _search(c, p, b, "rule.level:>=7 AND rule.level:<=9",
                    {"rule": _terms("rule.id", 10, desc=_terms("rule.description", 1))})
        dyn["l7_9_top"] = [{"rule": x["key"], "count": x["doc_count"],
                            "desc": (x["desc"]["buckets"] or [{"key": "-"}])[0]["key"]}
                           for x in d["aggregations"]["rule"]["buckets"]]
        d = _search(c, p, b, "rule.level:<=6", {"rule": _terms("rule.id", 100)})
        low = {x["key"]: x["doc_count"] for x in d["aggregations"]["rule"]["buckets"]}
        prev = store.recent_reports(24)
        seen = set()
        for rep in prev:
            seen |= set((rep.get("_low_rules") or {}).keys())
            seen |= {x["rule"] for x in rep.get("l10_top", [])}
        last_low = (prev[0].get("_low_rules") or {}) if prev else {}
        if prev:
            dyn["new_rules_vs_24_runs"] = sorted(k for k in low if k not in seen)[:15]
            movers = [(k, v, last_low.get(k, 0)) for k, v in low.items()]
            movers = [m for m in movers if m[1] >= 50 and m[1] >= 3 * max(m[2], 1)]
            dyn["l0_6_movers"] = [{"rule": k, "now": v, "prev": pv} for k, v, pv in
                                  sorted(movers, key=lambda m: -m[1])[:10]]
        else:
            dyn["note"] = "no report history yet; new-rule and mover checks start next run"
        r["dynamic"] = dyn
        r["_low_rules"] = low
    r["queries_used"] = b.used
    return r


def render(r, summary, profile=None):
    """Slack mrkdwn text."""
    sb = r["scoreboard"]

    def row(k, label):
        v = sb.get(k)
        if not v:
            return None
        split = " / ".join(f"{cl} {v[cl]}" for cl in v if cl != "all")
        return f"• {label}: *{v['all']}*  ({split})"

    lines = [f"*Wazuh hourly* — last {r['window_min']} min to {r['generated']}", "", summary, ""]
    lines.append("*Severity*")
    lines.append(row("l13", "L13+"))
    lines.append(row("l10_clean", "L10+ excl. noise"))
    for k in sb:
        if k.startswith("noise: "):
            lines.append(row(k, k[7:]))
    # section rows: grouped/labelled by the profile's report_groups, else every section by name
    groups = profile.report_groups if profile and profile.report_groups else \
        [{"title": "Sections", "rows": [{"key": k} for k in (profile.sections if profile else sb)
                                        if k not in ("l10", "l13") and not k.startswith("noise: ") and k != "l10_clean"]}]
    for g in groups:
        lines.append(f"*{g['title']}*")
        for rw in g["rows"]:
            lines.append(row(rw["key"], rw.get("label", rw["key"])))
    lines.append("*L10+ top rules*")
    for x in r["l10_top"][:5]:
        ips = ", ".join(i["value"] for i in x["srcip"])
        lines.append(f"• `{x['rule']}` ×{x['count']} {x['desc'][:60]}  {ips}")
    lines.append("*SIEM health*")
    for cl, a in r["agents"].items():
        if isinstance(a, dict):
            a = " ".join(f"{k} {v}" for k, v in a.items() if v or k in ("active", "disconnected"))
        lines.append(f"• agents {cl}: {a}")
    lines.append("• nodes: " + ", ".join(f"{n['value'].split('.')[0]} {n['count']}" for n in r["nodes"]))
    if r.get("watch_nonzero"):
        lines.append("• :warning: watch checks non-zero: " + ", ".join(f"{k} = {v}" for k, v in r["watch_nonzero"].items()))
    if r.get("dynamic"):
        dy = r["dynamic"]
        lines.append(f"*Low-level enrichment* ({dy['reason']})")
        for x in dy.get("l7_9_top", [])[:5]:
            lines.append(f"• L7-9 `{x['rule']}` ×{x['count']} {x['desc'][:60]}")
        if dy.get("new_rules_vs_24_runs"):
            lines.append("• new rules (not seen in last 24 runs): " + ", ".join(f"`{k}`" for k in dy["new_rules_vs_24_runs"]))
        for m in dy.get("l0_6_movers", [])[:5]:
            lines.append(f"• L0-6 mover `{m['rule']}`: {m['prev']} → {m['now']}")
        if dy.get("note"):
            lines.append(f"• {dy['note']}")
    return "\n".join(x for x in lines if x is not None)


def run(c, p, summarize_fn=None):
    r = build(c, p)
    public = {k: v for k, v in r.items() if not k.startswith("_")}
    summary = "(no summary)"
    if summarize_fn:
        try:
            summary = summarize_fn(json.dumps(public, default=str))
        except Exception as e:  # numbers still go out if the LLM is down or unkeyed
            summary = f"(summary unavailable: {type(e).__name__})"
    store.save_report(r)
    return render(r, summary, p), [r["attack_rows"]], r
