"""Attack table: one aggregation -> exact rows, rendered as a slim Slack Block Kit table.

Plaintext and JSON nginx streams use different field names; each pair is merged per row:
URL = data.url | data.requesturi, status = data.id | data.code, host = data.servername | agent.name.
"""
import re

from . import guard
from .wazuh import bool_filter

HEADERS = ["Rule", "Lvl", "Hits", "Top IP", "Path · Status"]
MAX_RULES = 15
SLACK_TABLE_CHARS = 10000
DOMINANT = 0.8   # UA/host shown in the footnote only when one value covers >= 80% of a rule's hits


def _t(field, size):
    return {"terms": {"field": field, "size": size}}


def _keys(agg, with_counts=False):
    b = agg.get("buckets", []) if agg else []
    return [f"{x['key']}({x['doc_count']})" if with_counts else str(x["key"]) for x in b]


def _top(agg):
    b = (agg or {}).get("buckets") or []
    return (str(b[0]["key"]), b[0]["doc_count"]) if b else (None, 0)


def _cut(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def short_desc(desc, n=28):
    d = desc.split(":", 1)[0] if ":" in desc else desc
    d = re.sub(r"\s*\([^)]*\)", "", d).strip().rstrip(".")
    return _cut(d, n)


def short_path(url, n=40):
    p = (url or "-").split("?", 1)[0]
    if len(p) <= n:
        return p
    parts = p.split("/")
    if len(parts) > 3:
        p = "/".join(parts[:2]) + "/…/" + parts[-1]
    return _cut(p, n)


def body(profile, query, minutes, cluster=None):
    aggs = {"rule": {"terms": {"field": "rule.id", "size": MAX_RULES}, "aggs": {
        "desc": _t("rule.description", 1), "lvl": {"max": {"field": "rule.level"}},
        "ip": _t("data.srcip", 3), "remote": _t("data.remote", 3),
        "ipn": {"cardinality": {"field": "data.srcip"}}, "remn": {"cardinality": {"field": "data.remote"}},
        "url": _t("data.url", 1), "uri": _t("data.requesturi", 1),
        "id": _t("data.id", 3), "code": _t("data.code", 3),
        "ua": _t("data.agent", 1), "srv": _t("data.servername", 1), "agent": _t("agent.name", 1)}}}
    return {"size": 0, "track_total_hits": True, "query": bool_filter(profile, query, minutes, cluster), "aggs": aggs}


def rows_from(resp):
    rows = []
    for b in resp["aggregations"]["rule"]["buckets"]:
        hits = b["doc_count"]
        plain = bool(b["ip"]["buckets"])
        ips = _keys(b["ip"], True) if plain else _keys(b["remote"], True)
        ipn = (b.get("ipn") if plain else b.get("remn")) or {}
        ip_top = (_keys(b["ip"]) if plain else _keys(b["remote"]) or ["-"])
        status = _keys(b["id"]) or _keys(b["code"])
        ua, ua_n = _top(b["ua"])
        host, host_n = _top(b["srv"]) if b["srv"]["buckets"] else _top(b["agent"])
        desc = (_keys(b["desc"]) or ["-"])[0]
        rows.append({
            "rule": str(b["key"]), "desc": desc, "short_desc": short_desc(desc),
            "level": int(b["lvl"]["value"] or 0), "hits": hits,
            "ips": ips, "ip_top": (ip_top or ["-"])[0], "ip_more": max(int(ipn.get("value") or len(ips)) - 1, 0),
            "url": (_keys(b["url"]) or _keys(b["uri"]) or ["-"])[0],
            "status": status, "ok": any(s.startswith("2") for s in status),
            "ua": ua or "-", "ua_share": ua_n / hits if hits else 0,
            "host": host or "-", "host_share": host_n / hits if hits else 0,
        })
    rows.sort(key=lambda r: (not r["ok"], -r["hits"]))
    return rows


def attack_rows(client, profile, query, minutes, cluster=None, budget=None):
    query = profile.sections.get((query or "").strip(), query)
    guard.check_query_string(query)
    guard.check_window(minutes, profile.limits)
    resp = client.indexer(f"{profile.index}/_search", body(profile, query, minutes, cluster), budget)
    return rows_from(resp), resp["hits"]["total"]["value"]


def _cells(r):
    rule = f"{r['rule']} {r['short_desc']}" + (" *" if r["ok"] else "")
    ip = r["ip_top"] + (f" +{r['ip_more']}" if r["ip_more"] else "")
    return [rule, str(r["level"]), str(r["hits"]), ip,
            f"{short_path(r['url'])} · {','.join(r['status']) or '-'}"]


def to_slack_table(rows):
    L = {"align": "left"}  # Slack rejects null column_settings entries
    rs = rows[:99]
    while rs and sum(len(c) for r in rs for c in _cells(r)) + sum(map(len, HEADERS)) > SLACK_TABLE_CHARS - 500:
        rs = rs[:-1]
    return {"type": "table",
            "column_settings": [L, {"align": "right"}, {"align": "right"}, L, {"is_wrapped": True}],
            "rows": [[{"type": "raw_text", "text": h} for h in HEADERS]] +
                    [[{"type": "raw_text", "text": c} for c in _cells(r)] for r in rs]}


def footnote(rows):
    # only distinctive UAs (bot/tool strings) are worth a line; browser strings say nothing
    parts = [f"UA {r['rule']}: {_cut(r['ua'], 40)}" for r in rows
             if r["ua"] != "-" and not r["ua"].startswith("Mozilla/") and r["hits"] >= 5
             and r["ua_share"] >= DOMINANT][:3]
    hosts = sorted({r["host"] for r in rows if r["host"] != "-" and r["host_share"] >= DOMINANT})
    if hosts:
        parts.append("host: " + ", ".join(hosts[:3]) + (f" +{len(hosts) - 3}" if len(hosts) > 3 else ""))
    if any(r["ok"] for r in rows):
        parts.append("* = 2xx, reached the server")
    return " · ".join(parts)


def to_text(rows):
    if not rows:
        return "(no matching alerts)"
    lines = [" | ".join(HEADERS)] + [" | ".join(_cells(r)) for r in rows]
    fn = footnote(rows)
    return "\n".join(lines + ([fn] if fn else []))
