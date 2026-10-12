"""Claude tool schemas + handlers. Every handler goes through guard before touching the indexer."""
import json

from . import guard
from .wazuh import bool_filter

_CLUSTER = {"type": "string", "description": "Restrict to one cluster. Omit for all."}
_QUERY = {"type": "string", "description": "Lucene query_string (AND/OR/NOT, field:value, field:>=N). "
          "No leading wildcards. Use * for everything."}
_MIN = {"type": "integer", "description": "Look-back window in minutes (max 60)."}
_HIDDEN = {"type": "boolean", "description": "Include rules hidden by the profile base filter. Default false."}


def schemas(profile):
    cl = dict(_CLUSTER, enum=profile.clusters)
    lim = profile.limits
    return [
        {"name": "count", "description": "Count alerts matching a query in the last N minutes.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["query", "minutes"],
                          "properties": {"query": _QUERY, "minutes": _MIN, "cluster": cl, "include_hidden": _HIDDEN}}},
        {"name": "top", "description": f"Top values of a field (terms aggregation, max {lim.max_terms}) "
         "for alerts matching a query. Use for 'which IPs / rules / agents / URLs'.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["query", "field", "minutes"],
                          "properties": {"query": _QUERY, "field": {"type": "string", "description": "Keyword field, e.g. rule.id, data.srcip, agent.name"},
                                         "minutes": _MIN, "n": {"type": "integer", "description": f"Buckets, max {lim.max_terms}"},
                                         "cluster": cl, "include_hidden": _HIDDEN}}},
        {"name": "search", "description": f"Newest matching alerts (max {lim.max_hits}), only the listed fields.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["query", "minutes", "fields"],
                          "properties": {"query": _QUERY, "minutes": _MIN,
                                         "fields": {"type": "array", "items": {"type": "string"},
                                                    "description": "e.g. timestamp, rule.id, rule.description, data.srcip, data.url, agent.name"},
                                         "n": {"type": "integer", "description": f"Hits, max {lim.max_hits}"},
                                         "cluster": cl, "include_hidden": _HIDDEN}}},
        {"name": "attack_table", "description": "Attack breakdown per rule: description, level, hits, top IPs, sample URL, "
         "HTTP status, UA, host. Shown to the user as a table. Use for any question about attacks / web attacks. "
         "query defaults to rule.groups:attack; saved-query names (e.g. web_attack_ext, success) work.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["minutes"],
                          "properties": {"query": _QUERY, "minutes": _MIN, "cluster": cl}}},
        {"name": "agent_status", "description": "Wazuh agent connection summary for a cluster (active/disconnected/never_connected).",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["cluster"],
                          "properties": {"cluster": dict(cl, description="Cluster")}}},
        {"name": "disconnected_agents", "description": "List disconnected agents (name, ip, lastKeepAlive) for a cluster.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["cluster"],
                          "properties": {"cluster": dict(cl, description="Cluster")}}},
        {"name": "rule_info", "description": "Rule definition summary (level, description, groups, file) by rule id.",
         "input_schema": {"type": "object", "additionalProperties": False, "required": ["rule_id", "cluster"],
                          "properties": {"rule_id": {"type": "string"}, "cluster": dict(cl, description="Cluster")}}},
    ]


def _flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


class ToolRunner:
    def __init__(self, client, profile, budget):
        self.c, self.p, self.budget = client, profile, budget
        self.tables = []   # attack rows to render as Slack tables

    def run(self, name, args):
        fn = getattr(self, f"t_{name}", None)
        if not fn:
            raise guard.GuardError(f"unknown tool {name}")
        return fn(**args)

    def _q(self, query, minutes, cluster, include_hidden):
        # models sometimes pass a saved-query name instead of its Lucene; resolve it
        query = self.p.sections.get((query or "").strip(), query)
        guard.check_query_string(query)
        guard.check_window(minutes, self.p.limits)
        return bool_filter(self.p, query, minutes, cluster, include_hidden)

    def t_count(self, query, minutes, cluster=None, include_hidden=False):
        body = {"size": 0, "track_total_hits": True, "query": self._q(query, minutes, cluster, include_hidden)}
        d = self.c.indexer(f"{self.p.index}/_search", body, self.budget)
        return {"count": d["hits"]["total"]["value"], "minutes": minutes, "cluster": cluster or "all"}

    def t_top(self, query, field, minutes, n=10, cluster=None, include_hidden=False):
        guard.check_size(n, self.p.limits.max_terms, "n")
        guard.check_terms_field(field, query)
        body = {"size": 0, "track_total_hits": True, "query": self._q(query, minutes, cluster, include_hidden),
                "aggs": {"t": {"terms": {"field": field, "size": n}}}}
        d = self.c.indexer(f"{self.p.index}/_search", body, self.budget)
        return {"total": d["hits"]["total"]["value"], "field": field,
                "buckets": [{"value": b["key"], "count": b["doc_count"]} for b in d["aggregations"]["t"]["buckets"]],
                "other": d["aggregations"]["t"].get("sum_other_doc_count", 0)}

    def t_search(self, query, minutes, fields, n=10, cluster=None, include_hidden=False):
        guard.check_size(n, self.p.limits.max_hits, "n")
        body = {"size": n, "_source": fields, "sort": [{self.p.ts_field: "desc"}],
                "track_total_hits": True, "query": self._q(query, minutes, cluster, include_hidden)}
        d = self.c.indexer(f"{self.p.index}/_search", body, self.budget)
        return {"total": d["hits"]["total"]["value"],
                "hits": [dict(_flat(h["_source"]), _index=h["_index"]) for h in d["hits"]["hits"]]}

    def t_attack_table(self, minutes, query="rule.groups:attack", cluster=None):
        from .attacks import attack_rows
        rows, total = attack_rows(self.c, self.p, query, minutes, cluster, self.budget)
        self.tables.append(rows)
        return {"note": "Shown to the user as a table. Do not repeat it; comment only.",
                "total": total, "minutes": minutes, "rows": rows}

    def t_agent_status(self, cluster):
        return self.c.api_get(cluster, "/agents/summary/status").get("data")

    def t_disconnected_agents(self, cluster):
        d = self.c.api_get(cluster, "/agents?status=disconnected&select=name,ip,lastKeepAlive&limit=50")
        return d.get("data")

    def t_rule_info(self, rule_id, cluster):
        if not str(rule_id).isdigit():
            raise guard.GuardError("rule_id must be numeric")
        d = self.c.api_get(cluster, f"/rules?rule_ids={rule_id}&select=id,level,description,groups,filename")
        return d.get("data")


def result_text(obj):
    s = json.dumps(obj, default=str, separators=(",", ":"))
    return s if len(s) <= 20000 else s[:20000] + "...(truncated)"
