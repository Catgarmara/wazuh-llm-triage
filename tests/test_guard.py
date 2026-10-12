import pytest

from triage import guard
from triage.config import Limits, Profile
from triage.tools import ToolRunner

L = Limits()


@pytest.mark.parametrize("path", ["*-wazuh-alerts-*/_search", "x-wazuh-alerts-2026.10.12/_count"])
def test_indexer_path_ok(path):
    guard.check_indexer_path(path)


@pytest.mark.parametrize("path", ["*-wazuh-alerts-*/_delete_by_query", "*-wazuh-alerts-*/_doc/1",
                                  ".kibana/_search", "_cluster/settings", "*-wazuh-alerts-*/_search/x",
                                  "*/_search", "wazuh-states-*/_search"])
def test_indexer_path_blocked(path):
    with pytest.raises(guard.GuardError):
        guard.check_indexer_path(path)


@pytest.mark.parametrize("q", ["*login*", "data.url:*login", "a AND (*x)"])
def test_leading_wildcard_blocked(q):
    with pytest.raises(guard.GuardError):
        guard.check_query_string(q)


@pytest.mark.parametrize("q", ["*", "data.srcip:*", "data.url:/login*", "rule.level:>=10 AND NOT x:y"])
def test_query_ok(q):
    guard.check_query_string(q)


def test_window():
    guard.check_window(60, L)
    for bad in (0, 61, 1440, "60"):
        with pytest.raises(guard.GuardError):
            guard.check_window(bad, L)


def test_terms_data_url_unscoped():
    with pytest.raises(guard.GuardError):
        guard.check_terms_field("data.url", "*")
    guard.check_terms_field("data.url", "rule.id:31106")


def test_api_allowlist():
    allow = ["/agents/summary/status", "/rules?"]
    guard.check_api_get("/agents/summary/status", allow)
    for bad in ("/manager/configuration", "/security/users", "/agents/001/restart"):
        with pytest.raises(guard.GuardError):
            guard.check_api_get(bad, allow)


def test_budget():
    b = guard.Budget(2)
    b.take(); b.take()
    with pytest.raises(guard.GuardError):
        b.take()


class FakeClient:
    def __init__(self):
        self.calls = []

    def indexer(self, path, body, budget=None):
        guard.check_indexer_path(path)
        if budget:
            budget.take()
        self.calls.append(body)
        return {"hits": {"total": {"value": 7}, "hits": []},
                "aggregations": {"t": {"buckets": [{"key": "192.0.2.10", "doc_count": 7}], "sum_other_doc_count": 0}}}


def _profile():
    return Profile(dashboard_url="https://x", creds_file="/dev/null", clusters=["a"],
                   base_filter="NOT rule.id:1", cluster_filter={"a": "manager.name:a*"})


def test_tool_applies_base_filter_and_caps():
    c = FakeClient()
    r = ToolRunner(c, _profile(), guard.Budget(5))
    assert r.run("count", {"query": "*", "minutes": 30})["count"] == 7
    f = c.calls[0]["query"]["bool"]["filter"]
    assert {"range": {"timestamp": {"gte": "now-30m"}}} in f
    assert any(x.get("query_string", {}).get("query") == "NOT rule.id:1" for x in f)
    with pytest.raises(guard.GuardError):
        r.run("top", {"query": "*", "field": "rule.id", "minutes": 10, "n": 500})
    with pytest.raises(guard.GuardError):
        r.run("search", {"query": "*", "minutes": 10, "fields": ["x"], "n": 1000})
    with pytest.raises(guard.GuardError):
        r.run("count", {"query": "*", "minutes": 120})


def test_saved_query_name_resolves():
    c = FakeClient()
    p = _profile()
    p.sections = {"ssh_external": "rule.groups:sshd AND x:y"}
    ToolRunner(c, p, guard.Budget(5)).run("count", {"query": "ssh_external", "minutes": 15})
    f = c.calls[0]["query"]["bool"]["filter"]
    assert any(x.get("query_string", {}).get("query") == "rule.groups:sshd AND x:y" for x in f)
