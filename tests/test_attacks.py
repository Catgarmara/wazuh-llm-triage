from triage import attacks


def _b(*keys, n=2):
    return {"buckets": [{"key": k, "doc_count": n} for k in keys]}


def _rule(rid, hits=9, plaintext=True, status="404", ua_n=9):
    e = _b()
    return {"key": rid, "doc_count": hits, "desc": _b("Path traversal (access log): encoded dot-dot sequence"),
            "lvl": {"value": 7.0},
            "ip": _b("192.0.2.10") if plaintext else e, "remote": e if plaintext else _b("198.51.100.20"),
            "ipn": {"value": 5 if plaintext else 0}, "remn": {"value": 0 if plaintext else 1},
            "url": _b("/app/find?q=x%2e%2e") if plaintext else e, "uri": e if plaintext else _b("/json/uri"),
            "id": _b(status) if plaintext else e, "code": e if plaintext else _b(status),
            "ua": _b("ua/1", n=ua_n), "srv": _b("web1", n=hits) if plaintext else e, "agent": _b("agent-x", n=hits)}


def _rows(*rules):
    return attacks.rows_from({"aggregations": {"rule": {"buckets": list(rules)}}})


def test_rows_merge_plaintext_and_json():
    a, b = _rows(_rule("31103"), _rule("31104", hits=3, plaintext=False))
    assert (a["url"], a["status"], a["host"], a["ip_top"], a["ip_more"]) == ("/app/find?q=x%2e%2e", ["404"], "web1", "192.0.2.10", 4)
    assert (b["url"], b["status"], b["host"], b["ip_top"], b["ip_more"]) == ("/json/uri", ["404"], "agent-x", "198.51.100.20", 0)


def test_shaping():
    assert attacks.short_desc("Path traversal (access log): encoded dot-dot sequence") == "Path traversal"
    assert attacks.short_path("/app/find?q=abc") == "/app/find"
    assert attacks.short_path("/static/assets/img/icons/misc/brand/logo.svg") == "/static/…/logo.svg"


def test_2xx_first_and_marker():
    rows = _rows(_rule("31103", hits=200), _rule("31106", hits=1, status="200", ua_n=1))
    assert rows[0]["rule"] == "31106" and rows[0]["ok"]
    cells = attacks._cells(rows[0])
    assert cells[0].endswith(" *") and cells[4].endswith("· 200")
    assert "* = 2xx" in attacks.footnote(rows)


def test_footnote_thresholds():
    rows = _rows(_rule("1", hits=10, ua_n=9), _rule("2", hits=10, ua_n=5))
    fn = attacks.footnote(rows)
    assert "UA 1: ua/1" in fn and "UA 2" not in fn and "host: web1" in fn


def test_slack_table_limits():
    big = [{"rule": str(i), "short_desc": "d" * 28, "level": 7, "hits": 1, "ip_top": "203.0.113.30", "ip_more": 9,
            "url": "/" + "u" * 300, "status": ["200"], "ok": False} for i in range(150)]
    t = attacks.to_slack_table(big)
    assert len(t["rows"]) <= 100 and sum(len(c["text"]) for r in t["rows"] for c in r) <= 10000
    assert all(len(r) == len(attacks.HEADERS) for r in t["rows"])
    assert all(isinstance(c, dict) for c in t["column_settings"]) and len(t["column_settings"]) == len(attacks.HEADERS)
