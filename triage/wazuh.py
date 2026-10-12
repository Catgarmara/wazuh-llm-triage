"""Wazuh Dashboard client: indexer via /api/console/proxy, Wazuh API via /api/request.

Read-only by construction: indexer calls go through check_indexer_path (_search/_count only,
sent as GET), API calls are GET-only against an allowlist.
"""
import json
import logging
import urllib.parse

import requests
import urllib3

from . import guard
from .config import read_kv

log = logging.getLogger(__name__)


class WazuhError(RuntimeError):
    pass


class DashboardClient:
    def __init__(self, profile):
        self.p = profile
        self.s = requests.Session()
        self.s.headers.update({"osd-xsrf": "true", "Content-Type": "application/json"})
        self.s.verify = profile.verify_tls
        if not profile.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._logged_in = False

    def _url(self, path):
        return self.p.dashboard_url.rstrip("/") + path

    def login(self):
        kv = read_kv(self.p.creds_file)
        r = self.s.post(self._url("/auth/login"), timeout=self.p.limits.timeout_s,
                        data=json.dumps({"username": kv["USER"], "password": kv["PASS"]}))
        if r.status_code != 200:
            raise WazuhError(f"dashboard login failed: HTTP {r.status_code}")
        self._logged_in = True

    def _post(self, path, body):
        if not self._logged_in:
            self.login()
        for attempt in (1, 2):
            try:
                r = self.s.post(self._url(path), data=json.dumps(body), timeout=self.p.limits.timeout_s)
            except requests.ConnectionError:
                if attempt == 2:
                    raise
                log.warning("connection dropped, retrying once")
                continue
            if r.status_code == 401 and attempt == 1:
                self.login()
                continue
            return r

    def indexer(self, path, body, budget=None):
        guard.check_indexer_path(path)
        if budget:
            budget.take()
        q = urllib.parse.quote(path, safe="")
        with guard.INDEXER_LOCK:
            r = self._post(f"/api/console/proxy?path={q}&method=GET", body)
        if r.status_code != 200:
            raise WazuhError(f"indexer HTTP {r.status_code}: {r.text[:300]}")
        d = r.json()
        if d.get("timed_out"):
            log.warning("indexer query timed out (partial results)")
        return d

    def api_get(self, cluster, path):
        guard.check_api_get(path, self.p.api_allow)
        if cluster not in self.p.clusters:
            raise guard.GuardError(f"unknown cluster {cluster}")
        r = self._post("/api/login", {"idHost": cluster, "force": True})
        if r.status_code != 200:
            raise WazuhError(f"api login {cluster}: HTTP {r.status_code}")
        r = self._post("/api/request", {"method": "GET", "path": path, "body": {}, "id": cluster})
        if r.status_code != 200:
            raise WazuhError(f"api GET {path}: HTTP {r.status_code}: {r.text[:300]}")
        return r.json()


# ---- query builders (shared by tools and report) ----

def qs(query):
    return {"query_string": {"query": query or "*", "analyze_wildcard": True,
                             "allow_leading_wildcard": False}}


def bool_filter(profile, query, minutes, cluster=None, include_hidden=False):
    f = [{"range": {profile.ts_field: {"gte": f"now-{minutes}m"}}}, qs(query)]
    if profile.base_filter and not include_hidden:
        f.append(qs(profile.base_filter))
    if cluster:
        f.append(qs(profile.cluster_filter[cluster]))
    return {"bool": {"filter": f}}
