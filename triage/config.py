"""Settings from env + a YAML profile.

The profile holds everything environment-specific (dashboard URL, exclusions, rule lists,
noise sources). Keep real profiles outside the repo; point TRIAGE_PROFILE at one.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_PROFILE = Path.home() / ".config" / "wazuh-llm-triage" / "prod.yaml"
DEFAULT_DB = Path.home() / ".local" / "state" / "wazuh-llm-triage" / "triage.db"


def load_env_file(path):
    """Minimal KEY=VALUE loader; does not override variables already set."""
    p = Path(path).expanduser()
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip("'\"")
        if v:  # an empty value would shadow other credential sources
            os.environ.setdefault(k.strip(), v)


def read_kv(path):
    out = {}
    for line in Path(path).expanduser().read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


@dataclass
class Limits:
    max_window_min: int = 60        # heap guard: never query more than this window
    max_hits: int = 20
    max_terms: int = 25
    max_queries_per_run: int = 12
    timeout_s: int = 60


@dataclass
class Profile:
    dashboard_url: str
    creds_file: str
    clusters: list
    index: str = "*-wazuh-alerts-*"
    ts_field: str = "timestamp"
    verify_tls: bool = False
    base_filter: str = ""                    # applied to every query unless include_hidden
    cluster_filter: dict = field(default_factory=dict)   # cluster -> query_string
    api_allow: list = field(default_factory=list)        # Wazuh API GET path prefixes
    sections: dict = field(default_factory=dict)         # named query_strings for the report
    watch: list = field(default_factory=list)            # [{query, label}] expected 0
    noise: list = field(default_factory=list)            # [{query, label}] split out, not hidden
    dynamic_threshold: int = 20
    notes: str = ""                                      # extra context for the LLM
    report_groups: list = field(default_factory=list)    # [{title, rows: [{key, label}]}] for the hourly report
    limits: Limits = field(default_factory=Limits)


def load_profile(path=None):
    p = Path(path or os.environ.get("TRIAGE_PROFILE") or DEFAULT_PROFILE).expanduser()
    raw = yaml.safe_load(p.read_text())
    raw["limits"] = Limits(**(raw.get("limits") or {}))
    return Profile(**raw)


def db_path():
    p = Path(os.environ.get("TRIAGE_DB") or DEFAULT_DB).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p
