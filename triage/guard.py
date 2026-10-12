"""Read-only and heap guards. Enforced in code; the prompt is not trusted to keep queries safe."""
import re
import threading

ALLOWED_INDEX = re.compile(r"^[\w*-]*wazuh-alerts-[\w*.-]*$")
ALLOWED_OPS = {"_search", "_count"}
LEADING_WILDCARD = re.compile(r"(^|[\s(:])\*[^\s)]")   # *foo or field:*foo (field:* alone is fine)


class GuardError(ValueError):
    pass


class Budget:
    """Caps queries per chat turn / report run."""

    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def take(self):
        if self.used >= self.limit:
            raise GuardError(f"query budget exhausted ({self.limit} per run)")
        self.used += 1


# one indexer query at a time across the whole process
INDEXER_LOCK = threading.Lock()


def check_indexer_path(path):
    parts = path.strip("/").split("/")
    if len(parts) != 2 or not ALLOWED_INDEX.match(parts[0]) or parts[1] not in ALLOWED_OPS:
        raise GuardError(f"indexer path not allowed: {path}")


def check_query_string(q):
    if q and LEADING_WILDCARD.search(q):
        raise GuardError("leading wildcards are not allowed (slow); use a prefix like /login*")
    if len(q or "") > 2000:
        raise GuardError("query too long")


def check_window(minutes, limits):
    if not isinstance(minutes, int) or minutes < 1:
        raise GuardError("minutes must be a positive integer")
    if minutes > limits.max_window_min:
        raise GuardError(f"window {minutes}m exceeds max {limits.max_window_min}m")


def check_size(n, cap, what):
    if not isinstance(n, int) or n < 0 or n > cap:
        raise GuardError(f"{what} must be 0..{cap}")


def check_terms_field(field, query):
    if field == "data.url" and (not query or query.strip() in ("*", "")):
        raise GuardError("unscoped terms on data.url is not allowed; add a filter")


def check_api_get(path, allow):
    if not any(path.startswith(a) for a in allow):
        raise GuardError(f"Wazuh API path not allowed: {path}")
