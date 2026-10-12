"""Claude tool-use loop (manual loop; no beta tool runner)."""
import logging
import os
from datetime import datetime, timezone

import anthropic

from . import guard
from .tools import ToolRunner, result_text, schemas

log = logging.getLogger(__name__)

# TRIAGE_PROVIDER=anthropic (default) | glm  (Z.ai, Anthropic-compatible endpoint)
PROVIDER = os.environ.get("TRIAGE_PROVIDER", "anthropic").lower()
MODEL = os.environ.get("TRIAGE_MODEL") or ("glm-4.7" if PROVIDER == "glm" else "claude-opus-5-5")
EFFORT = os.environ.get("TRIAGE_EFFORT", "medium")
GLM_BASE_URL = os.environ.get("GLM_BASE_URL", "https://api.z.ai/api/anthropic")
MAX_STEPS = 8
# server-side refusal fallback: security questions can trip the cyber classifier (Claude only)
FALLBACK = dict(betas=["server-side-fallback-2026-07-01"], fallbacks="default")

SYSTEM = """You are a SOC triage assistant for a Wazuh SIEM. Analysts ask questions in Slack; you answer
by querying the alert index with the tools, then reply.

Rules:
- Query before you answer. Never invent counts, IPs, rule ids or field names; if a tool fails, say so.
- Queries are Lucene query_string: escape / as \\/ in values (data.url:\\/login*), quote phrases.
- Keep queries cheap: smallest window that answers the question (max 60 min), count/top before search.
- Reply like an engineer: answer first, then one line per finding. Numbers carry their window.
- Never write headings, titles, or labels like "Assessment:", "Net:", "Key points:", "Triage verdict:".
- No preamble, no recap, no closing, no offers ("I can pull...", "let me know").
- Any question about attacks / web attacks: call attack_table. The table is shown under your reply.
  Your reply with a table = 1 verdict line + at most 2 bullets on the rows that matter and why.
  Do not describe, count or summarise the other rows; the table already shows them.
- No claims the tools did not show (what software a host runs, whether something is patched, intent).
- Slack mrkdwn: *bold*, `code`, short bullets. No markdown tables.
- Counts, IPs, URLs only from tool output. No estimates ("~230"), no extrapolation.
- If the question cannot be answered from these tools (no data source, window too long), say what is missing.
- Copy IPs, rule ids, hostnames and counts character-for-character from tool output.
- Never state IP ownership, ASN, geography or reputation; the tools do not provide it. Say "unknown" if asked.
- Prefer the saved queries below over writing your own for the same concept.

Saved queries. Pass the Lucene text (or just the name) as `query`:
{saved}

Environment:
{notes}"""


def system_prompt(profile):
    saved = "\n".join(f"- {k}: {v}" for k, v in profile.sections.items())
    saved += "".join(f"\n- noise '{n['label']}': {n['query']}" for n in profile.noise)
    return SYSTEM.format(saved=saved, notes=profile.notes.strip())


def _client():
    if PROVIDER == "glm":
        os.environ.pop("ANTHROPIC_API_KEY", None)  # else the SDK would send it to the GLM endpoint too
        return anthropic.Anthropic(base_url=GLM_BASE_URL, auth_token=os.environ["GLM_API_KEY"], api_key=None)
    return anthropic.Anthropic()


def _create(client, **kw):
    effort = kw.pop("effort", EFFORT)
    if PROVIDER == "glm":  # plain Messages API only; Claude-specific params dropped
        return client.messages.create(model=MODEL, max_tokens=16000, **kw)
    return client.beta.messages.create(model=MODEL, max_tokens=16000, output_config={"effort": effort},
                                       cache_control={"type": "ephemeral"}, **FALLBACK, **kw)


def ask(question, history, wazuh, profile, client=None):
    """Run one user turn. history: list of prior message dicts (mutated: turn appended).
    Returns (reply_text, queries_used, tables)."""
    client = client or _client()
    budget = guard.Budget(profile.limits.max_queries_per_run)
    runner = ToolRunner(wazuh, profile, budget)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    history.append({"role": "user", "content": f"[now: {now}]\n{question}"})
    tools = schemas(profile)
    for _ in range(MAX_STEPS):
        resp = _create(client, system=system_prompt(profile), tools=tools, messages=history)
        history.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in resp.content]})
        if resp.stop_reason == "refusal":
            return "Declined by the model's safety filter. Rephrase the question.", budget.used, runner.tables
        if resp.stop_reason != "tool_use":
            text = "\n".join(b.text for b in resp.content if b.type == "text").strip()
            return text or "(no answer)", budget.used, runner.tables
        results = []
        for b in resp.content:
            if b.type != "tool_use":
                continue
            try:
                out, err = result_text(runner.run(b.name, b.input)), False
            except Exception as e:  # guard + indexer errors go back to the model
                log.warning("tool %s failed: %s", b.name, e)
                out, err = f"Error: {e}", True
            log.info("tool %s %s -> %s", b.name, b.input, out[:200])
            results.append({"type": "tool_result", "tool_use_id": b.id, "content": out, "is_error": err})
        history.append({"role": "user", "content": results})
    return f"Stopped after {MAX_STEPS} steps without a final answer.", budget.used, runner.tables


def summarize(report_json, profile, client=None):
    """3-5 line summary of a computed report. No tools."""
    client = client or _client()
    msg = ("Hourly SIEM report data (computed, authoritative):\n" + report_json +
           "\n\nWrite 3-5 short lines: what matters this hour, then a 'Look at:' list (max 3 items) "
           "or 'Look at: nothing'. Use only numbers present above. Slack mrkdwn, no headings.")
    resp = _create(client, system=system_prompt(profile), effort="low",
                   messages=[{"role": "user", "content": msg}])
    if resp.stop_reason == "refusal":
        return "(summary declined by the model's safety filter)"
    return "\n".join(b.text for b in resp.content if b.type == "text").strip()
