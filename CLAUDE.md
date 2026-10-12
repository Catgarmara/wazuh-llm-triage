# CLAUDE.md

Guidance for Claude Code in this repo.

## What this is
Slack bot (`triage/`) that answers SOC questions from Wazuh alerts and posts an hourly report.
An LLM (Claude default, GLM optional, both via the `anthropic` SDK) drives a manual tool-use loop.
Code-enforced guards keep every query read-only and cheap. See README.md for setup and usage.

## Layout
| Path | Role |
|---|---|
| `triage/__main__.py` | CLI: `probe`, `ask`, `report`, `bot` |
| `triage/config.py` | env loader, YAML `Profile` + `Limits` dataclasses |
| `triage/guard.py` | read-only/heap guards: index path, window, size, wildcards, query budget, global lock |
| `triage/wazuh.py` | `DashboardClient`: Dashboard login, indexer via `/api/console/proxy`, Wazuh API via `/api/request` (GET only); `bool_filter`, `qs` |
| `triage/tools.py` | LLM tool schemas + `ToolRunner` handlers |
| `triage/llm.py` | system prompt, provider switch (Claude/GLM), `ask()` loop, `summarize()` |
| `triage/attacks.py` | attack-table aggregation, row shaping, Slack `table` block, footnote |
| `triage/report.py` | hourly report: fixed aggregations, dynamic low-level enrichment, `render()` |
| `triage/slack_app.py` | Bolt Socket Mode app, `post()` (text + table blocks), APScheduler hourly job |
| `triage/store.py` | sqlite: thread sessions, report history |
| `profiles/example.yaml` | example profile (copy outside the repo) |
| `archive/legacy-flask-app/` | previous Flask/DeepSeek app. Unused; do not import from it |

## Rules
- **Config and secrets stay outside the repo.** The profile goes in `TRIAGE_PROFILE`, default `~/.config/wazuh-llm-triage/prod.yaml`. Env vars go in `TRIAGE_ENV`, default `~/.config/wazuh-llm-triage/.env`. Never commit real hostnames, IPs, rule IDs, channel IDs or tokens.
- **Examples and tests use placeholders only:** documentation-range IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), `example.com`, and built-in Wazuh rule IDs.
- **Guards live in code (`guard.py`), never only in the prompt.** Any new tool goes through `guard.check_*`, `Budget` and `INDEXER_LOCK`.
- **Profile queries are Lucene `query_string`.** Escape `/` as `\/`, because a bare `/.../` is a regex. No leading wildcards.
- **Keep message history append-only.** Store `response.content` as returned. Persist a session only when the turn succeeded.
- **Slack `table` blocks:** `column_settings` entries must be objects. `null` is rejected even though the docs allow it. Limits are 100 rows and 10k chars per message.

## Commands
```bash
python -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python -m pytest              # offline; pytest.ini sets paths
venv/bin/python -m triage probe        # live: one size:0 count
venv/bin/python -m triage report --no-llm
venv/bin/python -m triage bot
```
