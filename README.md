# wazuh-llm-triage

Slack bot that answers SOC questions from Wazuh alerts and posts an hourly report.
An LLM (Claude by default, GLM optional) plans the queries. Code makes sure every query is read-only and cheap.

## How it works

```
Slack @mention / DM
  -> Bolt (Socket Mode, no public endpoint)
  -> LLM tool loop (max 8 steps)
       tools: count | top | search | attack_table | agent_status | disconnected_agents | rule_info
  -> guard.py checks (path, window, size, wildcard, budget)
  -> Wazuh Dashboard
       indexer:   /api/console/proxy  (_search/_count, sent as GET)
       Wazuh API: /api/request        (GET, allowlisted paths)
  -> reply in thread + native Slack table for attack questions
```

**Attack table.** Exact numbers from one aggregation; the LLM only adds a verdict line.

```
Rule                       Lvl  Hits  Top IP              Path · Status
31106 Attack, HTTP 200 *     6     1  203.0.113.9         /app/upload · 200
31103 SQL injection          7   233  198.51.100.4 +232   /app/find · 404
* = 2xx, reached the server · UA 31103: scanner-bot/1 · host: app.example.com
```

**Hourly report.** A cron job (minute `TRIAGE_REPORT_MINUTE`, default 5, UTC) runs a fixed set of aggregations over the last 60 min:
- scoreboard of the named sections, per cluster
- attack table
- top L10+ rules
- severity bands
- per-node volume
- watch checks
- agent status

When L10+ is quiet, the report also checks the low levels: rules not seen in the last 24 runs, and rules that jumped against the previous hour.

The LLM writes a short summary on top. If the LLM fails, the numbers still post.

Thread history lives in sqlite (`~/.local/state/wazuh-llm-triage/triage.db`; set `TRIAGE_DB` to change it), with a 24h TTL.

## Safety guards (enforced in code, not the prompt)

- **Indexer path:** must be `<index matching *wazuh-alerts-*>/_search` or `/_count`. Nothing else.
- **Wazuh API:** GET only, on paths allowlisted in the profile's `api_allow`. The cluster must be in `clusters`. `rule_id` must be numeric.
- **Time window:** 1 to 60 minutes (`limits.max_window_min`).
- **`search`:** max 20 hits (`limits.max_hits`), returning only the requested fields.
- **`top`:** max 25 buckets (`limits.max_terms`). Unscoped terms on `data.url` are rejected.
- **Wildcards:** leading wildcards are rejected, and `allow_leading_wildcard: false` is set on every query_string. Query length max 2000.
- **Budget:** 12 indexer queries per chat turn or report run (`limits.max_queries_per_run`).
- **Concurrency:** one indexer query in flight per process, and one chat turn at a time.
- **Timeouts and output:** requests time out after 60s. Tool results are truncated at 20k chars.
- **Base filter:** the profile's `base_filter` is ANDed onto every query unless the tool call sets `include_hidden`.
- **Who can ask:** `SLACK_ALLOWED_USERS` takes comma-separated user IDs. **If it's empty, anyone in the workspace can query.**

Use a dedicated read-only Dashboard user. The guards are defence in depth, not a substitute.

## Setup

Python 3.10+.

```bash
python -m venv venv && . venv/bin/activate
pip install -r requirements.txt
```

### Slack app

1. Go to api.slack.com/apps -> Create New App -> From a manifest, and paste `slack-manifest.yaml`.
2. Under Basic Information -> App-Level Tokens, create a token with `connections:write`. That's the `xapp-...` token.
3. Install the app to the workspace and copy the Bot token (`xoxb-...`).
4. `/invite` the bot to the report channel, then copy the channel ID (channel name -> About -> bottom).

### Profile (YAML, keep it outside the repo)

The default path is `~/.config/wazuh-llm-triage/prod.yaml`. Override it with `TRIAGE_PROFILE` or `--profile`.

```yaml
dashboard_url: https://wazuh.example.com
creds_file: ~/.config/wazuh-llm-triage/dashboard.creds   # USER=... / PASS=... (no quotes)
verify_tls: true
index: "*-wazuh-alerts-*"
ts_field: timestamp

clusters: [east, west]                 # Wazuh API host ids configured in the Dashboard
cluster_filter:                        # same keys as clusters
  east: "manager.name:east*"
  west: "manager.name:west*"

base_filter: ""                        # optional, ANDed onto every query

api_allow: ["/agents/summary/status", "/agents?", "/rules?"]

sections:                              # named Lucene queries: scoreboard rows + LLM shortcuts
  l10: "rule.level:>=10"               # required
  l13: "rule.level:>=13"
  success: "rule.groups:attack_successful OR rule.id:(31106 OR 31168 OR 31169)"
  web_attack_ext: "rule.groups:web AND rule.groups:attack AND data.srcip:* AND NOT data.srcip:(10.* OR 192.168.*)"
  brute: "rule.groups:authentication_failures"
  ssh_external: "rule.groups:sshd AND data.srcip:* AND NOT data.srcip:(10.* OR 192.168.*)"

watch:                                 # expected 0; flagged when non-zero
  - {label: "decoder errors", query: "rule.id:1002"}

noise:                                 # split into its own scoreboard row, never hidden
  - {label: "vuln scanner", query: "data.srcip:198.51.100.7"}

dynamic_threshold: 20                  # if L10+ (excl. noise) < this, pull in L7-9 and L0-6 movers
report_groups:                         # optional: group + label section rows in the hourly report
  - title: Attacks
    rows: [{key: success, label: "attack success"}, {key: web_attack_ext, label: "web attacks, external"}]
  - title: Auth
    rows: [{key: brute, label: "auth failures"}, {key: ssh_external, label: "external SSH (expect 0)"}]
notes: |
  Free text added to the system prompt: what the clusters are, internal ranges, known noise.

limits:                                # optional; defaults shown
  max_window_min: 60
  max_hits: 20
  max_terms: 25
  max_queries_per_run: 12
  timeout_s: 60
```

These are Lucene `query_string` rules. Escape `/` in values (`data.url:\/login*`). A bare `/.../` is read as a regex.

### Env file

The default path is `~/.config/wazuh-llm-triage/.env`. Override it with `TRIAGE_ENV`. Values already set in the environment win.

```
ANTHROPIC_API_KEY=sk-ant-...
# or: TRIAGE_PROVIDER=glm
#     GLM_API_KEY=...
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_REPORT_CHANNEL=C0123456789
SLACK_ALLOWED_USERS=U0123456789
# optional
TRIAGE_MODEL=
TRIAGE_EFFORT=medium
TRIAGE_REPORT_MINUTE=5
GLM_BASE_URL=https://api.z.ai/api/anthropic
```

## Usage

```bash
python -m triage probe                    # one _count over 60m: checks login + index
python -m triage ask "web attacks last 15 min"
python -m triage report --no-llm          # build the hourly report, print it
python -m triage bot                      # Slack bot + hourly scheduler
```

Flags: `--profile PATH`, `-v` (logs every tool call).

## Providers

- **Claude (default).** Set `ANTHROPIC_API_KEY`.
  - Model: `TRIAGE_MODEL`, default `claude-opus-5-5`.
  - Effort: `TRIAGE_EFFORT`, default `medium`.
  - Uses the server-side refusal fallback. A security question that trips a safety classifier is retried on a fallback model.
- **GLM.** Set `TRIAGE_PROVIDER=glm` and `GLM_API_KEY`.
  - Model: default `glm-4.7`.
  - Endpoint: Z.ai's Anthropic-compatible `https://api.z.ai/api/anthropic`.
  - Uses the same SDK. Claude-only parameters (fallback, effort, caching) are dropped.

Both send alert content to the provider. Check that this is acceptable for your data.

## Tests

```bash
python -m pytest
```

No network. The indexer is faked.

## Limitations

- **Alerts index only.** No archives, raw events, or state/inventory indices.
- **Window:** max 60 minutes per query. No long-range trends.
- **No enrichment:** no GeoIP, ASN or reputation. The bot answers "unknown".
- **LLM mistakes:** the model can misread results or pick the wrong query. Every reply shows its query count; verify before acting.
- **Field mapping:** the attack table assumes nginx-style decoders (`data.url`/`data.requesturi`, `data.id`/`data.code`, `data.srcip`/`data.remote`).

## Status

`triage/` is the active code. The previous Flask/DeepSeek app is in `archive/legacy-flask-app/` (unused).
