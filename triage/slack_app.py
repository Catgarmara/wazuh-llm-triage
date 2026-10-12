"""Slack bot (Bolt, Socket Mode): @mention or DM to ask; hourly report to one channel.

Env: SLACK_BOT_TOKEN (xoxb-), SLACK_APP_TOKEN (xapp-), SLACK_REPORT_CHANNEL (channel id),
SLACK_ALLOWED_USERS (comma-separated user ids; empty = anyone in the workspace).
"""
import logging
import os
import re
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from slack_sdk.errors import SlackApiError

from . import attacks, llm, report, store
from .wazuh import DashboardClient

log = logging.getLogger(__name__)
MENTION = re.compile(r"<@[A-Z0-9]+>\s*")


def _sections(text):
    """mrkdwn section blocks; Slack caps a section's text at 3000 chars."""
    return [{"type": "section", "text": {"type": "mrkdwn", "text": text[i:i + 2900]}}
            for i in range(0, len(text or " "), 2900)] if text else []


def post(client, channel, text, tables=(), footer=None, thread_ts=None):
    """text + native table blocks; falls back to code-block tables if Slack rejects the table block."""
    blocks = _sections(text)
    for rows in tables:
        if rows:
            blocks.append(attacks.to_slack_table(rows))
            fn = attacks.footnote(rows)
            if fn:
                blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": fn}]})
    if footer:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": footer}]})
    kw = dict(channel=channel, text=(text or "")[:3000], thread_ts=thread_ts)
    try:
        return client.chat_postMessage(blocks=blocks, **kw)
    except SlackApiError as e:
        log.warning("table post rejected (%s); falling back to text", e.response.get("error"))
        alt = (text or "") + "".join(f"\n```{attacks.to_text(r)}```" for r in tables if r)
        return client.chat_postMessage(blocks=_sections(alt) + blocks[-1:] if footer else _sections(alt), **kw)


def build_app(profile):
    app = App(token=os.environ["SLACK_BOT_TOKEN"])
    wazuh = DashboardClient(profile)
    allowed = {u for u in os.environ.get("SLACK_ALLOWED_USERS", "").split(",") if u}
    turn_lock = threading.Lock()   # one chat turn at a time (indexer is single-flight anyway)

    def handle(event, say):
        user, text = event.get("user"), MENTION.sub("", event.get("text", "")).strip()
        thread = event.get("thread_ts") or event["ts"]
        if allowed and user not in allowed:
            say(text="Not authorised for this bot.", thread_ts=thread)
            return
        if not text:
            return
        key = f"{event['channel']}:{thread}"
        with turn_lock:
            history = store.load_session(key)
            try:
                reply, used, tables = llm.ask(text, history, wazuh, profile)
                store.save_session(key, history)   # only on success; a failed turn would poison the thread
            except Exception as e:
                log.exception("ask failed")
                reply, used, tables = f"Error: {e}", 0, []
        post(app.client, event["channel"], reply, tables, f"{used} queries", thread)

    @app.event("app_mention")
    def on_mention(event, say):
        handle(event, say)

    @app.event("message")
    def on_dm(event, say):
        if event.get("channel_type") == "im" and not event.get("bot_id") and not event.get("subtype"):
            handle(event, say)

    def hourly():
        tables = []
        try:
            text, tables, _ = report.run(wazuh, profile, lambda j: llm.summarize(j, profile))
        except Exception as e:
            log.exception("report failed")
            text = f"Hourly report failed: {e}"
        post(app.client, os.environ["SLACK_REPORT_CHANNEL"], text, tables)

    return app, hourly


def main(profile):
    app, hourly = build_app(profile)
    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(hourly, "cron", minute=int(os.environ.get("TRIAGE_REPORT_MINUTE", "5")),
                  max_instances=1, coalesce=True)
    sched.start()
    SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"]).start()
