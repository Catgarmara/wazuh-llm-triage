"""CLI.

  python -m triage probe                 one size:0 _count over 1h (connectivity check)
  python -m triage ask "question"        one chat turn in the terminal
  python -m triage report [--no-llm]     build the hourly report, print it (no Slack)
  python -m triage bot                   run the Slack bot + hourly scheduler
"""
import argparse
import logging
import os

from .config import load_env_file, load_profile


def main():
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("cmd", choices=["probe", "ask", "report", "bot"])
    ap.add_argument("text", nargs="?")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--profile")
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    if a.cmd == "ask" and not a.text:
        ap.error("ask needs a question")
    logging.basicConfig(level=logging.INFO if a.v else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    load_env_file(os.environ.get("TRIAGE_ENV", "~/.config/wazuh-llm-triage/.env"))
    p = load_profile(a.profile)

    from .wazuh import DashboardClient, bool_filter
    if a.cmd == "probe":
        c = DashboardClient(p)
        body = {"size": 0, "track_total_hits": True, "query": bool_filter(p, "*", 60)}
        d = c.indexer(f"{p.index}/_search", body)
        print(f"ok: {d['hits']['total']['value']} alerts in last 60m (base filter applied), took {d.get('took')} ms")
    elif a.cmd == "ask":
        from . import llm
        from .attacks import to_text
        reply, used, tables = llm.ask(a.text, [], DashboardClient(p), p)
        print(reply)
        for t in tables:
            print("\n" + to_text(t))
        print(f"({used} queries)")
    elif a.cmd == "report":
        from . import llm, report
        fn = None if a.no_llm else (lambda j: llm.summarize(j, p))
        from .attacks import to_text
        text, tables, r = report.run(DashboardClient(p), p, fn)
        print(text)
        for t in tables:
            print("\n" + to_text(t))
        print(f"({r['queries_used']} indexer queries)")
    elif a.cmd == "bot":
        from . import slack_app
        slack_app.main(p)


if __name__ == "__main__":
    main()
