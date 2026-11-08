#!/usr/bin/env python3
"""Shows Tripwire's decision log in a readable form.

    python3 tripwire/show_log.py               # the last 20 calls
    python3 tripwire/show_log.py --last 50     # the last 50 calls
    python3 tripwire/show_log.py --stopped     # only asks and denies
    python3 tripwire/show_log.py --summary     # totals, and what stops calls
    python3 tripwire/show_log.py --id 42       # everything about call 42

The log itself stays as it is, because a replay under a new policy needs its full detail.
"""

import argparse
import json
import os
import re
import shutil
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from policy import red_flags

DEFAULT_LOG = Path(__file__).resolve().parent / "logs" / "decisions.jsonl"
WHY_WIDTH = 34
MIN_CALL_WIDTH = 30


def load(path):
    """Return [(line_number, record)], skipping lines that aren't valid JSON."""
    entries = []
    with open(path, errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                entries.append((number, record))
    return entries


def clip(text, width):
    return text if len(text) <= width else text[: width - 1] + "…"


def call_text(record):
    tool_input = (record.get("call") or {}).get("input")
    if isinstance(tool_input, dict):
        text = next((tool_input[key] for key in ("command", "file_path", "notebook_path", "url") if tool_input.get(key)),
                    json.dumps(tool_input))
    else:
        text = tool_input or ""
    return " ".join(str(text).split())


def when(record, form="%m-%d %H:%M:%S"):
    return time.strftime(form, time.localtime(record["ts"])) if record.get("ts") else "-"


def milliseconds(record):
    return str(round(record["hook_ms"])) if record.get("hook_ms") is not None else "-"


def is_stopped(record):
    return record.get("decision") in ("ask", "deny")


def show_table(entries):
    columns = shutil.get_terminal_size((140, 24)).columns
    call_width = max(MIN_CALL_WIDTH, columns - 5 - 14 - 5 - 5 - 12 - WHY_WIDTH - 6)
    print(f"{'id':>5} {'time':14} {'said':5} {'ms':>5} {'tool':12} {'call':{call_width}} why")
    for number, record in entries:
        print(f"{number:>5} {when(record):14} {str(record.get('decision')):5} {milliseconds(record):>5} "
              f"{clip(str(record.get('tool')), 12):12} {clip(call_text(record), call_width):{call_width}} "
              f"{clip(str(record.get('reason', '')), WHY_WIDTH)}")
    shadow = sum(1 for _, record in entries if record.get("shadow"))
    print(f"\n{len(entries)} shown, {shadow} of them in shadow mode, where the decision was only logged. "
          "Use --id N for details on one call.")


def stop_cause(record):
    """What made the hook stop a call, as a short label."""
    if record.get("error"):
        return "the check failed"
    if record.get("source") == "pre_rule":
        return f"pre-rule: {record.get('reason')}"
    match = re.match(r"(\w+)=", str(record.get("reason", "")))
    return match.group(1) if match else str(record.get("reason"))


def show_summary(entries):
    records = [record for _, record in entries]
    total = len(records)
    shadow = sum(1 for record in records if record.get("shadow"))
    print(f"{total} calls logged, {shadow} in shadow mode (only logged, no effect)\n")
    print("Decisions")
    for decision, count in Counter(str(record.get("decision")) for record in records).most_common():
        print(f"  {decision:8} {count:>5}  {count / total:.0%}")
    decided = Counter("the check failed" if record.get("error") else str(record.get("source", "unknown"))
                      for record in records)
    print("\nDecided by")
    for source, count in decided.most_common():
        print(f"  {source:18} {count:>5}")
    times = [record["hook_ms"] for record in records if record.get("hook_ms") is not None]
    if times:
        print(f"\nHook time: {round(statistics.median(times))} ms typical, {round(max(times))} ms slowest")
    causes = Counter(stop_cause(record) for record in records if is_stopped(record))
    if causes:
        print("\nWhat stopped calls")
        for cause, count in causes.most_common():
            print(f"  {clip(cause, 60):60} {count:>5}")
    print("\nDecisions are shown as logged, under the policy in use at the time.")


def show_one(number, record):
    print(f"Call {number}, {when(record, '%Y-%m-%d %H:%M:%S')}")
    print(f"Decision: {record.get('decision')}{' (shadow mode, only logged)' if record.get('shadow') else ''}")
    print(f"Reason:   {record.get('reason')}")
    print(f"Source:   {record.get('source', 'unknown')}, {milliseconds(record)} ms")
    if record.get("error"):
        print(f"Error:    {record['error']}")
    print(f"\nTool: {record.get('tool')}")
    print(json.dumps((record.get("call") or {}).get("input"), indent=2))
    probabilities = record.get("probabilities")
    if probabilities:
        print("\nJev's answers")
        for name, value in sorted(probabilities.items(), key=lambda item: -item[1]):
            print(f"  {name:32} {value:.2f}")
        print("\nRed flags")
        flags = red_flags(probabilities, record.get("has_user_request", True))
        for name, value in sorted(flags.items(), key=lambda item: -item[1]):
            print(f"  {name:32} {value:.2f}")
    if record.get("state"):
        print("\nWhat Jev was sent")
        print(json.dumps(record["state"], indent=2))


def main():
    parser = argparse.ArgumentParser(description="Shows Tripwire's decision log in a readable form.")
    parser.add_argument("--last", type=int, default=20, metavar="N", help="how many calls to show (default 20)")
    parser.add_argument("--stopped", action="store_true", help="only calls that got ask or deny")
    parser.add_argument("--summary", action="store_true", help="totals, and what stops calls")
    parser.add_argument("--id", type=int, metavar="N", help="everything about one call")
    parser.add_argument("--log", type=Path, help="log file (default: TRIPWIRE_LOG, else tripwire/logs/decisions.jsonl)")
    args = parser.parse_args()

    path = args.log or Path(os.environ.get("TRIPWIRE_LOG") or DEFAULT_LOG)
    if not path.exists():
        print(f"No log yet at {path}. Tripwire writes one once the hook has run.")
        return 0
    entries = load(path)
    if not entries:
        print(f"The log at {path} has no entries.")
        return 0

    if args.id is not None:
        match = next((record for number, record in entries if number == args.id), None)
        if match is None:
            print(f"No call with id {args.id}.", file=sys.stderr)
            return 1
        show_one(args.id, match)
    elif args.summary:
        show_summary(entries)
    else:
        if args.stopped:
            entries = [entry for entry in entries if is_stopped(entry[1])]
        if not entries:
            print("No calls match.")
            return 0
        show_table(entries[-max(args.last, 1):])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # The reader closed early, as `| head` does. Stop quietly.
        sys.stderr.close()
        sys.exit(0)
