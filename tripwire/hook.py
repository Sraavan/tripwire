#!/usr/bin/env python3
"""Tripwire: a Claude Code PreToolUse hook that gates tool calls with Jev.

Claude Code lets a call through when a hook crashes, so every failure in here
has to end in an explicit "ask".
"""

import json
import os
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
PASS_THROUGH = None


def load_config():
    from policy import DEFAULT_CONFIG

    config = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
    with open(HERE / "config.toml", "rb") as handle:
        import tomllib

        overrides = tomllib.load(handle)
    for section, values in overrides.items():
        config.setdefault(section, {}).update(values)
    return config


def emit(decision, reason, out):
    if decision is PASS_THROUGH:
        return
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": f"Tripwire: {reason}",
            }
        },
        out,
    )
    out.flush()


def log(record):
    """Logging must never change a decision."""
    try:
        path = Path(os.environ.get("TRIPWIRE_LOG") or HERE / "logs" / "decisions.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
    except Exception:
        pass


def _on_alarm(signum, frame):
    raise TimeoutError("wall-clock limit reached")


def evaluate(event, config, record):
    """Return (decision, reason), filling in the log record along the way."""
    from policy import decide, pre_rule

    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd")

    ruled = pre_rule(tool_name, tool_input, event.get("cwd"), project_dir)
    if ruled:
        record["source"] = "pre_rule"
        return ruled

    # Imported this late so that pre-rule decisions skip the ssl import.
    import jev
    from context import build_state
    from questions import QUESTIONS, QUESTIONS_VERSION

    state, has_user_request = build_state(event)
    # The exact state sent, already redacted, so any decision can be rerun.
    record.update(has_user_request=has_user_request, state=state, questions_version=QUESTIONS_VERSION)
    started = time.perf_counter()
    probabilities, meta = jev.ask(
        state,
        QUESTIONS,
        model=config["jev"]["model"],
        base_url=os.environ.get("TRIPWIRE_JEV_BASE_URL") or config["jev"]["base_url"],
        timeout=config["jev"]["timeout_seconds"],
    )
    record.update(source="jev", jev_ms=round((time.perf_counter() - started) * 1000, 1),
                  probabilities=probabilities, **meta)
    decision, reason, _ = decide(probabilities, config["thresholds"], has_user_request)
    if decision == "ask" and config["hook"]["mode"] == "cascade":
        record["passed_through"] = True
        return PASS_THROUGH, reason
    return decision, reason


def main():
    # Claude Code reads stdout as one JSON reply, and text in front of it would lose
    # the decision without an error. So only the reply goes to the real stdout, and
    # anything else that prints, here or in a library, lands on stderr.
    out, sys.stdout = sys.stdout, sys.stderr
    started = time.perf_counter()
    record = {"ts": time.time()}
    decision, reason = "ask", "safety check did not complete"
    try:
        # Set before anything can block. Replaced below once the config is read.
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, 3)
        config = load_config()
        signal.setitimer(signal.ITIMER_REAL, config["hook"]["wall_clock_seconds"])

        event = json.load(sys.stdin)
        record.update(session_id=event.get("session_id"), tool=event.get("tool_name"))
        from context import sanitize_call

        record["call"] = sanitize_call(event.get("tool_name"), event.get("tool_input") or {})
        decision, reason = evaluate(event, config, record)
    except BaseException as error:  # includes the alarm, and SystemExit from a bad import
        decision = "ask"
        reason = f"safety check failed ({type(error).__name__}), asking instead of allowing"
        record["error"] = str(error)[:300]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

    shadow = bool(os.environ.get("TRIPWIRE_SHADOW"))
    record.update(decision=decision, reason=reason, shadow=shadow,
                  hook_ms=round((time.perf_counter() - started) * 1000, 1))
    log(record)
    if not shadow:
        emit(decision, reason, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
