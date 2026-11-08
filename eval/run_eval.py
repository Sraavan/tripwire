#!/usr/bin/env python3
"""Runs the test set through each backend and saves raw probabilities.

Scoring is separate (report.py), so policies can be replayed without new API calls.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from backends import FACTORIES  # noqa: E402
from context import assemble_state  # noqa: E402
from questions import QUESTIONS_VERSION  # noqa: E402

HOOK = HERE.parent / "tripwire" / "hook.py"
CWD = "/workspace/app"
# The home folder the cases are written against. Claude Code passes Read, Write and
# Edit paths already absolute, with ~ expanded, so the cases do the same.
EVAL_HOME = "/home/dev"


def load_cases(path=HERE / "cases.jsonl"):
    with open(path) as handle:
        return [json.loads(line) for line in handle if line.strip()]


def case_state(case):
    """earlier_turns are requests the user made before user_request, oldest first."""
    turns = [(turn["request"], [tuple(call) for call in turn["calls"]]) for turn in case.get("earlier_turns", [])]
    turns.append((case["user_request"], [tuple(call) for call in case["prior_calls"]]))
    return assemble_state(turns, (case["tool"], case["tool_input"]), CWD)


def measure_hook(cases, samples):
    """Wall-clock time of the real hook process, including Python startup."""
    timings = []
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ | {"TRIPWIRE_LOG": str(Path(tmp) / "log.jsonl"), "CLAUDE_PROJECT_DIR": CWD}
        # Bash goes to the model, so this measures the full path rather than a pre-rule.
        bash_cases = [case for case in cases if case["tool"] == "Bash"]
        for index in range(samples):
            case = bash_cases[index % len(bash_cases)]
            event = {"tool_name": case["tool"], "tool_input": case["tool_input"], "cwd": CWD,
                     "session_id": "eval", "transcript_path": None}
            started = time.perf_counter()
            subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event), env=env,
                           capture_output=True, text=True, check=False, timeout=30)
            timings.append(round((time.perf_counter() - started) * 1000, 1))
    return timings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backends", nargs="+", default=list(FACTORIES), choices=list(FACTORIES))
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--limit", type=int, help="only the first N safe and first N dangerous cases")
    parser.add_argument("--hook-samples", type=int, default=30, help="0 skips the end-to-end hook timing")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    cases = load_cases()
    if args.limit:
        safe = [case for case in cases if not case["dangerous"]][: args.limit]
        dangerous = [case for case in cases if case["dangerous"]][: args.limit]
        cases = safe + dangerous

    out = args.out or HERE / "results" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    backends = [FACTORIES[name]() for name in args.backends]
    (out / "meta.json").write_text(json.dumps({
        "backends": args.backends, "repeats": args.repeats, "cases": len(cases),
        "questions_version": QUESTIONS_VERSION,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }, indent=2))

    with open(out / "raw.jsonl", "a") as raw:
        # Rounds rather than one backend at a time, so a slow patch of network or a
        # provider incident doesn't land on a single backend.
        for repeat in range(args.repeats):
            for case in cases:
                state = case_state(case)
                for backend in backends:
                    result = backend(state)
                    raw.write(json.dumps({"backend": backend.name, "case": case["id"],
                                          "repeat": repeat, **result}) + "\n")
                    raw.flush()
                    status = result.get("error") or ("refusal" if result.get("refusal") else "ok")
                    print(f"{repeat} {case['id']} {backend.name}: {result['ms']}ms {status}", flush=True)

    if args.hook_samples and "jev" in args.backends:
        (out / "hook_latency.json").write_text(json.dumps(measure_hook(cases, args.hook_samples)))
    print(f"\nRaw results: {out}\nNext: python3 eval/report.py {out}")


if __name__ == "__main__":
    main()
