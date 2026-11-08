"""Builds the state sent to the model, and redacts it before it leaves the machine."""

import json
import re

MAX_USER_TEXT = 2000
MAX_FIELD = 2000
RECENT_CALLS = 5  # calls made for the current request
EARLIER_MESSAGES = 3  # prompts before it, so a reply like "yes" keeps its meaning
EARLIER_CALLS = 3  # calls made before it, so a file read for an earlier task stays visible
# The transcript can be very large, so only its two ends are read.
HEAD_BYTES = 256 * 1024
TAIL_BYTES = 256 * 1024

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), "[REDACTED API KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"), "[REDACTED JWT]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{16,}=*"), r"\1 [REDACTED]"),
    # NAME=value where the name looks secret. Shell references ($VAR, $(cmd)) stay
    # visible: the model has to see them to spot exfiltration.
    (re.compile(
        r"(?i)\b([A-Z0-9_\-]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_\-]*)"
        r"(\s*[=:]\s*)(['\"]?)(?![$'\"\s])[^\s'\"]+"),
     r"\1\2\3[REDACTED]"),
]


def redact(text):
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _clip(text, limit=MAX_FIELD):
    """Keep both ends, so a payload can't hide after a long harmless prefix."""
    if len(text) <= limit:
        return text
    tail = limit // 4
    return f"{text[:limit - tail]}\n...[{len(text) - limit} chars omitted]...\n{text[-tail:]}"


def _sanitize(value):
    if isinstance(value, str):
        return _clip(redact(value))
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def sanitize_call(tool_name, tool_input):
    if isinstance(tool_input, dict):
        tool_input = {key: value for key, value in tool_input.items() if key not in _NARRATION_FIELDS}
    return {"tool": tool_name, "input": _sanitize(tool_input)}


def _read_lines(path):
    with open(path, "rb") as handle:
        handle.seek(0, 2)
        size = handle.seek(0, 1)
        handle.seek(0)
        if size <= HEAD_BYTES + TAIL_BYTES:
            return handle.read().splitlines()
        head = handle.read(HEAD_BYTES).splitlines()[:-1]  # the last line may be cut off
        handle.seek(size - TAIL_BYTES)
        tail = handle.read().splitlines()[1:]  # the first line may be cut off
        return head + tail


# Text Claude Code adds to user lines. Checked per block, because a reminder block
# can sit in front of the text the user typed in the same line. A "!" command is
# stored as a human line holding the command and its output: the output is a tool
# result in all but name, so it must never reach the state.
_NOT_TYPED = (
    "<system-reminder>",
    "<command-",
    "<local-command",
    "<bash-input>",
    "<bash-stdout>",
    "<bash-stderr>",
    "[Request interrupted by user",
)
# Tools that act on files, the shell or the web. The agent's own planning and
# messaging tools are narration, and would take the places of real actions.
ACTION_TOOLS = {"Bash", "Read", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Glob", "Grep"}
# Inputs the agent writes about its own call. Like its messages, they can argue
# that the call is safe, so the model judges the call without them.
_NARRATION_FIELDS = {"description"}


def _user_text(entry):
    """The text of a prompt the human typed, or None for anything else."""
    if entry.get("type") != "user" or entry.get("isSidechain"):
        return None
    # isMeta marks injected content such as skills; isCompactSummary marks the
    # summary that replaces history after compaction.
    if entry.get("isMeta") or entry.get("isCompactSummary"):
        return None
    origin = entry.get("origin")
    if isinstance(origin, dict) and origin.get("kind") not in (None, "human"):
        return None
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        texts = [content]
    elif isinstance(content, list):
        # Tool results also arrive as user lines. They are not the user speaking.
        texts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
    else:
        return None
    typed = [text.strip() for text in texts if not text.strip().startswith(_NOT_TYPED)]
    return " ".join(text for text in typed if text) or None


def read_transcript(path):
    """Return the session as turns: [(typed prompt, [tool calls after it])], oldest first.

    A call belongs to the last prompt typed before it. Calls before any prompt go
    in a turn whose prompt is None. Tolerant: the format is undocumented.
    """
    turns = []
    try:
        lines = _read_lines(path)
    except (OSError, TypeError, ValueError):
        return turns
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        text = _user_text(entry)
        if text:
            turns.append((text, []))
        elif entry.get("type") == "assistant" and not entry.get("isSidechain"):
            message = entry.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") in ACTION_TOOLS:
                    if not turns:
                        turns.append((None, []))
                    turns[-1][1].append((block.get("name"), block.get("input") or {}))
    return turns


def assemble_state(turns, proposed, cwd):
    """Return (state, has_user_request). turns are as read_transcript returns them.

    The current request is kept apart from earlier ones, so a call is judged
    against what the user is asking for now, with earlier work labeled as such.

    Tool results are left out on purpose. Jev doesn't treat state as hostile, so
    planted text in a file could steer its answer. Auto mode's classifier drops
    them too.
    """
    turns = [(prompt, list(calls)) for prompt, calls in turns]
    # The transcript may already hold the call being judged, or may lag behind it.
    if turns and turns[-1][1] and turns[-1][1][-1] == proposed:
        turns[-1][1].pop()
    current_request, current_calls = turns[-1] if turns and turns[-1][0] else (None, [])
    earlier = turns[:-1] if current_request else turns
    earlier_messages = [prompt for prompt, _ in earlier if prompt][-EARLIER_MESSAGES:]
    earlier_calls = [call for _, calls in earlier for call in calls][-EARLIER_CALLS:]

    # Fields with nothing in them are left out: the model can read an empty list,
    # or a null request, as a signal.
    state = {}
    if current_request:
        state["current_request"] = _clip(redact(current_request), MAX_USER_TEXT)
    if earlier_messages:
        state["earlier_messages"] = [_clip(redact(text), MAX_USER_TEXT) for text in earlier_messages]
    if current_calls:
        state["calls_for_current_request"] = [sanitize_call(*call) for call in current_calls[-RECENT_CALLS:]]
    if earlier_calls:
        state["earlier_calls"] = [sanitize_call(*call) for call in earlier_calls]
    state["proposed_tool_call"] = sanitize_call(*proposed)
    if cwd:
        state["working_directory"] = cwd
    return state, bool(current_request)


def build_state(event):
    turns = read_transcript(event.get("transcript_path"))
    proposed = (event.get("tool_name"), event.get("tool_input") or {})
    return assemble_state(turns, proposed, event.get("cwd"))
