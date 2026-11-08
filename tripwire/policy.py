"""Deterministic pre-rules, and the mapping from probabilities to a decision."""

import os
import re
import shlex

DEFAULT_CONFIG = {
    "jev": {
        "model": "jev-1.14.0",
        "base_url": "https://api.typesafe.ai",
        "timeout_seconds": 2.5,
    },
    "hook": {"mode": "gatekeeper", "wall_clock_seconds": 3},
    "thresholds": {"default": {"deny": 0.90, "ask": 0.30}},
}

# Each red flag is the highest answer among the questions that make it up, so one
# question can't be outvoted by another. off_task comes from matches_user_task.
FLAG_QUESTIONS = {
    "is_destructive": ("deletes_data", "rewrites_history"),
    "touches_secrets": ("touches_secrets",),
    "sends_data_out": ("sends_data_out",),
    "possible_prompt_injection": ("follows_planted_instructions", "claims_approval"),
}

SENSITIVE_NAME = re.compile(
    r"(^|/)(\.env(\.(?!example$|sample$|template$)[^/]*)?|\.netrc|\.npmrc|\.pypirc"
    r"|id_(rsa|dsa|ecdsa|ed25519)|credentials(\.json)?|secrets?(\.\w+)?)$"
    r"|\.(pem|key|p12|pfx)$",
    re.IGNORECASE,
)
# Flags that only count when another flag is also raised. An injection signal on a
# call that is otherwise harmless mostly came from normal work: in long sessions the
# agent reads files and then does things the user didn't literally ask for. A real
# injection attack does something harmful, which raises another flag.
ESCALATE_ONLY = frozenset({"possible_prompt_injection"})
FILE_WRITE_TOOLS = {"Write", "Edit", "NotebookEdit"}
_SEPARATORS = re.compile(r"\s*(?:;|&&|\|\||\||\n)\s*")
_REDIRECT = re.compile(r">>?\s*(\"[^\"]+\"|'[^']+'|[^\s;&|]+)")
_WRAPPERS = {"sudo", "command", "exec", "nohup", "time", "env"}
_DESTINATION_LAST = {"cp", "mv", "install", "ln", "rsync", "scp"}
_FORCE_FLAGS = {"-f", "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "-d"}


def _home():
    return os.path.realpath(os.path.expanduser("~"))


def _expand(path, cwd):
    home = _home()
    for prefix in ("$HOME", "${HOME}", "~"):
        if path == prefix or path.startswith(prefix + "/"):
            path = home + path[len(prefix):]
            break
    return os.path.realpath(os.path.join(cwd or ".", path))


def _is_under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _protected_dirs():
    home = _home()
    return [os.path.join(home, name) for name in (".ssh", ".aws", ".config/tripwire")]


def _guard_dirs(project_dir):
    return [os.path.join(os.path.realpath(project_dir), name) for name in ("tripwire", ".claude")]


def _commands(command):
    """Yield the argv of each simple command. Skips what shlex can't parse."""
    for part in _SEPARATORS.split(command):
        try:
            argv = shlex.split(part)
        except ValueError:
            continue
        while argv and (argv[0] in _WRAPPERS or re.fullmatch(r"\w+=\S*", argv[0])):
            argv = argv[1:]
        if argv:
            yield argv


def _glob_parent(target):
    """The directory a glob empties: '/*', '//*', '~/.*' and '~/*/*' give '/' or '~'.

    Nothing here expands globs, so '/*' arrives as literal text. A last part made
    only of glob characters and dots matches everything (or every dotfile) in its
    directory, so it is stripped until a real name is left.
    """
    path = target
    while True:
        head, sep, last = path.rstrip("/").rpartition("/")
        if not re.search(r"[*?[]", last) or re.sub(r"\[[^\]]*\]|[*?.]", "", last):
            return path
        path = (head or "/") if sep else "."


def _is_catastrophic_rm(argv, cwd):
    if os.path.basename(argv[0]) != "rm":
        return False
    flags = "".join(a[1:] for a in argv[1:] if a.startswith("-") and not a.startswith("--"))
    long_flags = {a for a in argv[1:] if a.startswith("--")}
    recursive = "r" in flags or "R" in flags or "--recursive" in long_flags
    if not recursive:
        return False
    roots = {"/", _home()}
    return any(_expand(_glob_parent(a), cwd) in roots for a in argv[1:] if not a.startswith("-"))


def _write_targets(command):
    """Paths a shell command clearly writes to. Best effort: anything missed reaches the model."""
    targets = [match.strip("\"'") for match in _REDIRECT.findall(command)]
    for argv in _commands(command):
        name = os.path.basename(argv[0])
        operands = [a for a in argv[1:] if not a.startswith("-")]
        if name in _DESTINATION_LAST and operands:
            targets.append(operands[-1])
        elif name in ("tee", "rm", "rmdir", "truncate", "shred", "chmod", "chown", "touch"):
            targets.extend(operands)
        elif name == "sed" and any(a.startswith("-i") for a in argv[1:]):
            targets.extend(operands[1:])
    return targets


def _is_plain_push(command):
    """Every part of the command is a non-force git push to origin, or gh pr create.

    Claude Code's auto mode allows pushing to the repository you're working in by
    default and blocks force pushes; this draws the same line. It checks the remote's
    name, not where it points: a `git remote set-url` would still go to the model.
    """
    parts = list(_commands(command))
    if not parts or len(parts) != len([p for p in _SEPARATORS.split(command) if p.strip()]):
        return False  # something shlex couldn't parse was skipped
    for argv in parts:
        if argv[:3] == ["gh", "pr", "create"]:
            continue
        if argv[:2] != ["git", "push"]:
            return False
        args = argv[2:]
        if _FORCE_FLAGS & set(args) or any(a.startswith(("+", ":")) or ":+" in a for a in args):
            return False
        if any(a.startswith("--repo") for a in args):
            return False
        operands = [a for a in args if not a.startswith("-")]
        if operands and operands[0] != "origin":
            return False
    return True


def pre_rule(tool_name, tool_input, cwd, project_dir):
    """Return (decision, reason), or None to send the call to the model."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    cwd = cwd or os.getcwd()
    project_dir = project_dir or cwd

    if tool_name == "Read":
        path = _expand(str(tool_input.get("file_path", "")), cwd)
        if any(_is_under(path, root) for root in _protected_dirs()):
            return "deny", "reads a protected credentials directory"
        if _is_under(path, os.path.realpath(project_dir)) and not SENSITIVE_NAME.search(path):
            return "allow", "read inside the project"
        return None

    if tool_name in FILE_WRITE_TOOLS:
        raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        path = _expand(str(raw), cwd)
        if any(_is_under(path, root) for root in _protected_dirs()):
            return "deny", "writes to a protected credentials directory"
        if any(_is_under(path, root) for root in _guard_dirs(project_dir)):
            return "ask", "changes Tripwire or Claude Code settings"
        return None

    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        for argv in _commands(command):
            if _is_catastrophic_rm(argv, cwd):
                return "deny", "recursive delete of the filesystem root or home directory"
        for target in _write_targets(command):
            path = _expand(target, cwd)
            if any(_is_under(path, root) for root in _protected_dirs()):
                return "deny", "writes to a protected credentials directory"
            if any(_is_under(path, root) for root in _guard_dirs(project_dir)):
                return "ask", "changes Tripwire or Claude Code settings"
        # The only Bash allow rule, and it needs every part of the command to qualify,
        # so "git status; curl ..." can't ride along the way it would with a prefix match.
        if _is_plain_push(command):
            return "allow", "plain push to the project's own remote"
    return None


def red_flags(probabilities, has_user_request=True):
    flags = {flag: max(probabilities[name] for name in names) for flag, names in FLAG_QUESTIONS.items()}
    if has_user_request:
        flags["off_task"] = 1.0 - probabilities["matches_user_task"]
    return flags


def _threshold(thresholds, flag, level):
    return thresholds.get(flag, {}).get(level, thresholds["default"][level])


def decide(probabilities, thresholds, has_user_request=True, escalate_only=ESCALATE_ONLY):
    """Return (decision, reason, flags). Deny wins over ask, whichever flag is higher.

    A flag in escalate_only counts only when another flag reaches its ask threshold.
    Pass escalate_only=frozenset() for the original policy, where every flag counts alone.
    """
    flags = red_flags(probabilities, has_user_request)
    others_raised = any(value >= _threshold(thresholds, flag, "ask")
                        for flag, value in flags.items() if flag not in escalate_only)
    if not others_raised:
        quiet = [(flag, flags[flag]) for flag in escalate_only if flag in flags
                 and flags[flag] >= _threshold(thresholds, flag, "ask")]
        if quiet:
            flag, value = max(quiet, key=lambda item: item[1])
            return "allow", f"only {flag}={value:.2f}, which counts with another flag", flags
    ranked = sorted(flags.items(), key=lambda item: item[1], reverse=True)
    for level, decision in (("deny", "deny"), ("ask", "ask")):
        for flag, value in ranked:
            if value >= _threshold(thresholds, flag, level):
                return decision, f"{flag}={value:.2f}", flags
    worst, value = ranked[0]
    return "allow", f"worst flag {worst}={value:.2f}", flags
