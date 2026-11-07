"""Minimal Jev client. Stdlib only, because the hook starts a new process per call."""

import json
import os
import urllib.request
from pathlib import Path

KEY_FILE = Path.home() / ".config" / "tripwire" / "env"


class JevError(Exception):
    pass


def load_api_key():
    key = os.environ.get("TYPESAFE_API_KEY")
    if key:
        return key.strip()
    try:
        for line in KEY_FILE.read_text().splitlines():
            name, sep, value = line.strip().removeprefix("export ").partition("=")
            if sep and name.strip() == "TYPESAFE_API_KEY":
                return value.strip().strip("\"'")
    except OSError:
        pass
    raise JevError(f"no API key: set TYPESAFE_API_KEY or create {KEY_FILE}")


def build_request(state, questions, *, model, base_url, api_key=None):
    return urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/systemone",
        data=json.dumps({"model": model, "state": state, "questions": questions}).encode(),
        headers={
            "Authorization": f"Bearer {api_key or load_api_key()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )


def ask(state, questions, *, model, base_url, timeout, api_key=None):
    """Return ({question: P(yes)}, response metadata). Raises JevError on any failure."""
    request = build_request(state, questions, model=model, base_url=base_url, api_key=api_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.load(response)
    except Exception as error:
        # Only the type: an HTTPError's text could echo the request.
        raise JevError(f"Jev request failed: {type(error).__name__}") from error
    return parse(body, questions)


def parse(body, questions):
    """Return ({question: P(yes)}, response metadata) from a decoded response body."""
    try:
        answers = body["answers"]
        probabilities = {name: float(answers[name]["noul"]) for name in questions}
    except Exception as error:
        raise JevError(f"unexpected Jev response: {type(error).__name__}") from error
    for name, value in probabilities.items():
        if not 0.0 <= value <= 1.0:  # also catches NaN
            raise JevError(f"Jev returned an out-of-range probability for {name}")
    return probabilities, {
        "model": body.get("model"),
        "input_tokens": (body.get("usage") or {}).get("input_tokens"),
    }
