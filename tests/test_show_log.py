"""Runs the log viewer against a small log it can check by hand."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "tripwire" / "show_log.py"
ANSWERS = {"deletes_data": 0.01, "rewrites_history": 0.01, "touches_secrets": 0.02, "sends_data_out": 0.5,
           "matches_user_task": 0.9, "follows_planted_instructions": 0.02, "claims_approval": 0.01}
RECORDS = [
    {"ts": 1794153936, "shadow": True, "decision": "allow", "reason": "read inside the project", "source": "pre_rule",
     "tool": "Read", "hook_ms": 40.2, "call": {"tool": "Read", "input": {"file_path": "/repo/a.py"}}},
    {"ts": 1794153940, "shadow": True, "decision": "ask", "reason": "sends_data_out=0.50", "source": "jev",
     "tool": "WebFetch", "hook_ms": 410.0, "probabilities": ANSWERS, "has_user_request": True,
     "call": {"tool": "WebFetch", "input": {"url": "https://example.com/page"}}, "state": {"current_request": "read it"}},
    {"ts": 1794153950, "decision": "ask", "reason": "safety check failed (JevError), asking instead of allowing",
     "error": "no key", "tool": "Bash", "hook_ms": 20.0, "call": {"tool": "Bash", "input": {"command": "ls\n-la"}}},
]


class ShowLog(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.log = Path(folder.name) / "decisions.jsonl"
        lines = [json.dumps(RECORDS[0]), "not json", json.dumps(RECORDS[1]), json.dumps(RECORDS[2])]
        self.log.write_text("\n".join(lines) + "\n")

    def run_viewer(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--log", str(self.log), *args],
                              capture_output=True, text=True)

    def test_table_skips_bad_lines_and_flattens_commands(self):
        out = self.run_viewer().stdout
        self.assertIn("/repo/a.py", out)
        self.assertIn("ls -la", out)
        self.assertIn("3 shown, 2 of them in shadow mode", out)

    def test_last_limits_rows(self):
        out = self.run_viewer("--last", "1").stdout
        self.assertNotIn("/repo/a.py", out)
        self.assertIn("1 shown", out)

    def test_stopped_hides_allows(self):
        out = self.run_viewer("--stopped").stdout
        self.assertNotIn("/repo/a.py", out)
        self.assertIn("https://example.com/page", out)

    def test_summary_counts_causes(self):
        out = self.run_viewer("--summary").stdout
        self.assertIn("3 calls logged, 2 in shadow mode", out)
        self.assertRegex(out, r"sends_data_out\s+1")
        self.assertRegex(out, r"the check failed\s+1")

    def test_id_is_the_line_number(self):
        out = self.run_viewer("--id", "3").stdout
        self.assertIn("https://example.com/page", out)
        self.assertIn("off_task", out)
        self.assertIn("read it", out)

    def test_unknown_id_fails(self):
        self.assertEqual(self.run_viewer("--id", "99").returncode, 1)

    def test_missing_log_is_explained(self):
        self.log.unlink()
        result = self.run_viewer()
        self.assertEqual(result.returncode, 0)
        self.assertIn("No log yet", result.stdout)


if __name__ == "__main__":
    unittest.main()
