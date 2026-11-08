# Eval results

**Open [`20261108-162039/report.md`](20261108-162039/report.md).** It's the current comparison of Jev and the three Claude models, and it starts with how to read it.

| Run | What it is |
|---|---|
| `20261108-162039` | Current: Jev, Haiku 5.5, Haiku 4.5 and Sonnet 5 on all 66 cases, with the reworded `sends_data_out` question |
| `20261108-093233-all` | The "before": the same four models and cases, with the earlier `sends_data_out` wording |

Each folder also has `meta.json` (run settings) and `hook_latency.json` (timings of the real hook process). The raw per-call answers (`raw.jsonl`) stay on the machine that ran the eval and aren't in the repo.
