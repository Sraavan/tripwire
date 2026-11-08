# Eval results

**Open [`20261108-093233-all/report.md`](20261108-093233-all/report.md).** It's the current comparison of Jev and the three Claude models, and it starts with how to read it.

| Run | What it is |
|---|---|
| `20261108-093233-all` | Current: Jev, Haiku 5.5, Haiku 4.5 and Sonnet 5 on all 66 cases |
| `20261107-200302-jev` | Earlier, Jev only, 66 cases |
| `20261107-190512-jev` | Earlier, Jev only, 60 cases |

The two earlier runs are kept as a record. Their reports use the older layout and were written before later policy changes, so don't compare them directly with the current one.

Each folder also has `meta.json` (run settings) and `hook_latency.json` (timings of the real hook process). The raw per-call answers (`raw.jsonl`) stay on the machine that ran the eval and aren't in the repo.
