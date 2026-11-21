# Engram Empirical Continual-Learning Benchmark (`engram-continual-learning-v1`)

- **Mode:** `local`
- **Pass Rate Gain (Run 1 → Run 3):** `+66.7 pp`
- **Token Reduction (Run 1 → Run 3):** `78.0%`
- **Wall-Clock Speedup (Run 1 → Run 3):** `1.90x`

## Aggregate Pass Comparison

| Pass | Passed / Total | Pass Rate | Total Tokens | Mean Tokens/Task | Total Wall-Clock (ms) | Errors Prevented |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Run 1 | 1/3 | 33.3% | 23,099 | 7,699.7 | 3,374.7 | 0 |
| Run 2 | 3/3 | 100.0% | 5,071 | 1,690.3 | 1,818.2 | 3 |
| Run 3 | 3/3 | 100.0% | 5,071 | 1,690.3 | 1,780.3 | 3 |

## Per-Task Trace Measurements

| Task | Run | Passed | Steps | Errors | Prevented | Total Tokens | Wall-Clock (ms) | Compiled Engram |
| --- | ---: | :---: | ---: | ---: | ---: | ---: | ---: | --- |
| `swe_db_port_prereq` | 1 | FAIL | 3 | 3 | 0 | 8,079 | 2,636.9 | `eng_1A1FFB7F81CF1DE36` (hook) |
| `swe_db_port_prereq` | 2 | PASS | 2 | 0 | 1 | 1,736 | 1,645.4 | — |
| `swe_db_port_prereq` | 3 | PASS | 2 | 0 | 1 | 1,736 | 1,613.0 | — |
| `swe_composite_migration_chain` | 1 | PASS | 4 | 0 | 0 | 9,140 | 560.2 | `eng_1A1FFB80D9B88CEED` (tool) |
| `swe_composite_migration_chain` | 2 | PASS | 1 | 0 | 1 | 1,530 | 171.8 | — |
| `swe_composite_migration_chain` | 3 | PASS | 1 | 0 | 1 | 1,530 | 167.2 | — |
| `swe_circular_async_edit` | 1 | FAIL | 3 | 2 | 0 | 5,880 | 177.5 | `eng_1A1FFB81172E785C8` (rule) |
| `swe_circular_async_edit` | 2 | PASS | 1 | 0 | 1 | 1,805 | 1.0 | — |
| `swe_circular_async_edit` | 3 | PASS | 1 | 0 | 1 | 1,805 | 0.1 | — |
