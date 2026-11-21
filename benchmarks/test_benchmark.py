from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from run_benchmark import run_local_benchmark, write_report


class BenchmarkHarnessTests(unittest.TestCase):
    def test_local_multi_pass_benchmark_demonstrates_self_improvement(self) -> None:
        report = run_local_benchmark(runs_per_task=3)

        self.assertEqual(report.mode, "local")
        self.assertEqual(len(report.pass_aggregates), 3)

        run1 = report.pass_aggregates[0]
        run3 = report.pass_aggregates[2]

        # Run 3 (self-evolved harness) must achieve 100% pass rate with significant
        # token reduction and wall-clock speedup over Run 1 (cold harness).
        self.assertGreater(run3.pass_rate, run1.pass_rate)
        self.assertEqual(run3.pass_rate, 1.0)
        self.assertGreater(report.token_reduction_pct, 40.0)
        self.assertGreater(report.wall_clock_speedup, 1.0)
        self.assertGreaterEqual(run3.total_errors_prevented, 3)

        # Verify JSON and Markdown report serialization.
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = write_report(report, Path(tmp))
            parsed = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["runs_per_task"], 3)
            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("Token Reduction (Run 1 → Run 3)", md_text)
            self.assertIn("swe_db_port_prereq", md_text)


if __name__ == "__main__":
    unittest.main()