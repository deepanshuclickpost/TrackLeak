"""
TrackLeak Integration Tests
============================

Runs the leak patterns with LD_PRELOAD and asserts expected retention values.

Requirements:
  - trackleak.so must be built first: make build
  - Python 3.11+ with --enable-shared

Run:
  pytest test_trackleak.py -v

Or directly:
  python3 test_trackleak.py
"""

import os
import subprocess
import time
import json
import re
import tempfile
import pytest

TRACKLEAK_SO = os.path.join(os.path.dirname(__file__), "trackleak.so")
TEST_SCRIPT = os.path.join(os.path.dirname(__file__), "test_leaks.py")


def skip_if_no_so():
    return pytest.mark.skipif(
        not os.path.exists(TRACKLEAK_SO),
        reason="trackleak.so not built — run: make build"
    )


def run_with_trackleak(script, dump_interval=5, min_size=100, top_n=20,
                        extra_env=None, timeout=60) -> list[dict]:
    """
    Run a Python script under LD_PRELOAD and parse the profiler output.
    Returns a list of parsed stat rows from the dump.
    """
    with tempfile.TemporaryDirectory() as log_dir:
        env = os.environ.copy()
        env["LD_PRELOAD"] = TRACKLEAK_SO
        env["TRACKLEAK_LOG_DIR"] = log_dir
        env["TRACKLEAK_DUMP_INTERVAL"] = str(dump_interval)
        env["TRACKLEAK_MIN_SIZE"] = str(min_size)
        env["TRACKLEAK_STARTUP_DELAY"] = "0"
        env["TRACKLEAK_SAMPLE_RATE"] = "1"   # Track every allocation in tests
        env["TRACKLEAK_TOP_N"] = str(top_n)
        if extra_env:
            env.update(extra_env)

        result = subprocess.run(
            ["python3.11", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        log_path = os.path.join(log_dir, "profiler.json")
        if not os.path.exists(log_path):
            return []

        with open(log_path) as f:
            content = f.read()

        return _parse_dump_output(content)


def _parse_dump_output(content: str) -> list[dict]:
    """
    Parse the tabular profiler.json output into a list of dicts.
    Each dict has: function, count, total_mb, samples, sample_mb, line,
                   freed_mb, retention_pct, file
    """
    rows = []
    # Match data rows (not header/separator/summary lines)
    pattern = re.compile(
        r"^(\S+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+([\d.]+)\(([\d.]+)%\)\s+\|\s+(\S+)",
        re.MULTILINE
    )
    for m in pattern.finditer(content):
        rows.append({
            "function":      m.group(1),
            "count":         int(m.group(2)),
            "total_mb":      float(m.group(3)),
            "samples":       int(m.group(4)),
            "sample_mb":     float(m.group(5)),
            "line":          int(m.group(6)),
            "freed_mb":      float(m.group(7)),
            "retention_pct": float(m.group(8)),
            "file":          m.group(9),
        })
    return rows


def find_function(rows: list[dict], name: str) -> dict | None:
    """Find a stat row by function name."""
    for row in rows:
        if row["function"] == name:
            return row
    return None


# ---------------------------------------------------------------------------
# Inline mini-scripts (no LD_PRELOAD dependency) for fast unit tests
# ---------------------------------------------------------------------------

class TestDumpParsing:
    """Unit tests for the output parser — no .so needed."""

    SAMPLE_OUTPUT = """
FUNCTION                          COUNT     TOTAL_MB  SAMPLES    SAMPLE_MB     LINE     FREED_MB(RET%) | FILE
------------------------------   --------  ---------- --------  ------------ --------  ---------------- | -----
leaky_cache                       10000         5.29      200         0.10       38      0.00(100.0%)   | test_leaks.py
healthy_allocation                 5000         2.90      100         0.06       53      0.06(0.0%)     | test_leaks.py
string_format_leak                 5000        19.53      100         0.39       72      0.39(0.0%)     | test_leaks.py
--- dump at 1771567369 (3 functions, hash 300/200000) ---
"""

    def test_parses_correct_number_of_rows(self):
        rows = _parse_dump_output(self.SAMPLE_OUTPUT)
        assert len(rows) == 3

    def test_leaky_cache_retention(self):
        rows = _parse_dump_output(self.SAMPLE_OUTPUT)
        row = find_function(rows, "leaky_cache")
        assert row is not None
        assert row["retention_pct"] == 100.0

    def test_healthy_allocation_retention(self):
        rows = _parse_dump_output(self.SAMPLE_OUTPUT)
        row = find_function(rows, "healthy_allocation")
        assert row is not None
        assert row["retention_pct"] == 0.0

    def test_row_fields_populated(self):
        rows = _parse_dump_output(self.SAMPLE_OUTPUT)
        row = find_function(rows, "leaky_cache")
        assert row["count"] == 10000
        assert row["total_mb"] == 5.29
        assert row["line"] == 38
        assert row["file"] == "test_leaks.py"


# ---------------------------------------------------------------------------
# Integration tests — require trackleak.so
# ---------------------------------------------------------------------------

@skip_if_no_so()
class TestLeakPatterns:
    """Integration tests — run test_leaks.py under LD_PRELOAD."""

    @pytest.fixture(scope="class")
    def dump_rows(self):
        """Run once for the whole class."""
        rows = run_with_trackleak(TEST_SCRIPT, dump_interval=5, timeout=90)
        assert rows, "No dump output found — check that trackleak.so is built correctly"
        return rows

    def test_leaky_cache_high_retention(self, dump_rows):
        row = find_function(dump_rows, "leaky_cache")
        assert row is not None, "leaky_cache not found in dump"
        assert row["retention_pct"] >= 80.0, \
            f"Expected retention >= 80%, got {row['retention_pct']}%"

    def test_leaky_list_high_retention(self, dump_rows):
        row = find_function(dump_rows, "leaky_list_append")
        assert row is not None, "leaky_list_append not found in dump"
        assert row["retention_pct"] >= 80.0, \
            f"Expected retention >= 80%, got {row['retention_pct']}%"

    def test_healthy_allocation_low_retention(self, dump_rows):
        row = find_function(dump_rows, "healthy_allocation")
        assert row is not None, "healthy_allocation not found in dump"
        assert row["retention_pct"] <= 20.0, \
            f"Expected retention <= 20%, got {row['retention_pct']}%"

    def test_dump_contains_multiple_functions(self, dump_rows):
        assert len(dump_rows) >= 3, \
            f"Expected at least 3 tracked functions, got {len(dump_rows)}"


@skip_if_no_so()
class TestTopN:
    """Test that TRACKLEAK_TOP_N limits output correctly."""

    def test_top_n_limits_output(self):
        rows = run_with_trackleak(TEST_SCRIPT, dump_interval=5, top_n=2, timeout=90)
        # Each dump shows at most top_n rows; across multiple dumps some overlap,
        # but no single dump block should have more than top_n unique entries.
        assert len(rows) <= 2 * 2 + 5, "top_n=2 should produce very few rows"


if __name__ == "__main__":
    # Quick smoke test without pytest
    print("Running parser unit tests...")
    t = TestDumpParsing()
    t.test_parses_correct_number_of_rows()
    t.test_leaky_cache_retention()
    t.test_healthy_allocation_retention()
    t.test_row_fields_populated()
    print("  Parser tests passed.")

    if os.path.exists(TRACKLEAK_SO):
        print(f"Found {TRACKLEAK_SO}, running integration tests...")
        rows = run_with_trackleak(TEST_SCRIPT, dump_interval=5, timeout=90)
        if rows:
            print(f"  Got {len(rows)} function rows from dump")
            row = find_function(rows, "leaky_cache")
            if row:
                print(f"  leaky_cache retention: {row['retention_pct']}%")
        else:
            print("  WARNING: no dump output captured")
    else:
        print(f"Skipping integration tests ({TRACKLEAK_SO} not found — run: make build)")

    print("Done.")