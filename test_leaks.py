"""
TrackLeak Test Script - Memory Leak Patterns
=============================================

Run with:
  LD_PRELOAD=./trackleak.so python3.11 test_leaks.py

With custom log directory:
  TRACKLEAK_LOG_DIR=/tmp/trackleak \
  TRACKLEAK_DUMP_INTERVAL=30 \
  TRACKLEAK_MIN_SIZE=100 \
  LD_PRELOAD=./trackleak.so python3.11 test_leaks.py

Check logs:
  tail -f /tmp/trackleak/profiler.json
"""

import time
import sys
import warnings

# ============================================================
# Pattern 1: Classic list leak — grows forever, never freed
# ============================================================
leaked_data = []

def leaky_list_append():
    """Appends to a global list — memory never released."""
    for i in range(5000):
        leaked_data.append("x" * 1024)  # 1KB strings piling up


# ============================================================
# Pattern 2: Dict cache with no eviction
# ============================================================
cache = {}

def leaky_cache():
    """Simulates unbounded cache — keys keep growing."""
    for i in range(10000):
        cache[f"user:{i}:session:{time.time()}"] = {
            "payload": bytearray(512),
            "timestamp": time.time(),
        }


# ============================================================
# Pattern 3: Healthy allocation — alloc + free (no leak)
# ============================================================
def healthy_allocation():
    """Allocates and frees — should show ~0% retention."""
    for i in range(5000):
        tmp = [j for j in range(200)]
        del tmp


# ============================================================
# Pattern 4: warnings.warn() — hidden allocator
# ============================================================
def warning_spam():
    """Each warnings.warn() call allocates internally.
    This is a real pattern that leaks in production."""
    for i in range(2000):
        warnings.warn("db connection slow", stacklevel=1)


# ============================================================
# Pattern 5: String formatting in a loop
# ============================================================
log_lines = []

def string_format_leak():
    """time.strftime + string concat — small per-call, adds up."""
    for i in range(5000):
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Request {i} processed in {i * 0.001:.3f}s"
        log_lines.append(line)


# ============================================================
# Pattern 6: Bytearray that grows via realloc
# ============================================================
def realloc_growth():
    """Repeatedly extends a bytearray — triggers PyMem_Realloc."""
    buf = bytearray()
    for i in range(3000):
        buf.extend(b"A" * 1024)
    return buf


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 60)
    print("TrackLeak Test Script")
    print("=" * 60)
    print()

    dump_interval = 30  # match TRACKLEAK_DUMP_INTERVAL for best results

    # --- Round 1 ---
    print("[Round 1] Running leak patterns...")
    print("  → leaky_list_append()")
    leaky_list_append()

    print("  → leaky_cache()")
    leaky_cache()

    print("  → healthy_allocation()")
    healthy_allocation()

    print("  → warning_spam()")
    warning_spam()

    print("  → string_format_leak()")
    string_format_leak()

    print("  → realloc_growth()")
    realloc_growth()

    print()
    print(f"  Waiting {dump_interval}s for first stats dump...")
    time.sleep(dump_interval)

    # --- Round 2 (repeat to see retention grow) ---
    print()
    print("[Round 2] Repeating to show retention climbing...")
    leaky_list_append()
    leaky_cache()
    healthy_allocation()
    string_format_leak()

    print()
    print(f"  Waiting {dump_interval}s for second stats dump...")
    time.sleep(dump_interval)

    # --- Summary ---
    print()
    print("=" * 60)
    print("Expected results in profiler.json:")
    print("=" * 60)
    print()
    print("  HIGH retention (leaks):")
    print("    leaky_list_append    — retention ~90-100%")
    print("    leaky_cache          — retention ~90-100%")
    print("    string_format_leak   — retention ~90-100%")
    print("    warning_spam         — retention ~50-80%")
    print()
    print("  LOW retention (healthy):")
    print("    healthy_allocation   — retention ~0-10%")
    print()
    print("  REALLOC pattern:")
    print("    realloc_growth       — shows PyMem_Realloc activity")
    print()
    print(f"  leaked_data:  {len(leaked_data)} items, ~{len(leaked_data) * 1024 // 1024}KB")
    print(f"  cache:        {len(cache)} keys")
    print(f"  log_lines:    {len(log_lines)} entries")
    print()
    print("Done. Check your logs:")
    print("  cat $(TRACKLEAK_LOG_DIR)/profiler.json")
    print()


if __name__ == "__main__":
    main()
