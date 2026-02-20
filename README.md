# TrackLeak

**Hunt Python memory leaks at the C level.**

TrackLeak is a memory profiler that intercepts `malloc`/`free` and `PyMem_*` allocations **below** the Python interpreter using `LD_PRELOAD`. It catches leaks that pure-Python profilers like `tracemalloc` and `Memray` miss — including leaks in C extensions, the CPython runtime itself, and glibc.

No code changes. No restarts. One environment variable.

```bash
LD_PRELOAD=./trackleak.so python3.11 your_app.py
```

---

## Table of Contents

- [Why TrackLeak?](#why-trackleak)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Reading the Output](#reading-the-output)
- [Examples](#examples)
- [Elasticsearch Integration](#elasticsearch-integration)
- [Limitations](#limitations)
- [Build Options](#build-options)
- [License](#license)

---

## Why TrackLeak?

Python's `tracemalloc` and tools like Memray only see allocations made through Python's memory API. But in production, memory leaks often happen **below** that layer — in C extensions, CPython internals, or glibc itself. TrackLeak intercepts at the C level so nothing escapes.

| Feature | tracemalloc | Memray | **TrackLeak** |
|---|---|---|---|
| Tracks `malloc`/`free` | ❌ | ✅ | ✅ |
| Tracks `PyMem_*` | ✅ | ✅ | ✅ |
| Sees C extension leaks | ❌ | Partial | ✅ |
| Sees CPython internal leaks | ❌ | ❌ | ✅ |
| Needs code changes | ✅ | ❌ | ❌ |
| Sampling (low overhead) | ❌ | ❌ | ✅ |
| Retention % per function | ❌ | ❌ | ✅ |
| Elasticsearch integration | ❌ | ❌ | ✅ |
| Production safe | ⚠️ High overhead | ⚠️ High overhead | ✅ Sampling-based |

### Real-world leaks TrackLeak caught

- `warnings.warn()` allocating on every DB write — invisible to tracemalloc
- `time.strftime()` creating intermediate C strings on every log line
- Unbounded dict caches with no eviction policy
- C extension buffer leaks in third-party libraries

---

## How It Works

TrackLeak uses `LD_PRELOAD` to insert itself before glibc in the dynamic linker's search order. When any code calls `malloc()` or `PyMem_Malloc()`, TrackLeak's version runs first:

```
Your Python code
  → CPython interpreter
    → PyMem_Malloc / malloc
      → trackleak.so (intercepts → tracks → attributes to Python function)
        → real malloc (glibc)
          → kernel
```

For every intercepted allocation, TrackLeak:

1. **Walks the Python stack** to find which Python function triggered it
2. **Updates per-function stats** (count, total bytes, peak size)
3. **Samples 1 in N allocations** for detailed retention tracking
4. **On free()**, checks if the pointer was sampled and updates freed bytes
5. **Periodically dumps stats** showing retention % per function

The key insight: **if sampled memory is never freed, it's a leak.** A function showing 100% retention is holding onto everything it allocated.

### The LD_PRELOAD Trick

```
Normal:       python → glibc malloc()
With preload: python → trackleak.so malloc() → tracks it → glibc malloc()
```

TrackLeak uses `dlsym(RTLD_NEXT, "malloc")` to call the **real** malloc after recording the allocation. This is the same technique used by `jemalloc`, `tcmalloc`, and other allocator replacements.

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/deepanshuclickpost/TrackLeak.git
cd TrackLeak
```

### 2. Build

```bash
make build
```

This auto-detects and installs missing dependencies (`libpython` shared library, `libcurl`).

### 3. Run

```bash
LD_PRELOAD=./trackleak.so python3.11 your_app.py
```

### 4. Check Logs

```bash
# Default log path
tail -f /var/log/memory-profiler/profiler.json

# Or if you set a custom log dir
tail -f $TRACKLEAK_LOG_DIR/profiler.json
```

That's it. No code changes needed.

---

## Installation

### Prerequisites

- **Linux** (uses `LD_PRELOAD`, `dlsym`)
- **Python 3.11+** built with `--enable-shared` (the Makefile handles this)
- **libcurl** (for Elasticsearch support, auto-installed by `make`)
- **GCC** or compatible C compiler

### Build from Source

```bash
git clone https://github.com/deepanshuclickpost/TrackLeak.git
cd TrackLeak
make build
```

The Makefile will:
- Check if `libpython3.11.so` exists → auto-installs Python with `--enable-shared` if not
- Check if `libcurl.so` exists → auto-installs via your package manager if not
- Compile `trackleak.so`

### Verify the Build

```bash
make verify
```

This shows linked libraries, exported symbols, and confirms everything is wired correctly.

### Install System-wide

```bash
sudo make install
```

Installs to `/usr/local/lib/trackleak.so`. Then use:

```bash
LD_PRELOAD=/usr/local/lib/trackleak.so python3.11 your_app.py
```

### Uninstall

```bash
sudo make uninstall
```

### Build for a Different Python Version

```bash
make build PYTHON_VERSION=3.12 PYTHON_FULL_VERSION=3.12.7
```

---

## Configuration

All configuration is via **environment variables**. No recompilation needed.

### Profiler Settings

| Variable | Default | Description |
|---|---|---|
| `TRACKLEAK_DUMP_INTERVAL` | `300` | Seconds between stats dumps to log file |
| `TRACKLEAK_SAMPLE_RATE` | `50` | Sample 1 in N allocations for retention tracking |
| `TRACKLEAK_MIN_SIZE` | `500` | Minimum allocation size in bytes to track |
| `TRACKLEAK_STARTUP_DELAY` | `10` | Seconds to wait before profiling starts (skip init noise) |

### Log Settings

| Variable | Default | Description |
|---|---|---|
| `TRACKLEAK_LOG_DIR` | `/var/log/memory-profiler` | Log directory (auto-created if missing, falls back to `/tmp/trackleak/`) |
| `TRACKLEAK_JSON_LOG` | `profiler.json` | Stats log filename |
| `TRACKLEAK_EVENT_LOG` | `events.log` | Per-allocation event log filename |
| `MEMORY_PROFILER_EVENTS` | `0` | Set to `1` to log every individual alloc/free |

### Elasticsearch Settings (Optional)

| Variable | Default | Description |
|---|---|---|
| `ENABLE_ELASTICSEARCH` | `0` | Set to `1` to enable ES integration |
| `ELASTICSEARCH_URL` | — | ES bulk endpoint URL (required if enabled) |
| `ELASTICSEARCH_INDEX` | `trackleak-memory` | Index name |
| `ELASTICSEARCH_USERNAME` | — | Basic auth username |
| `ELASTICSEARCH_PASSWORD` | — | Basic auth password |
| `ELASTICSEARCH_API_KEY` | — | API key auth (preferred over basic auth) |
| `ELASTICSEARCH_SSL_VERIFY` | `1` | Set to `0` to disable SSL certificate verification |
| `NOMAD_JOB_NAME` | `unknown` | Job name tag added to every ES document |

### Startup Output

When TrackLeak loads, it prints its active configuration to stderr:

```
[trackleak]   log_dir=/var/log/memory-profiler
[trackleak]   json_log=/var/log/memory-profiler/profiler.json
[trackleak]   event_log=/var/log/memory-profiler/events.log
[trackleak] Configuration loaded:
[trackleak]   dump_interval=300s, sample_rate=1/50, min_size=500, startup_delay=10s
[trackleak]   elasticsearch=disabled
[trackleak]   job_name=unknown
```

---

## Reading the Output

### Stats Log (`profiler.json`)

Every `TRACKLEAK_DUMP_INTERVAL` seconds, TrackLeak writes the top 20 functions by total bytes allocated.

```bash
# View last 100 lines (default log path)
tail -f -n 100 /var/log/memory-profiler/profiler.json

# Or if you set a custom log dir
tail -f -n 100 $TRACKLEAK_LOG_DIR/profiler.json
```

Sample output:

```
FUNCTION                          COUNT     TOTAL_MB  SAMPLES    SAMPLE_MB     LINE     FREED_MB(RET%) | FILE
------------------------------   --------  ---------- --------  ------------ --------  ---------------- | -----
string_format_leak                 5000        19.53      100         0.39       72      0.39(0.0%)     | test_leaks.py
leaky_cache                       10000         5.29      200         0.10       38      0.00(100.0%)   | test_leaks.py
<listcomp>                         5000         2.90      100         0.06       53      0.00(100.0%)   | test_leaks.py
--- dump at 1771567369 (3 functions, hash 300/200000) ---
```

### Column Reference

| Column | Meaning |
|---|---|
| `FUNCTION` | Python function name where allocation originated |
| `COUNT` | Total number of allocations from this function |
| `TOTAL_MB` | Total bytes allocated (in MB) |
| `SAMPLES` | Number of allocations that were sampled (1 in N) |
| `SAMPLE_MB` | Total bytes in sampled allocations |
| `LINE` | Source line number |
| `FREED_MB(RET%)` | Freed bytes in samples and **retention percentage** |
| `FILE` | Source file path |

### Understanding Retention %

This is the **key metric** for finding leaks:

| Retention | Meaning | Action |
|---|---|---|
| **0%** | All sampled memory was freed | ✅ Healthy — no leak |
| **30-70%** | Some memory retained | ⚠️ Investigate — possible slow leak or long-lived cache |
| **100%** | Nothing was freed | 🔴 **Memory leak** — allocated memory never released |

### Event Log (`events.log`)

When `MEMORY_PROFILER_EVENTS=1`, every individual allocation and free is logged:

```json
{"event_type":1,"ptr":"0x55abc123","size":1024,"function":"leaky_cache","file":"app.py","line":38,"timestamp":"1771567369"}
{"event_type":2,"ptr":"0x55abc123","timestamp":"1771567370"}
```

- `event_type: 1` = allocation
- `event_type: 2` = free

> ⚠️ Event logging is verbose. Use it for debugging, not production.

---

## Examples

### Basic Usage (file logging only)

```bash
LD_PRELOAD=./trackleak.so python3.11 app.py

# Check the output (default log path)
tail -f /var/log/memory-profiler/profiler.json
```

### Local Debugging (aggressive tracking)

```bash
TRACKLEAK_DUMP_INTERVAL=10 \
TRACKLEAK_SAMPLE_RATE=1 \
TRACKLEAK_MIN_SIZE=100 \
TRACKLEAK_LOG_DIR=/tmp/trackleak \
LD_PRELOAD=./trackleak.so python3.11 app.py

# Watch live (matches TRACKLEAK_LOG_DIR above)
tail -f /tmp/trackleak/profiler.json
```

### Production (low overhead)

```bash
TRACKLEAK_DUMP_INTERVAL=300 \
TRACKLEAK_SAMPLE_RATE=100 \
TRACKLEAK_MIN_SIZE=1024 \
LD_PRELOAD=/usr/local/lib/trackleak.so python3.11 app.py

# Check logs (default path)
tail -f /var/log/memory-profiler/profiler.json
```

### With Elasticsearch (API Key)

```bash
ENABLE_ELASTICSEARCH=1 \
ELASTICSEARCH_URL='https://es-server:9200/_bulk' \
ELASTICSEARCH_API_KEY='VnVhQ2...' \
ELASTICSEARCH_INDEX='myapp-memory' \
LD_PRELOAD=/usr/local/lib/trackleak.so python3.11 app.py
```

### With Elasticsearch (Basic Auth)

```bash
ENABLE_ELASTICSEARCH=1 \
ELASTICSEARCH_URL='http://localhost:9200/_bulk' \
ELASTICSEARCH_INDEX='myapp-memory' \
ELASTICSEARCH_USERNAME='elastic' \
ELASTICSEARCH_PASSWORD='changeme' \
LD_PRELOAD=./trackleak.so python3.11 app.py
```

### Using the Makefile

```bash
# Run any script with profiler
make run SCRIPT=app.py

# Run tests
make test

# Test Elasticsearch
make test-es
```

### Test with Sample Script

A test script is included that simulates common leak patterns:

```bash
TRACKLEAK_DUMP_INTERVAL=30 \
TRACKLEAK_MIN_SIZE=100 \
TRACKLEAK_LOG_DIR=/tmp/trackleak \
LD_PRELOAD=./trackleak.so python3.11 test_leaks.py

# Watch results
tail -f /tmp/trackleak/profiler.json
```

The test script exercises:
- **Leaky list** — global list that grows forever (100% retention)
- **Unbounded cache** — dict with no eviction (100% retention)
- **Healthy allocation** — alloc + free loop (~0% retention)
- **warnings.warn()** — hidden CPython allocator
- **String formatting** — f-strings and `time.strftime()` in loops
- **Realloc growth** — `bytearray.extend()` triggering `PyMem_Realloc`

---

## Elasticsearch Integration

TrackLeak can ship profiling data to Elasticsearch in real-time for dashboards and alerting.

### What Gets Sent

Every stats dump sends a bulk request with one document per function:

```json
{
  "timestamp": 1771567369,
  "time": "2026-02-20T14:30:00",
  "job_name": "my-service",
  "hostname": "prod-worker-01",
  "function": "leaky_cache",
  "file": "app.py",
  "line": 38,
  "count": 10000,
  "total_bytes": 5548032,
  "total_mb": 5.29,
  "sample_count": 200,
  "sample_total_bytes": 104857,
  "sample_total_mb": 0.10,
  "sample_free_bytes": 0,
  "sample_free_mb": 0.00,
  "retention_pct": 100.0,
  "peak_single": 1024,
  "avg_size": 554,
  "elapsed_seconds": 300
}
```

### Architecture

- Bulk requests are **queued** and sent by a background thread (non-blocking)
- Queue size: 100 entries with automatic oldest-entry eviction
- Connection timeouts: 5s connect, 10s total
- Supports both **API Key** (recommended) and **Basic Auth**

### Test ES Integration

```bash
make test-es
```

### Query Example

```bash
# Top leaking functions (retention > 80%)
curl -s 'http://localhost:9200/trackleak-memory/_search?pretty' \
  -H 'Content-Type: application/json' -d '{
  "query": { "range": { "retention_pct": { "gte": 80 } } },
  "sort": [{ "total_mb": "desc" }],
  "size": 10
}'
```

---

## Limitations

- **Linux only** — `LD_PRELOAD` is a Linux dynamic linker feature.
- **pymalloc arena** — By default, Python's internal allocator handles objects ≤512 bytes without calling `malloc`. To track these too, force all allocations through `malloc` and lower the minimum size:
  ```bash
  PYTHONMALLOC=malloc TRACKLEAK_MIN_SIZE=100 LD_PRELOAD=./trackleak.so python3.11 app.py
  ```
- **Sampling** — By default, only 1 in 50 allocations are tracked for retention. Set `TRACKLEAK_SAMPLE_RATE=1` for exhaustive tracking (higher overhead).
- **GIL** — Python stack walking requires the GIL, which adds some overhead per tracked allocation.
- **Shared libpython required** — Python must be built with `--enable-shared` for `PyMem_*` interception to work. The Makefile handles this automatically.

---

## Build Options

```bash
make build                # Build (auto-installs deps)
make build PYTHON_VERSION=3.12  # Different Python version
make check                # Check dependencies
make verify               # Detailed build verification
make test                 # Test basic functionality
make test-es              # Test Elasticsearch integration
sudo make install         # Install to /usr/local/lib
sudo make uninstall       # Remove from /usr/local/lib
make clean                # Remove build artifacts
make quickstart           # Quick start guide
make help                 # Full help
```

---

## Project Structure

```
TrackLeak/
├── trackleak.c       # The profiler (~1400 lines of C)
├── Makefile          # Build system with auto-dependency installation
├── test_leaks.py     # Sample script with common leak patterns
├── LICENSE           # MIT
├── .gitignore
└── README.md
```

---

## License

MIT — see [LICENSE](LICENSE)

## Author

**Deepanshu Kartikey** — [kartikey406@gmail.com](mailto:kartikey406@gmail.com)

---

*Built at [ClickPost](https://www.clickpost.ai) to hunt memory leaks in production Python services.*
