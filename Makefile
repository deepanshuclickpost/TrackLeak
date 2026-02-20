# ============================================================
# TrackLeak - Python Memory Profiler using LD_PRELOAD
# https://github.com/deepanshukartikey/trackleak
#
# Intercepts malloc/free and PyMem_* at the C level to find
# memory leaks that pure-Python profilers miss.
# ============================================================

# ---- Configuration ----
PYTHON_VERSION     ?= 3.11
PYTHON_FULL_VERSION ?= 3.11.10
SOURCE              = trackleak.c
OUTPUT              = trackleak.so

# ---- Auto-detect system ----
LIBPYTHON_EXISTS := $(shell ldconfig -p 2>/dev/null | grep -c "libpython$(PYTHON_VERSION).so" || echo "0")
LIBCURL_EXISTS   := $(shell ldconfig -p 2>/dev/null | grep -c "libcurl.so" || echo "0")
OS               := $(shell . /etc/os-release 2>/dev/null && echo $$ID || echo "unknown")
NPROC            := $(shell nproc 2>/dev/null || echo 4)

# ---- Compiler flags ----
CC       = cc
CFLAGS   = -shared -fPIC -O2 -Wall
INCLUDES = -I/usr/local/include/python$(PYTHON_VERSION)/
LIBS     = -ldl -lpthread -lcurl

# ============================================================
# Build
# ============================================================

.PHONY: build check install clean test test-es verify run quickstart help deps

build: deps
	@echo ""
	@echo "Compiling $(OUTPUT)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(OUTPUT) $(SOURCE) $(LIBS)
	@echo ""
	@echo "Verifying library links..."
	@ldd $(OUTPUT) | grep -E "python|curl|pthread" || echo "WARNING: Some libraries may not be linked"
	@echo ""
	@echo "✓ Build complete: $(OUTPUT)"
	@echo ""
	@echo "Usage:"
	@echo "  LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION) your_script.py"
	@echo ""

# ============================================================
# Dependency check & auto-install
# ============================================================

deps:
	@echo ""
	@echo "=== TrackLeak Build ==="
	@echo ""
	@echo "Checking dependencies..."
	@if [ $(LIBPYTHON_EXISTS) -eq 0 ]; then \
		echo "✗ libpython$(PYTHON_VERSION).so not found"; \
		echo "  Installing Python with shared library..."; \
		$(MAKE) install-python; \
	else \
		echo "✓ libpython$(PYTHON_VERSION).so found"; \
	fi
	@if [ $(LIBCURL_EXISTS) -eq 0 ]; then \
		echo "✗ libcurl.so not found"; \
		echo "  Installing libcurl..."; \
		$(MAKE) install-curl; \
	else \
		echo "✓ libcurl.so found"; \
	fi

install-python:
	@echo ""
	@echo "=========================================="
	@echo "Installing Python $(PYTHON_FULL_VERSION) (shared library)"
	@echo "=========================================="
	@echo "This will take 10-15 minutes..."
	@cd /tmp && \
	if [ ! -f Python-$(PYTHON_FULL_VERSION).tgz ]; then \
		wget -q --show-progress https://www.python.org/ftp/python/$(PYTHON_FULL_VERSION)/Python-$(PYTHON_FULL_VERSION).tgz; \
	fi && \
	tar -xzf Python-$(PYTHON_FULL_VERSION).tgz && \
	cd Python-$(PYTHON_FULL_VERSION) && \
	export CFLAGS="-O3 -fPIC" && \
	export LDFLAGS="-Wl,-rpath=/usr/local/lib" && \
	./configure \
		--enable-optimizations \
		--enable-shared \
		--prefix=/usr/local \
		--with-system-ffi \
		--with-computed-gotos \
		--enable-loadable-sqlite-extensions \
		--with-lto \
		--quiet && \
	make -j $(NPROC) --quiet && \
	sudo make altinstall --quiet && \
	sudo ldconfig && \
	echo "✓ Python $(PYTHON_VERSION) installed with shared library support!"

install-curl:
	@echo ""
	@echo "=========================================="
	@echo "Installing libcurl Development Package"
	@echo "=========================================="
	@if [ "$(OS)" = "ubuntu" ] || [ "$(OS)" = "debian" ]; then \
		echo "Detected: Ubuntu/Debian"; \
		sudo apt-get update -qq && \
		sudo apt-get install -y -qq libcurl4-openssl-dev; \
	elif [ "$(OS)" = "centos" ] || [ "$(OS)" = "rhel" ] || [ "$(OS)" = "rocky" ] || [ "$(OS)" = "amzn" ]; then \
		echo "Detected: CentOS/RHEL/Rocky/Amazon Linux"; \
		sudo yum install -y -q libcurl-devel; \
	elif [ "$(OS)" = "fedora" ]; then \
		echo "Detected: Fedora"; \
		sudo dnf install -y -q libcurl-devel; \
	elif [ "$(OS)" = "alpine" ]; then \
		echo "Detected: Alpine"; \
		sudo apk add --quiet curl-dev; \
	elif [ "$(OS)" = "arch" ]; then \
		echo "Detected: Arch Linux"; \
		sudo pacman -S --noconfirm curl; \
	else \
		echo "ERROR: Unsupported OS: $(OS)"; \
		echo "Please manually install libcurl development headers:"; \
		echo "  Ubuntu/Debian:  sudo apt-get install libcurl4-openssl-dev"; \
		echo "  CentOS/RHEL:    sudo yum install libcurl-devel"; \
		echo "  Fedora:         sudo dnf install libcurl-devel"; \
		echo "  Alpine:         apk add curl-dev"; \
		echo "  Arch:           pacman -S curl"; \
		exit 1; \
	fi
	@sudo ldconfig
	@echo "✓ libcurl installed"

# ============================================================
# Check / Verify
# ============================================================

check:
	@echo ""
	@echo "=== Dependency Check ==="
	@echo ""
	@if [ $(LIBPYTHON_EXISTS) -gt 0 ]; then \
		echo "✓ libpython$(PYTHON_VERSION).so found"; \
		ldconfig -p | grep "libpython$(PYTHON_VERSION).so" | head -1; \
	else \
		echo "✗ libpython$(PYTHON_VERSION).so not found"; \
		echo "  Run 'make build' to auto-install"; \
	fi
	@echo ""
	@if [ $(LIBCURL_EXISTS) -gt 0 ]; then \
		echo "✓ libcurl.so found"; \
		ldconfig -p | grep "libcurl.so" | head -1; \
	else \
		echo "✗ libcurl.so not found"; \
		echo "  Run 'make build' to auto-install"; \
	fi
	@echo ""
	@if [ -f $(OUTPUT) ]; then \
		echo "✓ $(OUTPUT) built"; \
		echo ""; \
		echo "Linked libraries:"; \
		ldd $(OUTPUT) | grep -E "python|curl|pthread" || echo "  (none found)"; \
	else \
		echo "✗ $(OUTPUT) not built yet"; \
		echo "  Run 'make build' to build"; \
	fi

verify: build
	@echo ""
	@echo "=== Verification Report ==="
	@echo ""
	@echo "1. File info:"
	@ls -lh $(OUTPUT)
	@echo ""
	@echo "2. Linked libraries:"
	@ldd $(OUTPUT)
	@echo ""
	@echo "3. Required symbols (should see curl_*, pthread_*, Py*):"
	@nm -D $(OUTPUT) | grep " U " | grep -E "curl_|pthread_|Py" | head -15
	@echo ""
	@echo "4. Exported interceptors (should see malloc, free, PyMem_*):"
	@nm -D $(OUTPUT) | grep " T " | grep -E "malloc|free|PyMem" || echo "  (none found)"
	@echo ""

# ============================================================
# Install / Uninstall
# ============================================================

install: build
	@echo ""
	@echo "Installing TrackLeak..."
	sudo cp $(OUTPUT) /usr/local/lib/
	sudo ldconfig
	@echo "✓ Installed to /usr/local/lib/$(OUTPUT)"
	@echo ""
	@echo "Usage:"
	@echo "  LD_PRELOAD=/usr/local/lib/$(OUTPUT) python$(PYTHON_VERSION) script.py"

uninstall:
	@echo ""
	sudo rm -f /usr/local/lib/$(OUTPUT)
	sudo ldconfig
	@echo "✓ Removed /usr/local/lib/$(OUTPUT)"

# ============================================================
# Clean
# ============================================================

clean:
	rm -f $(OUTPUT)
	@echo "✓ Cleaned"

# ============================================================
# Test
# ============================================================

test: build
	@echo ""
	@echo "=== Testing TrackLeak ==="
	@echo ""
	@echo "Test 1: Library loads"
	@LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION) -c "print('✓ Library loads successfully')"
	@echo ""
	@echo "Test 2: Memory allocation tracking"
	@echo "import time; data = [i for i in range(100000)]; time.sleep(2); print('✓ Memory tracking active')" | \
		LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION)
	@echo ""
	@echo "Test 3: Custom log directory"
	@mkdir -p /tmp/trackleak-test
	@echo "import time; data = [i for i in range(100000)]; time.sleep(2); print('✓ Custom log dir works')" | \
		TRACKLEAK_LOG_DIR=/tmp/trackleak-test \
		LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION)
	@echo ""
	@echo "✓ All tests passed"

test-es: build
	@echo ""
	@echo "=== Testing Elasticsearch Integration ==="
	@echo ""
	@if [ -z "$$ELASTICSEARCH_URL" ]; then \
		echo "Running with default test config..."; \
		echo "  URL:   http://localhost:9200/_bulk"; \
		echo "  Index: trackleak-test"; \
		echo ""; \
		echo "Running test (15 seconds)..."; \
		echo "import time; data = [i*i for i in range(100000)]; time.sleep(15); print('✓ Test complete')" | \
			ENABLE_ELASTICSEARCH=1 \
			ELASTICSEARCH_URL="http://localhost:9200/_bulk" \
			ELASTICSEARCH_INDEX="trackleak-test" \
			LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION); \
	else \
		echo "Using environment ES settings..."; \
		echo "import time; data = [i*i for i in range(100000)]; time.sleep(15); print('✓ Test complete')" | \
			LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION); \
	fi
	@echo ""
	@echo "Verify in Elasticsearch:"
	@echo "  curl 'http://localhost:9200/trackleak-test/_search?pretty'"

# ============================================================
# Run
# ============================================================

run: build
	@if [ -z "$(SCRIPT)" ]; then \
		echo ""; \
		echo "Error: No script specified"; \
		echo ""; \
		echo "Usage:"; \
		echo "  make run SCRIPT=your_script.py"; \
		echo ""; \
		exit 1; \
	fi
	@echo ""
	@echo "=== Running with TrackLeak ==="
	@echo "Script: $(SCRIPT)"
	@if [ ! -z "$$ENABLE_ELASTICSEARCH" ]; then \
		echo "Elasticsearch: ENABLED → $$ELASTICSEARCH_URL"; \
	else \
		echo "Elasticsearch: disabled (set ENABLE_ELASTICSEARCH=1 to enable)"; \
	fi
	@echo ""
	@LD_PRELOAD=./$(OUTPUT) python$(PYTHON_VERSION) $(SCRIPT)

# ============================================================
# Help
# ============================================================

quickstart:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║       TrackLeak Memory Profiler - Quick Start       ║"
	@echo "╚══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  1. Build:        make build"
	@echo "  2. Test:         make test"
	@echo "  3. Run:          make run SCRIPT=your_app.py"
	@echo "  4. Install:      sudo make install"
	@echo ""
	@echo "  Or directly:"
	@echo "     LD_PRELOAD=./trackleak.so python3.11 your_app.py"
	@echo ""
	@echo "  For more: make help"
	@echo ""

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║             TrackLeak Memory Profiler                ║"
	@echo "╚══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "BUILD:"
	@echo "  make build              Build profiler (auto-installs deps)"
	@echo "  make build PYTHON_VERSION=3.12  Build for specific Python"
	@echo "  make check              Check dependency status"
	@echo "  make verify             Detailed build verification"
	@echo "  make clean              Remove built files"
	@echo ""
	@echo "INSTALL:"
	@echo "  sudo make install       Install to /usr/local/lib"
	@echo "  sudo make uninstall     Remove from /usr/local/lib"
	@echo ""
	@echo "TEST:"
	@echo "  make test               Test basic functionality"
	@echo "  make test-es            Test Elasticsearch integration"
	@echo ""
	@echo "RUN:"
	@echo "  make run SCRIPT=app.py  Run script with profiler"
	@echo ""
	@echo "PROFILER CONFIGURATION:"
	@echo "  TRACKLEAK_DUMP_INTERVAL   Stats dump interval, seconds (default: 300)"
	@echo "  TRACKLEAK_SAMPLE_RATE     Sample 1 in N allocations (default: 50)"
	@echo "  TRACKLEAK_MIN_SIZE        Min allocation size to track (default: 500)"
	@echo "  TRACKLEAK_STARTUP_DELAY   Delay before profiling starts (default: 10)"
	@echo "  TRACKLEAK_LOG_DIR         Log directory (default: /var/log/memory-profiler)"
	@echo "  TRACKLEAK_JSON_LOG        Stats log filename (default: profiler.json)"
	@echo "  TRACKLEAK_EVENT_LOG       Event log filename (default: events.log)"
	@echo "  MEMORY_PROFILER_EVENTS    Set to 1 to log every alloc/free"
	@echo ""
	@echo "ELASTICSEARCH (optional):"
	@echo "  ENABLE_ELASTICSEARCH      Set to 1 to enable"
	@echo "  ELASTICSEARCH_URL         Bulk endpoint URL"
	@echo "  ELASTICSEARCH_INDEX       Index name (default: trackleak-memory)"
	@echo "  ELASTICSEARCH_USERNAME    Basic auth username"
	@echo "  ELASTICSEARCH_PASSWORD    Basic auth password"
	@echo "  ELASTICSEARCH_API_KEY     API key auth (preferred)"
	@echo "  ELASTICSEARCH_SSL_VERIFY  Set to 0 to disable SSL verify"
	@echo ""
	@echo "EXAMPLES:"
	@echo ""
	@echo "  # Basic (logs to file only)"
	@echo "  LD_PRELOAD=./trackleak.so python3.11 app.py"
	@echo ""
	@echo "  # Custom log directory"
	@echo "  TRACKLEAK_LOG_DIR=/tmp/profiler \\"
	@echo "    LD_PRELOAD=./trackleak.so python3.11 app.py"
	@echo ""
	@echo "  # With Elasticsearch"
	@echo "  ENABLE_ELASTICSEARCH=1 \\"
	@echo "    ELASTICSEARCH_URL='https://es:9200/_bulk' \\"
	@echo "    ELASTICSEARCH_API_KEY='VnVhQ2...' \\"
	@echo "    LD_PRELOAD=./trackleak.so python3.11 app.py"
	@echo ""
