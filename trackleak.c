/**
 * TrackLeak - Memory Profiler for Python Applications
 *
 * Intercepts memory allocation functions (malloc/free, PyMem_*) to track
 * Python memory usage and identify memory leaks by monitoring
 * allocation/deallocation patterns.
 *
 * Features:
 * - Tracks malloc/free and PyMem_* allocations via LD_PRELOAD
 * - Samples 1 in 50 allocations for detailed tracking
 * - Reports retention rates to identify leaks
 * - Auto-resets when tables fill up
 * - Optional: Ships stats to Elasticsearch via bulk API
 * - Clears stats after each dump for fresh tracking
 *
 * Usage:
 *   LD_PRELOAD=./trackleak.so python3 your_script.py
 *
 * Environment Variables:
 *   TRACKLEAK_LOG_DIR=/path/to/logs      Log directory (default: /var/log/memory-profiler)
 *   TRACKLEAK_JSON_LOG=profiler.json      JSON stats filename (default: profiler.json)
 *   TRACKLEAK_EVENT_LOG=events.log        Event log filename (default: events.log)
 *   ENABLE_ELASTICSEARCH=1                Enable Elasticsearch integration
 *   ELASTICSEARCH_URL=<url>               ES bulk endpoint (required if enabled)
 *   ELASTICSEARCH_INDEX=<index>           Index name (default: trackleak-memory)
 *   ELASTICSEARCH_USERNAME=<user>         Basic auth username
 *   ELASTICSEARCH_PASSWORD=<pass>         Basic auth password
 *   ELASTICSEARCH_API_KEY=<key>           API key auth (preferred over basic auth)
 *   ELASTICSEARCH_SSL_VERIFY=0            Disable SSL verification (default: 1)
 *   NOMAD_JOB_NAME=<name>                Job name tag for ES documents
 *   MEMORY_PROFILER_EVENTS=1              Enable per-allocation event logging
 *   TRACKLEAK_DUMP_INTERVAL=300           Stats dump interval in seconds (default: 300)
 *   TRACKLEAK_SAMPLE_RATE=50              Sample 1 in N allocations (default: 50)
 *   TRACKLEAK_MIN_SIZE=500                Min allocation size to track (default: 500)
 *   TRACKLEAK_STARTUP_DELAY=10            Seconds to wait before profiling (default: 10)
 *
 * Developed By: Deepanshu Kartikey <kartikey406@gmail.com>
 * License: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <Python.h>
#include <frameobject.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <errno.h>
#if PY_VERSION_HEX >= 0x030b0000
#include <internal/pycore_frame.h>
#endif

/* ==================== Configuration Defaults ==================== */
/* These are compile-time defaults. Most can be overridden via env vars. */

#define MAX_FUNCTIONS 1000                    // Max unique Python functions to track
#define HASH_TABLE_SIZE 2048                  // Should be > MAX_FUNCTIONS for efficiency
#define FUNCTION_NAME_LEN 64                  // Max length of function names
#define DEFAULT_DUMP_INTERVAL 300             // Default dump interval (seconds)
#define DEFAULT_MIN_ALLOC_SIZE 500            // Default min allocation size to track (bytes)
#define DEFAULT_STARTUP_DELAY 10              // Default delay before profiling starts
#define ALLOCATION_HASH_SIZE 200000           // Size of allocation tracking table
#define MAX_FILE_PATH 256                     // Max file path length
#define DEFAULT_SAMPLE_RATE 50                // Default: sample 1 in 50 allocations
#define JSON_BUFFER_SIZE 8192                 // Buffer size for JSON output
#define MAX_LOG_SIZE (10 * 1024 * 1024)       // 10MB max before rotation

// Default log paths (overridable via env vars)
#define DEFAULT_LOG_DIR "/var/log/memory-profiler"
#define DEFAULT_JSON_LOG_FILENAME "profiler.json"
#define DEFAULT_EVENT_LOG_FILENAME "events.log"

// Event logging defaults
#define EVENT_BUFFER_SIZE (128 * 1024)        // 128KB buffer for event log
#define FLUSH_INTERVAL_SECONDS 5              // Flush events every 5 seconds
#define FLUSH_EVENT_COUNT 1000                // Flush after 1000 events

// Elasticsearch defaults
#define ES_BULK_BUFFER_SIZE (512 * 1024)      // 512KB buffer for ES bulk requests
#define ES_QUEUE_SIZE 100                     // Queue size for async ES sending
#define DEFAULT_ES_INDEX "trackleak-memory"   // Default index name

/* ==================== Data Structures ==================== */

typedef enum {
    EVENT_ALLOC = 1,
    EVENT_FREE = 2
} event_type_t;

/**
 * Statistics for each Python function.
 * Tracks both total allocations and sampled allocations.
 */
typedef struct {
    char function_name[FUNCTION_NAME_LEN];
    unsigned long count;                      // Total allocation count
    unsigned long total_bytes;                // Total bytes allocated
    unsigned long peak_single;                // Largest single allocation
    unsigned long avg_size;                   // Average allocation size
    unsigned long line_no;                    // Line number in source
    time_t first_seen;                        // First allocation timestamp
    time_t last_seen;                         // Last allocation timestamp
    char file_path[MAX_FILE_PATH];            // Source file path
    unsigned long sample_count;               // Number of sampled allocations
    unsigned long sample_total_bytes;         // Total bytes in samples
    unsigned long sample_free_bytes;          // Freed bytes in samples
} function_stats_t;

/**
 * Thread-local storage for current Python function info.
 */
typedef struct {
    char function_name[FUNCTION_NAME_LEN];
    int line_no;
    char file_path[MAX_FILE_PATH];
} code_stats_t;

/**
 * Tracks individual allocations for leak detection.
 * Only stores sampled allocations (1 in SAMPLE_RATE).
 */
typedef struct {
    void *ptr;                                // Pointer to allocated memory
    size_t size;                              // Size of allocation
    uint32_t func_index;                      // Index into function_stats array
} allocation_info_t;

/**
 * Elasticsearch bulk request queue entry.
 */
typedef struct {
    char bulk_data[ES_BULK_BUFFER_SIZE];
    int data_len;
    time_t timestamp;
} es_bulk_entry_t;

/**
 * Runtime Elasticsearch configuration.
 * Populated from environment variables at startup.
 */
typedef struct {
    int enabled;                              // Whether ES is active
    char url[512];                            // ES bulk endpoint URL
    char index[128];                          // Index name
    char username[128];                       // Basic auth username
    char password[128];                       // Basic auth password
    char api_key[512];                        // API key (preferred over basic)
    int ssl_verify;                           // Verify SSL certificates
} es_config_t;

/**
 * Runtime log configuration.
 * Populated from environment variables at startup.
 */
typedef struct {
    char log_dir[512];                        // Log directory path
    char json_log_path[768];                  // Full path to JSON stats log
    char event_log_path[768];                 // Full path to event log
} log_config_t;

/**
 * Runtime profiler configuration.
 * Populated from environment variables at startup.
 */
typedef struct {
    int dump_interval;                        // Seconds between stats dumps
    int sample_rate;                          // Sample 1 in N allocations
    int min_alloc_size;                       // Min bytes to track
    int startup_delay;                        // Seconds to wait before profiling
} profiler_config_t;

/* ==================== Global Variables ==================== */

// Runtime configuration (populated from env vars at init)
static es_config_t es_config;
static log_config_t log_config;
static profiler_config_t prof_config;

// Function pointers to real allocation functions
static void *(*real_malloc)(size_t) = NULL;
static void *(*real_free)(void *) = NULL;
static void *(*real_pymem_alloc)(size_t) = NULL;
static void *(*real_pymem_alloc_free)(void *) = NULL;
static void *(*real_pymem_calloc)(size_t, size_t) = NULL;
static void *(*real_pymem_realloc)(void*, size_t) = NULL;

// Statistics tracking
static size_t total_allocated = 0;
static function_stats_t function_stats[MAX_FUNCTIONS];
static int stats_count = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_dump_time = 0;
static time_t profiler_start_time = 0;
static __thread int in_profiler = 0;          // Prevent recursive profiling
static time_t job_time = 0;

// Hash tables for O(1) lookups
static int function_hash_table[HASH_TABLE_SIZE];
static int hash_table_initialized = 0;
static allocation_info_t allocation_hash_table[ALLOCATION_HASH_SIZE];

// Tracking statistics
static unsigned int unique_functions = 0;
static __thread code_stats_t code_t_storage;
static __thread int allocation_sample_counter = 0;
static __thread int in_malloc = 0;

// JSON logging (aggregated stats)
static FILE* json_log_fp = NULL;
static pthread_mutex_t json_mutex = PTHREAD_MUTEX_INITIALIZER;

// Event logging (individual allocations/frees)
static FILE* event_log_fp = NULL;
static pthread_mutex_t event_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t event_counter = 0;
static time_t last_event_flush_time = 0;
static char event_buffer[EVENT_BUFFER_SIZE];
static int profiler_ready = 0;

// Elasticsearch runtime state
static CURL *es_curl = NULL;
static struct curl_slist *es_headers = NULL;
static pthread_t es_sender_thread;
static es_bulk_entry_t es_queue[ES_QUEUE_SIZE];
static volatile int es_write_idx = 0;
static volatile int es_read_idx = 0;
static pthread_mutex_t es_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static int es_thread_running = 0;
static char job_name[128] = "unknown";

/* ==================== Forward Declarations ==================== */
static void send_bulk_to_elasticsearch(const char *bulk_data, int data_len);

/* ==================== Configuration Loading ==================== */

/**
 * Helper: read an integer environment variable with a default value.
 */
static int env_int(const char *name, int default_val) {
    const char *val = getenv(name);
    if (val) {
        int parsed = atoi(val);
        if (parsed > 0) return parsed;
    }
    return default_val;
}

/**
 * Helper: copy an environment variable into a buffer.
 * Returns 1 if the env var was set, 0 otherwise.
 */
static int env_str(const char *name, char *dest, size_t dest_size, const char *default_val) {
    const char *val = getenv(name);
    if (val && val[0] != '\0') {
        strncpy(dest, val, dest_size - 1);
        dest[dest_size - 1] = '\0';
        return 1;
    }
    if (default_val) {
        strncpy(dest, default_val, dest_size - 1);
        dest[dest_size - 1] = '\0';
    } else {
        dest[0] = '\0';
    }
    return 0;
}

/**
 * Recursively create directories (like mkdir -p).
 * Returns 0 on success, -1 on failure.
 */
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    // Remove trailing slash
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/**
 * Load log configuration from environment variables.
 * Builds full paths and ensures the log directory exists.
 */
static void load_log_config() {
    char log_dir[512];
    char json_filename[256];
    char event_filename[256];

    // Read log directory (with trailing slash cleanup)
    env_str("TRACKLEAK_LOG_DIR", log_dir, sizeof(log_dir), DEFAULT_LOG_DIR);

    // Strip trailing slash if present
    size_t dir_len = strlen(log_dir);
    if (dir_len > 1 && log_dir[dir_len - 1] == '/') {
        log_dir[dir_len - 1] = '\0';
    }

    strncpy(log_config.log_dir, log_dir, sizeof(log_config.log_dir) - 1);
    log_config.log_dir[sizeof(log_config.log_dir) - 1] = '\0';

    // Read filenames
    env_str("TRACKLEAK_JSON_LOG", json_filename, sizeof(json_filename), DEFAULT_JSON_LOG_FILENAME);
    env_str("TRACKLEAK_EVENT_LOG", event_filename, sizeof(event_filename), DEFAULT_EVENT_LOG_FILENAME);

    // Build full paths
    snprintf(log_config.json_log_path, sizeof(log_config.json_log_path),
             "%s/%s", log_config.log_dir, json_filename);
    snprintf(log_config.event_log_path, sizeof(log_config.event_log_path),
             "%s/%s", log_config.log_dir, event_filename);

    // Auto-create log directory
    if (mkdir_p(log_config.log_dir, 0755) != 0) {
        fprintf(stderr, "[trackleak] WARNING: Failed to create log dir '%s': %s\n",
                log_config.log_dir, strerror(errno));
        fprintf(stderr, "[trackleak]   Falling back to /tmp/trackleak/\n");

        strncpy(log_config.log_dir, "/tmp/trackleak", sizeof(log_config.log_dir) - 1);
        mkdir_p(log_config.log_dir, 0755);

        snprintf(log_config.json_log_path, sizeof(log_config.json_log_path),
                 "%s/%s", log_config.log_dir, json_filename);
        snprintf(log_config.event_log_path, sizeof(log_config.event_log_path),
                 "%s/%s", log_config.log_dir, event_filename);
    }

    fprintf(stderr, "[trackleak]   log_dir=%s\n", log_config.log_dir);
    fprintf(stderr, "[trackleak]   json_log=%s\n", log_config.json_log_path);
    fprintf(stderr, "[trackleak]   event_log=%s\n", log_config.event_log_path);
}

/**
 * Load all configuration from environment variables.
 * Called once at profiler startup.
 */
static void load_config() {
    // Profiler settings
    prof_config.dump_interval  = env_int("TRACKLEAK_DUMP_INTERVAL", DEFAULT_DUMP_INTERVAL);
    prof_config.sample_rate    = env_int("TRACKLEAK_SAMPLE_RATE", DEFAULT_SAMPLE_RATE);
    prof_config.min_alloc_size = env_int("TRACKLEAK_MIN_SIZE", DEFAULT_MIN_ALLOC_SIZE);
    prof_config.startup_delay  = env_int("TRACKLEAK_STARTUP_DELAY", DEFAULT_STARTUP_DELAY);

    // Elasticsearch settings
    const char *enable_es = getenv("ENABLE_ELASTICSEARCH");
    es_config.enabled = (enable_es && strcmp(enable_es, "1") == 0);

    env_str("ELASTICSEARCH_URL",      es_config.url,      sizeof(es_config.url),      NULL);
    env_str("ELASTICSEARCH_INDEX",    es_config.index,    sizeof(es_config.index),    DEFAULT_ES_INDEX);
    env_str("ELASTICSEARCH_USERNAME", es_config.username, sizeof(es_config.username), NULL);
    env_str("ELASTICSEARCH_PASSWORD", es_config.password, sizeof(es_config.password), NULL);
    env_str("ELASTICSEARCH_API_KEY",  es_config.api_key,  sizeof(es_config.api_key),  NULL);

    const char *ssl_verify = getenv("ELASTICSEARCH_SSL_VERIFY");
    es_config.ssl_verify = (ssl_verify && strcmp(ssl_verify, "0") == 0) ? 0 : 1;

    // Job name for tagging
    env_str("NOMAD_JOB_NAME", job_name, sizeof(job_name), "unknown");

    // Log configuration (directory + filenames)
    load_log_config();

    // Log configuration
    fprintf(stderr, "[trackleak] Configuration loaded:\n");
    fprintf(stderr, "[trackleak]   dump_interval=%ds, sample_rate=1/%d, min_size=%d, startup_delay=%ds\n",
            prof_config.dump_interval, prof_config.sample_rate,
            prof_config.min_alloc_size, prof_config.startup_delay);
    fprintf(stderr, "[trackleak]   elasticsearch=%s\n", es_config.enabled ? "ENABLED" : "disabled");

    if (es_config.enabled) {
        if (es_config.url[0] == '\0') {
            fprintf(stderr, "[trackleak] WARNING: ENABLE_ELASTICSEARCH=1 but ELASTICSEARCH_URL not set. Disabling ES.\n");
            es_config.enabled = 0;
        } else {
            fprintf(stderr, "[trackleak]   url=%s\n", es_config.url);
            fprintf(stderr, "[trackleak]   index=%s\n", es_config.index);
            if (es_config.api_key[0] != '\0') {
                fprintf(stderr, "[trackleak]   auth=API key\n");
            } else if (es_config.username[0] != '\0') {
                fprintf(stderr, "[trackleak]   auth=basic (%s)\n", es_config.username);
            } else {
                fprintf(stderr, "[trackleak]   auth=none (anonymous)\n");
            }
            fprintf(stderr, "[trackleak]   ssl_verify=%s\n", es_config.ssl_verify ? "yes" : "no");
        }
    }

    fprintf(stderr, "[trackleak]   job_name=%s\n", job_name);
}

/* ==================== Elasticsearch Functions ==================== */

/**
 * Initialize Elasticsearch connection using runtime config.
 */
static void init_elasticsearch() {
    if (!es_config.enabled) return;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    es_curl = curl_easy_init();

    if (!es_curl) {
        fprintf(stderr, "[trackleak] ERROR: Failed to initialize curl. Disabling ES.\n");
        es_config.enabled = 0;
        return;
    }

    // Headers (always needed)
    es_headers = curl_slist_append(es_headers, "Content-Type: application/x-ndjson");

    // API key header (if configured)
    if (es_config.api_key[0] != '\0') {
        char auth_header[600];
        snprintf(auth_header, sizeof(auth_header),
                 "Authorization: ApiKey %s", es_config.api_key);
        es_headers = curl_slist_append(es_headers, auth_header);
    }

    fprintf(stderr, "[trackleak] Elasticsearch initialized → %s\n", es_config.url);
}

/**
 * Elasticsearch sender thread — processes queued bulk requests.
 */
static void* es_sender_thread_func(void *arg) {
    while (es_thread_running) {
        pthread_mutex_lock(&es_queue_mutex);

        if (es_read_idx != es_write_idx) {
            es_bulk_entry_t *entry = &es_queue[es_read_idx];

            char bulk_data[ES_BULK_BUFFER_SIZE];
            memcpy(bulk_data, entry->bulk_data, entry->data_len);
            int data_len = entry->data_len;

            es_read_idx = (es_read_idx + 1) % ES_QUEUE_SIZE;
            pthread_mutex_unlock(&es_queue_mutex);

            send_bulk_to_elasticsearch(bulk_data, data_len);
        } else {
            pthread_mutex_unlock(&es_queue_mutex);
            usleep(100000);  // Sleep 100ms when queue is empty
        }
    }

    return NULL;
}

/**
 * Start the async Elasticsearch sender thread.
 */
static void start_es_sender_thread() {
    if (!es_config.enabled || es_thread_running) return;

    es_thread_running = 1;
    if (pthread_create(&es_sender_thread, NULL, es_sender_thread_func, NULL) != 0) {
        fprintf(stderr, "[trackleak] ERROR: Failed to create ES sender thread\n");
        es_thread_running = 0;
    } else {
        fprintf(stderr, "[trackleak] ES sender thread started\n");
    }
}

/**
 * Queue bulk request for async sending.
 */
static void queue_bulk_for_elasticsearch(const char *bulk_data, int data_len) {
    if (!es_config.enabled || data_len >= ES_BULK_BUFFER_SIZE) return;

    pthread_mutex_lock(&es_queue_mutex);

    int next_idx = (es_write_idx + 1) % ES_QUEUE_SIZE;
    if (next_idx == es_read_idx) {
        fprintf(stderr, "[trackleak] ES queue full, dropping oldest entry\n");
        es_read_idx = (es_read_idx + 1) % ES_QUEUE_SIZE;
    }

    memcpy(es_queue[es_write_idx].bulk_data, bulk_data, data_len);
    es_queue[es_write_idx].data_len = data_len;
    es_queue[es_write_idx].timestamp = time(NULL);
    es_write_idx = next_idx;

    pthread_mutex_unlock(&es_queue_mutex);
}

/**
 * Curl write callback — silently consume ES response.
 */
static size_t es_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb;
}

/**
 * Send bulk request to Elasticsearch.
 * Uses runtime config for URL, auth, and SSL settings.
 */
static void send_bulk_to_elasticsearch(const char *bulk_data, int data_len) {
    if (!es_curl || !bulk_data || data_len <= 0) return;

    // Reset for clean state
    curl_easy_reset(es_curl);

    // URL from config
    curl_easy_setopt(es_curl, CURLOPT_URL, es_config.url);

    // SSL verification
    if (!es_config.ssl_verify) {
        curl_easy_setopt(es_curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(es_curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    // Authentication: API key takes priority over basic auth
    if (es_config.api_key[0] != '\0') {
        // API key is set in the headers (added during init)
        curl_easy_setopt(es_curl, CURLOPT_HTTPHEADER, es_headers);
    } else if (es_config.username[0] != '\0' && es_config.password[0] != '\0') {
        char userpass[256];
        snprintf(userpass, sizeof(userpass), "%s:%s",
                 es_config.username, es_config.password);
        curl_easy_setopt(es_curl, CURLOPT_USERPWD, userpass);
        curl_easy_setopt(es_curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }

    // POST data
    curl_easy_setopt(es_curl, CURLOPT_POST, 1L);
    curl_easy_setopt(es_curl, CURLOPT_POSTFIELDS, bulk_data);
    curl_easy_setopt(es_curl, CURLOPT_POSTFIELDSIZE, data_len);

    // Headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");

    // Add API key header if configured
    if (es_config.api_key[0] != '\0') {
        char auth_header[600];
        snprintf(auth_header, sizeof(auth_header),
                 "Authorization: ApiKey %s", es_config.api_key);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(es_curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(es_curl, CURLOPT_WRITEFUNCTION, es_write_callback);

    // Timeouts to prevent hanging
    curl_easy_setopt(es_curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(es_curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(es_curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "[trackleak] ES send failed: %s\n", curl_easy_strerror(res));
    } else {
        long response_code;
        curl_easy_getinfo(es_curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200 || response_code == 201) {
            fprintf(stderr, "[trackleak] ES ✓ sent %d bytes (HTTP %ld)\n",
                    data_len, response_code);
        } else {
            fprintf(stderr, "[trackleak] ES ✗ HTTP %ld\n", response_code);
        }
    }

    curl_slist_free_all(headers);
}

/**
 * Cleanup Elasticsearch resources.
 */
static void cleanup_elasticsearch() {
    if (es_thread_running) {
        es_thread_running = 0;
        pthread_join(es_sender_thread, NULL);
    }

    if (es_headers) {
        curl_slist_free_all(es_headers);
        es_headers = NULL;
    }

    if (es_curl) {
        curl_easy_cleanup(es_curl);
        es_curl = NULL;
    }

    curl_global_cleanup();
}

/* ==================== Initialization ==================== */

/**
 * Constructor — runs when library is loaded via LD_PRELOAD.
 */
__attribute__((constructor))
void profiler_init() {
    profiler_start_time = time(NULL);
    job_time = time(NULL);
    last_event_flush_time = time(NULL);

    // Load all configuration from environment
    load_config();

    // Initialize Elasticsearch (if enabled)
    init_elasticsearch();
    start_es_sender_thread();
}

/**
 * Destructor — cleanup when library is unloaded.
 */
__attribute__((destructor))
void profiler_cleanup() {
    profiler_ready = 0;

    cleanup_elasticsearch();

    if (event_log_fp) {
        fflush(event_log_fp);
        fclose(event_log_fp);
        event_log_fp = NULL;
    }

    if (json_log_fp) {
        fflush(json_log_fp);
        fclose(json_log_fp);
        json_log_fp = NULL;
    }
}

/**
 * Initialize real function pointers using dlsym.
 */
static void init_real_functions() {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
        real_pymem_alloc = dlsym(RTLD_NEXT, "PyMem_Malloc");
        real_pymem_alloc_free = dlsym(RTLD_NEXT, "PyMem_Free");
        real_pymem_calloc = dlsym(RTLD_NEXT, "PyMem_Calloc");
        real_pymem_realloc = dlsym(RTLD_NEXT, "PyMem_Realloc");
    }
}

/* ==================== Event Logging ==================== */

/**
 * Log an allocation or free event (if MEMORY_PROFILER_EVENTS=1).
 * Now uses configurable log path from log_config.
 */
static void log_allocation_event(event_type_t event_type, void* ptr, size_t size,
                                  const char* func_name, const char* file_path,
                                  int line_no) {
    static int checked_env = 0;
    static int logging_enabled = 0;

    if (!checked_env) {
        char* enable_events = getenv("MEMORY_PROFILER_EVENTS");
        logging_enabled = (enable_events && strcmp(enable_events, "1") == 0);
        checked_env = 1;
    }

    if (!logging_enabled) return;

    pthread_mutex_lock(&event_log_mutex);

    if (!event_log_fp) {
        // Config not loaded yet — skip silently
        if (log_config.event_log_path[0] == '\0') {
            pthread_mutex_unlock(&event_log_mutex);
            return;
        }
        static int event_open_failed = 0;
        if (event_open_failed) {
            pthread_mutex_unlock(&event_log_mutex);
            return;
        }
        event_log_fp = fopen(log_config.event_log_path, "a");
        if (!event_log_fp) {
            fprintf(stderr, "[trackleak] WARNING: Cannot open event log '%s': %s\n",
                    log_config.event_log_path, strerror(errno));
            event_open_failed = 1;
            pthread_mutex_unlock(&event_log_mutex);
            return;
        }
        setvbuf(event_log_fp, NULL, _IOFBF, EVENT_BUFFER_SIZE);
    }

    long long timestamp = (long long)time(NULL);

    if (event_type == EVENT_ALLOC) {
        fprintf(event_log_fp,
                "{\"event_type\":1,"
                "\"ptr\":\"%p\","
                "\"size\":%zu,"
                "\"function\":\"%s\","
                "\"file\":\"%s\","
                "\"line\":%d,"
                "\"timestamp\":\"%lld\"}\n",
                ptr, size,
                func_name ? func_name : "unknown",
                file_path ? file_path : "unknown",
                line_no, timestamp);
    } else {
        fprintf(event_log_fp,
                "{\"event_type\":2,"
                "\"ptr\":\"%p\","
                "\"timestamp\":\"%lld\"}\n",
                ptr, timestamp);
    }

    event_counter++;

    time_t current_time = time(NULL);
    if (event_counter >= FLUSH_EVENT_COUNT ||
        (current_time - last_event_flush_time) >= FLUSH_INTERVAL_SECONDS) {
        fflush(event_log_fp);
        event_counter = 0;
        last_event_flush_time = current_time;
    }
    pthread_mutex_unlock(&event_log_mutex);
}

/* ==================== JSON Logging ==================== */

static void rotate_json_log_if_needed() {
    struct stat st;
    if (stat(log_config.json_log_path, &st) == 0 && st.st_size > MAX_LOG_SIZE) {
        if (json_log_fp) {
            fclose(json_log_fp);
            json_log_fp = NULL;
        }
        char backup_name[1024];
        snprintf(backup_name, sizeof(backup_name), "%s.%ld",
                 log_config.json_log_path, time(NULL));
        rename(log_config.json_log_path, backup_name);
        fprintf(stderr, "[trackleak] Rotated log → %s\n", backup_name);
    }
}

void init_json_logging() {
    // Config not loaded yet — skip silently
    if (log_config.json_log_path[0] == '\0') return;

    static int open_failed = 0;
    if (open_failed) return;

    rotate_json_log_if_needed();
    if (!json_log_fp) {
        json_log_fp = fopen(log_config.json_log_path, "a");
        if (json_log_fp) {
            setvbuf(json_log_fp, NULL, _IOFBF, JSON_BUFFER_SIZE);
        } else {
            fprintf(stderr, "[trackleak] WARNING: Cannot open JSON log '%s': %s\n",
                    log_config.json_log_path, strerror(errno));
            open_failed = 1;
        }
    }
}

/* ==================== Hash Table Functions ==================== */

static unsigned int hash_pointer(void *ptr) {
    return ((uintptr_t)ptr >> 3) % ALLOCATION_HASH_SIZE;
}

static unsigned int hash_function_name(const char* func_name) {
    unsigned int hash = 5381;
    int c;
    while ((c = *func_name++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_TABLE_SIZE;
}

static void init_hash_table() {
    if (!hash_table_initialized) {
        for (int i = 0; i < HASH_TABLE_SIZE; i++) {
            function_hash_table[i] = -1;
        }
        hash_table_initialized = 1;
    }
}

/* ==================== Allocation Tracking ==================== */

static void track_allocation(void *ptr, size_t size, const char *func_name,
                            int line_no, const char *file_path, int stats_index) {
    unsigned int hash = hash_pointer(ptr);
    unsigned int original_hash = hash;

    while (allocation_hash_table[hash].ptr != NULL) {
        hash = (hash + 1) % ALLOCATION_HASH_SIZE;
        if (hash == original_hash) {
            fprintf(stderr, "[trackleak] Allocation table full, resetting\n");
            memset(allocation_hash_table, 0, sizeof(allocation_hash_table));
            hash = hash_pointer(ptr);
            break;
        }
    }

    allocation_hash_table[hash].ptr = ptr;
    allocation_hash_table[hash].size = size;
    allocation_hash_table[hash].func_index = stats_index;
}

allocation_info_t* find_allocation(void *ptr) {
    unsigned int hash = hash_pointer(ptr);
    unsigned int original_hash = hash;

    while (allocation_hash_table[hash].ptr != NULL) {
        if (allocation_hash_table[hash].ptr == ptr) {
            return &allocation_hash_table[hash];
        }
        hash = (hash + 1) % ALLOCATION_HASH_SIZE;
        if (hash == original_hash) break;
    }
    return NULL;
}

/* ==================== Function Statistics ==================== */

static function_stats_t* get_function_stats(const char *func_name,
                                           const char* file_path,
                                           int create_new_entry) {
    if (!func_name) return NULL;

    pthread_mutex_lock(&stats_mutex);
    init_hash_table();

    unsigned int hash = hash_function_name(func_name);
    unsigned int original_hash = hash;

    while (function_hash_table[hash] != -1) {
        int index = function_hash_table[hash];
        if (strcmp(function_stats[index].function_name, func_name) == 0) {
            pthread_mutex_unlock(&stats_mutex);
            return &function_stats[index];
        }
        hash = (hash + 1) % HASH_TABLE_SIZE;
        if (hash == original_hash) break;
    }

    if (create_new_entry && stats_count >= MAX_FUNCTIONS) {
        fprintf(stderr, "[trackleak] Function stats full (%d), resetting\n", stats_count);
        memset(function_stats, 0, sizeof(function_stats));
        memset(function_hash_table, -1, sizeof(function_hash_table));
        stats_count = 0;
        unique_functions = 0;
    }

    if (stats_count < MAX_FUNCTIONS && create_new_entry) {
        unique_functions++;
        function_stats_t* stats = &function_stats[stats_count];

        strncpy(stats->function_name, func_name, FUNCTION_NAME_LEN - 1);
        stats->function_name[FUNCTION_NAME_LEN - 1] = '\0';
        strncpy(stats->file_path, file_path, MAX_FILE_PATH - 1);
        stats->file_path[MAX_FILE_PATH - 1] = '\0';
        stats->count = 0;
        stats->total_bytes = 0;
        stats->peak_single = 0;
        stats->avg_size = 0;
        stats->sample_count = 0;
        stats->sample_total_bytes = 0;
        stats->sample_free_bytes = 0;
        stats->first_seen = time(NULL);
        stats->last_seen = stats->first_seen;

        function_hash_table[hash] = stats_count;
        stats_count++;
        pthread_mutex_unlock(&stats_mutex);
        return stats;
    }
    else if (stats_count < MAX_FUNCTIONS && !create_new_entry) {
        unique_functions++;
    }

    pthread_mutex_unlock(&stats_mutex);
    return NULL;
}

static void update_function_stats(const char* func_name, size_t size,
                                 int line_no, const char *file_path, void *ptr) {
    function_stats_t* stats = get_function_stats(func_name, file_path, 1);
    if (!stats) return;

    pthread_mutex_lock(&stats_mutex);
    stats->count++;
    stats->total_bytes += size;
    stats->last_seen = time(NULL);
    stats->line_no = line_no;

    if (size > stats->peak_single) {
        stats->peak_single = size;
    }
    stats->avg_size = stats->total_bytes / stats->count;
    pthread_mutex_unlock(&stats_mutex);
}

static void update_function_stats_deallocation(allocation_info_t* alloc_info) {
    int func_index = alloc_info->func_index;
    function_stats_t* stats = &function_stats[func_index];
    if (!stats) return;

    size_t size = alloc_info->size;
    pthread_mutex_lock(&stats_mutex);
    stats->sample_free_bytes += size;
    stats->last_seen = time(NULL);
    alloc_info->ptr = NULL;
    pthread_mutex_unlock(&stats_mutex);
}

/* ==================== Python Stack Walking ==================== */

static code_stats_t* get_python_function() {
    code_stats_t *code_t = &code_t_storage;
    memset(code_t, 0, sizeof(code_stats_t));
    strncpy(code_t->function_name, "unknown", sizeof(code_t->function_name) - 1);
    code_t->function_name[sizeof(code_t->function_name) - 1] = '\0';
    strncpy(code_t->file_path, "unknown", sizeof(code_t->file_path) - 1);

    if (in_profiler) return code_t;

    code_t->file_path[sizeof(code_t->file_path) - 1] = '\0';
    code_t->line_no = -1;

    if (!Py_IsInitialized()) return code_t;

    in_profiler = 1;
    PyGILState_STATE gstate = PyGILState_Ensure();
    PyThreadState *tstate = PyGILState_GetThisThreadState();

    if (!tstate) {
        PyGILState_Release(gstate);
        in_profiler = 0;
        return code_t;
    }

    #if PY_VERSION_HEX >= 0x030b0000  // Python 3.11+
        if (tstate->cframe && tstate->cframe->current_frame) {
            _PyInterpreterFrame *iframe = tstate->cframe->current_frame;

            if (iframe && iframe->f_code) {
                PyCodeObject *code = iframe->f_code;

                if (code->co_name && PyUnicode_Check(code->co_name)) {
                    const char* func_name = PyUnicode_AsUTF8(code->co_name);
                    if (func_name) {
                        strncpy(code_t->function_name, func_name,
                               sizeof(code_t->function_name) - 1);
                        code_t->function_name[sizeof(code_t->function_name) - 1] = '\0';
                    }
                }

                if (code->co_filename && PyUnicode_Check(code->co_filename)) {
                    const char* file_path = PyUnicode_AsUTF8(code->co_filename);
                    if (file_path) {
                        strncpy(code_t->file_path, file_path,
                               sizeof(code_t->file_path) - 1);
                        code_t->file_path[sizeof(code_t->file_path) - 1] = '\0';
                    }
                }

                code_t->line_no = code->co_firstlineno;
            }
        }
    #else
        PyFrameObject *frame = tstate->frame;

        if (frame) {
            PyCodeObject *code = PyFrame_GetCode(frame);

            if (code) {
                if (code->co_name && PyUnicode_Check(code->co_name)) {
                    const char* func_name = PyUnicode_AsUTF8(code->co_name);
                    if (func_name) {
                        strncpy(code_t->function_name, func_name,
                               sizeof(code_t->function_name) - 1);
                        code_t->function_name[sizeof(code_t->function_name) - 1] = '\0';
                    }
                }

                if (code->co_filename && PyUnicode_Check(code->co_filename)) {
                    const char* file_path = PyUnicode_AsUTF8(code->co_filename);
                    if (file_path) {
                        strncpy(code_t->file_path, file_path,
                               sizeof(code_t->file_path) - 1);
                        code_t->file_path[sizeof(code_t->file_path) - 1] = '\0';
                    }
                }

                code_t->line_no = code->co_firstlineno;
            }

            Py_XDECREF(code);
        }
    #endif

    PyGILState_Release(gstate);
    in_profiler = 0;
    return code_t;
}

/* ==================== Statistics Dumping ==================== */

void dump_memory_statistics() {
    pthread_mutex_lock(&json_mutex);
    init_json_logging();

    pthread_mutex_lock(&stats_mutex);

    int used_slots = 0;
    for (int i = 0; i < ALLOCATION_HASH_SIZE; i++) {
        if (allocation_hash_table[i].ptr != NULL) used_slots++;
    }
    time_t now = time(NULL);

    // Sort indices by total_bytes (descending)
    int sorted_indices[MAX_FUNCTIONS];
    for (int i = 0; i < stats_count; i++) {
        sorted_indices[i] = i;
    }

    for (int i = 0; i < stats_count - 1; i++) {
        for (int j = 0; j < stats_count - i - 1; j++) {
            int idx1 = sorted_indices[j];
            int idx2 = sorted_indices[j+1];
            if (function_stats[idx1].total_bytes < function_stats[idx2].total_bytes) {
                int temp = sorted_indices[j];
                sorted_indices[j] = sorted_indices[j+1];
                sorted_indices[j+1] = temp;
            }
        }
    }

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    // Prepare Elasticsearch bulk request
    char es_bulk_data[ES_BULK_BUFFER_SIZE];
    int es_bulk_len = 0;

    // Write top 20 functions to log and ES
    int limit = (stats_count > 20) ? 20 : stats_count;

    // Write column header
    if (json_log_fp && limit > 0) {
        fprintf(json_log_fp, "\n%-30s %8s %12s %8s %12s %8s %18s | %-60s\n",
                "FUNCTION", "COUNT", "TOTAL_MB", "SAMPLES", "SAMPLE_MB",
                "LINE", "FREED_MB(RET%)", "FILE");
        fprintf(json_log_fp, "%-30s %8s %12s %8s %12s %8s %18s | %-60s\n",
                "------------------------------", "--------", "------------",
                "--------", "------------", "--------",
                "------------------", "------------------------------------------------------------");
    }

    for (int i = 0; i < limit; i++) {
        int idx = sorted_indices[i];
        function_stats_t* stats = &function_stats[idx];

        double retention_pct = stats->sample_total_bytes > 0 ?
            ((stats->sample_total_bytes - stats->sample_free_bytes) * 100.0) /
             stats->sample_total_bytes : 0;

        // Write to JSON log (if open)
        if (json_log_fp) {
            fprintf(json_log_fp, "%-30s %8lu %12.2f %8lu %12.2f %8lu %12.2f(%.1f%%) | %-60s\n",
                    stats->function_name,
                    stats->count,
                    stats->total_bytes / (1024.0 * 1024.0),
                    stats->sample_count,
                    stats->sample_total_bytes / (1024.0 * 1024.0),
                    stats->line_no,
                    stats->sample_free_bytes / (1024.0 * 1024.0),
                    retention_pct,
                    stats->file_path);
        }

        // Build ES document
        if (es_config.enabled && es_bulk_len < ES_BULK_BUFFER_SIZE - 2000) {
            char time_str[64];
            struct tm *tm_info = localtime(&now);
            strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", tm_info);

            int written = snprintf(es_bulk_data + es_bulk_len,
                                 ES_BULK_BUFFER_SIZE - es_bulk_len,
                                 "{\"index\":{\"_index\":\"%s\"}}\n",
                                 es_config.index);
            es_bulk_len += written;

            written = snprintf(es_bulk_data + es_bulk_len,
                 ES_BULK_BUFFER_SIZE - es_bulk_len,
                 "{\"timestamp\":%ld,"
                 "\"time\":\"%s\","
                 "\"job_name\":\"%s\","
                 "\"hostname\":\"%s\","
                 "\"function\":\"%s\","
                 "\"file\":\"%s\","
                 "\"line\":%lu,"
                 "\"count\":%lu,"
                 "\"total_bytes\":%lu,"
                 "\"total_mb\":%.2f,"
                 "\"sample_count\":%lu,"
                 "\"sample_total_bytes\":%lu,"
                 "\"sample_total_mb\":%.2f,"
                 "\"sample_free_bytes\":%lu,"
                 "\"sample_free_mb\":%.2f,"
                 "\"retention_pct\":%.1f,"
                 "\"peak_single\":%lu,"
                 "\"avg_size\":%lu,"
                 "\"elapsed_seconds\":%ld}\n",
                 now,
                 time_str,
                 job_name,
                 hostname,
                 stats->function_name,
                 stats->file_path,
                 stats->line_no,
                 stats->count,
                 stats->total_bytes,
                 stats->total_bytes / (1024.0 * 1024.0),
                 stats->sample_count,
                 stats->sample_total_bytes,
                 stats->sample_total_bytes / (1024.0 * 1024.0),
                 stats->sample_free_bytes,
                 stats->sample_free_bytes / (1024.0 * 1024.0),
                 retention_pct,
                 stats->peak_single,
                 stats->avg_size,
                 now - profiler_start_time);
            es_bulk_len += written;
        }
    }

    if (json_log_fp) {
        fprintf(json_log_fp, "--- dump at %ld (%d functions, hash %d/%d) ---\n\n",
                now, unique_functions, used_slots, ALLOCATION_HASH_SIZE);
        fflush(json_log_fp);
    }

    // Send to Elasticsearch
    if (es_config.enabled && es_bulk_len > 0) {
        queue_bulk_for_elasticsearch(es_bulk_data, es_bulk_len);
        fprintf(stderr, "[trackleak] Queued %d bytes → ES (%s)\n",
                es_bulk_len, es_config.index);
    }

    // Reset for fresh tracking
    memset(function_stats, 0, sizeof(function_stats));
    memset(function_hash_table, -1, sizeof(function_hash_table));
    stats_count = 0;
    unique_functions = 0;
    memset(allocation_hash_table, 0, sizeof(allocation_hash_table));

    pthread_mutex_unlock(&stats_mutex);
    pthread_mutex_unlock(&json_mutex);
}

static void check_and_dump_if_needed() {
    static pthread_mutex_t dump_mutex = PTHREAD_MUTEX_INITIALIZER;
    time_t now = time(NULL);

    if (now - last_dump_time < prof_config.dump_interval) return;

    if (pthread_mutex_trylock(&dump_mutex) == 0) {
        if (now - last_dump_time >= prof_config.dump_interval) {
            last_dump_time = now;
            dump_memory_statistics();
        }
        pthread_mutex_unlock(&dump_mutex);
    }
}

/* ==================== Memory Allocation Interceptors ==================== */

void* malloc(size_t size) {
    init_real_functions();

    if (in_malloc) return real_malloc(size);
    in_malloc = 1;

    void* ptr = real_malloc(size);
    total_allocated += size;
    time_t now_ts = time(NULL);

    if (size > (size_t)prof_config.min_alloc_size && Py_IsInitialized() &&
        now_ts - job_time > prof_config.startup_delay) {

        code_stats_t* code_t = get_python_function();
        if (strcmp(code_t->function_name, "unknown") != 0) {
            log_allocation_event(EVENT_ALLOC, ptr, size,
                               code_t->function_name,
                               code_t->file_path,
                               code_t->line_no);

            update_function_stats(code_t->function_name, size,
                                code_t->line_no, code_t->file_path, ptr);

            if (++allocation_sample_counter % prof_config.sample_rate == 0) {
                function_stats_t* stats = get_function_stats(code_t->function_name,
                                                            code_t->file_path, 0);
                if (stats) {
                    pthread_mutex_lock(&stats_mutex);
                    stats->sample_count++;
                    stats->sample_total_bytes += size;
                    int stats_index = stats - function_stats;
                    track_allocation(ptr, size, code_t->function_name,
                                   code_t->line_no, code_t->file_path, stats_index);
                    pthread_mutex_unlock(&stats_mutex);
                }
            }
        }
    }

    check_and_dump_if_needed();
    in_malloc = 0;
    return ptr;
}

void free(void* ptr) {
    if (!ptr) return;
    init_real_functions();

    log_allocation_event(EVENT_FREE, ptr, 0, NULL, NULL, 0);

    allocation_info_t *alloc_info = find_allocation(ptr);
    if (alloc_info) {
        update_function_stats_deallocation(alloc_info);
    }

    real_free(ptr);
}

void* PyMem_Malloc(size_t size) {
    init_real_functions();
    void *ptr = real_pymem_alloc(size);
    total_allocated += size;
    time_t now_ts = time(NULL);

    if (size > (size_t)prof_config.min_alloc_size && Py_IsInitialized() &&
        now_ts - job_time > prof_config.startup_delay) {

        code_stats_t* code_t = get_python_function();
        if (strcmp(code_t->function_name, "unknown") != 0) {
            log_allocation_event(EVENT_ALLOC, ptr, size,
                               code_t->function_name,
                               code_t->file_path,
                               code_t->line_no);

            update_function_stats(code_t->function_name, size,
                                code_t->line_no, code_t->file_path, ptr);

            if (++allocation_sample_counter % prof_config.sample_rate == 0) {
                function_stats_t* stats = get_function_stats(code_t->function_name,
                                                            code_t->file_path, 0);
                if (stats) {
                    pthread_mutex_lock(&stats_mutex);
                    stats->sample_count++;
                    stats->sample_total_bytes += size;
                    int stats_index = stats - function_stats;
                    track_allocation(ptr, size, code_t->function_name,
                                   code_t->line_no, code_t->file_path, stats_index);
                    pthread_mutex_unlock(&stats_mutex);
                }
            }
        }
    }

    check_and_dump_if_needed();
    return ptr;
}

void PyMem_Free(void* ptr) {
    if (!ptr) return;
    init_real_functions();

    log_allocation_event(EVENT_FREE, ptr, 0, NULL, NULL, 0);

    allocation_info_t *alloc_info = find_allocation(ptr);
    if (alloc_info) {
        update_function_stats_deallocation(alloc_info);
    }
    real_pymem_alloc_free(ptr);
}

void* PyMem_Calloc(size_t nelem, size_t size) {
    init_real_functions();
    void *ptr = real_pymem_calloc(nelem, size);
    size_t total_size = nelem * size;
    total_allocated += total_size;
    time_t now_ts = time(NULL);

    if (total_size > (size_t)prof_config.min_alloc_size && Py_IsInitialized() &&
        now_ts - job_time > prof_config.startup_delay) {

        code_stats_t* code_t = get_python_function();
        if (strcmp(code_t->function_name, "unknown") != 0) {
            log_allocation_event(EVENT_ALLOC, ptr, total_size,
                               code_t->function_name,
                               code_t->file_path,
                               code_t->line_no);

            update_function_stats(code_t->function_name, total_size,
                                code_t->line_no, code_t->file_path, ptr);

            if (++allocation_sample_counter % prof_config.sample_rate == 0) {
                function_stats_t* stats = get_function_stats(code_t->function_name,
                                                            code_t->file_path, 0);
                if (stats) {
                    pthread_mutex_lock(&stats_mutex);
                    stats->sample_count++;
                    stats->sample_total_bytes += total_size;
                    int stats_index = stats - function_stats;
                    track_allocation(ptr, total_size, code_t->function_name,
                                   code_t->line_no, code_t->file_path, stats_index);
                    pthread_mutex_unlock(&stats_mutex);
                }
            }
        }
    }

    check_and_dump_if_needed();
    return ptr;
}

void* PyMem_Realloc(void* ptr, size_t new_size) {
    init_real_functions();

    if (ptr) {
        log_allocation_event(EVENT_FREE, ptr, 0, NULL, NULL, 0);
    }

    void *new_ptr = real_pymem_realloc(ptr, new_size);
    total_allocated += new_size;
    time_t now_ts = time(NULL);

    if (new_size > (size_t)prof_config.min_alloc_size && Py_IsInitialized() &&
        now_ts - job_time > prof_config.startup_delay) {

        allocation_info_t *old_alloc = find_allocation(ptr);
        size_t old_size = 0;
        int func_index = -1;

        if (old_alloc) {
            old_size = old_alloc->size;
            func_index = old_alloc->func_index;
            old_alloc->ptr = NULL;
        }

        code_stats_t* code_t = get_python_function();
        if (strcmp(code_t->function_name, "unknown") != 0) {
            log_allocation_event(EVENT_ALLOC, new_ptr, new_size,
                               code_t->function_name,
                               code_t->file_path,
                               code_t->line_no);

            if (old_alloc && func_index >= 0) {
                pthread_mutex_lock(&stats_mutex);
                function_stats[func_index].total_bytes =
                    function_stats[func_index].total_bytes - old_size + new_size;
                function_stats[func_index].last_seen = time(NULL);

                if (new_size > function_stats[func_index].peak_single) {
                    function_stats[func_index].peak_single = new_size;
                }
                pthread_mutex_unlock(&stats_mutex);
            }
            else {
                update_function_stats(code_t->function_name, new_size,
                                    code_t->line_no, code_t->file_path, new_ptr);

                if (++allocation_sample_counter % prof_config.sample_rate == 0) {
                    function_stats_t* stats = get_function_stats(code_t->function_name,
                                                                code_t->file_path, 0);
                    if (stats) {
                        pthread_mutex_lock(&stats_mutex);
                        stats->sample_count++;
                        stats->sample_total_bytes += new_size;
                        int stats_index = stats - function_stats;
                        track_allocation(new_ptr, new_size, code_t->function_name,
                                       code_t->line_no, code_t->file_path, stats_index);
                        pthread_mutex_unlock(&stats_mutex);
                    }
                }
            }
        }
    }

    check_and_dump_if_needed();
    return new_ptr;
}
