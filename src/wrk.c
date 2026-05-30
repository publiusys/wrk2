// Copyright (C) 2012 - Will Glozer.  All rights reserved.
//
// Open-loop load generator (vs. wrk/wrk2 closed-loop):
//   Closed-loop: next request only sent after previous response received.
//   Consequence: if server slows down, fewer requests/sec are sent — load
//   self-limits and queuing delays on the server are hidden from latency.
//   wrk2 corrects reported latency via Coordinated Omission but the actual
//   traffic rate is still gated on responses.
//
//   Open-loop (this file): requests go out on a fixed schedule regardless of
//   outstanding responses. Server-side queue buildup shows up directly in
//   measured latency with no approximation needed.

#include "wrk.h"
#include "script.h"
#include "main.h"
#include "hdr_histogram.h"
#include "stats.h"
#include "assert.h"
#include <math.h>

// Max recordable latency of 1 day
#define MAX_LATENCY 24L * 60 * 60 * 1000000

// Trace-driven rate schedule: rps_schedule[i] = total target RPS at experiment
// second i, pre-computed by scaling the full trace to fit cfg.duration.
// NULL when -f is not used (fixed rate mode).
static uint64_t *rps_schedule  = NULL;
static uint64_t  schedule_len  = 0;

// Reads path (timestamp,rps CSV), averages every (trace_len/duration_s) rows
// into one slot, producing a schedule of exactly duration_s entries.
static void load_and_scale_trace(const char *path, uint64_t duration_s) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open trace file: %s\n", path); exit(1); }

    // Pass 1: count data points
    uint64_t count = 0;
    int ts, rps_val;
    while (fscanf(f, "%d,%d\n", &ts, &rps_val) == 2) count++;
    rewind(f);

    // Load raw trace into a temporary array
    uint64_t *trace = malloc(count * sizeof(uint64_t));
    if (!trace) { fprintf(stderr, "out of memory loading trace\n"); exit(1); }
    uint64_t trace_len = 0;
    while (fscanf(f, "%d,%d\n", &ts, &rps_val) == 2)
        trace[trace_len++] = (uint64_t)(rps_val > 0 ? rps_val : 1);
    fclose(f);

    // Allocate output schedule: one RPS value per experiment second
    schedule_len  = duration_s;
    rps_schedule  = malloc(schedule_len * sizeof(uint64_t));
    if (!rps_schedule) { fprintf(stderr, "out of memory for schedule\n"); exit(1); }

    // Scale: each experiment second covers (trace_len / duration_s) trace rows.
    // Average those rows to produce one representative RPS for that second.
    double scale = (double)trace_len / (double)duration_s;
    for (uint64_t i = 0; i < schedule_len; i++) {
        uint64_t lo = (uint64_t)floor(i       * scale);
        uint64_t hi = (uint64_t)floor((i + 1) * scale);
        if (hi > trace_len) hi = trace_len;
        if (lo >= trace_len) lo = trace_len - 1;
        uint64_t sum = 0;
        for (uint64_t j = lo; j < hi; j++) sum += trace[j];
        rps_schedule[i] = (hi > lo) ? sum / (hi - lo) : trace[lo];
        if (rps_schedule[i] == 0) rps_schedule[i] = 1;
    }

    free(trace);
    uint64_t smin = rps_schedule[0], smax = rps_schedule[0];
    for (uint64_t i = 1; i < schedule_len; i++) {
        if (rps_schedule[i] < smin) smin = rps_schedule[i];
        if (rps_schedule[i] > smax) smax = rps_schedule[i];
    }
    printf("Trace: %"PRIu64" points -> %"PRIu64"s schedule (%.1fx compression)  "
           "RPS min=%"PRIu64" max=%"PRIu64"\n",
           trace_len, schedule_len, scale, smin, smax);
}

// [Twitter cache trace] -S / --print-schedule debug helper.
// Prints every entry of the computed (and optionally maxrps-scaled) schedule,
// one line per second:  <second> <rps>
// Pipe to gnuplot or awk to verify the shape before committing to a full run.
// Exits immediately after printing so no load is generated.
static void print_rps_schedule() {
    if (!rps_schedule) {
        fprintf(stderr, "No schedule loaded (use -f to load a trace file)\n");
        return;
    }

    // Header summary
    uint64_t smin = rps_schedule[0], smax = rps_schedule[0];
    uint64_t sum  = 0;
    for (uint64_t i = 0; i < schedule_len; i++) {
        if (rps_schedule[i] < smin) smin = rps_schedule[i];
        if (rps_schedule[i] > smax) smax = rps_schedule[i];
        sum += rps_schedule[i];
    }
    printf("# schedule entries : %"PRIu64"\n", schedule_len);
    printf("# RPS min / mean / max : %"PRIu64" / %"PRIu64" / %"PRIu64"\n",
           smin, sum / schedule_len, smax);
    printf("# second rps\n");

    // One data line per second — machine-readable for easy piping
    for (uint64_t i = 0; i < schedule_len; i++)
        printf("%"PRIu64" %"PRIu64"\n", i, rps_schedule[i]);
}

// Raw per-request latency in microseconds, indexed [thread][request_seq].
// Populated only with -P flag, capped at MAXL=1,000,000 entries per thread.
// Separate from the HDR histogram used for summary stats — both record the
// same actual_latency_timing value, but this array preserves arrival order
// (enabling latency-over-time plots) whereas the histogram is lossy/bucketed.
uint64_t raw_latency[MAXTHREADS][MAXL];

static struct config {
    uint64_t threads;
    uint64_t connections;
    int dist; //0: fixed; 1: exp; 2: normal; 3: zipf
    uint64_t duration;
    uint64_t timeout;
    uint64_t pipeline;
    uint64_t rate;
    uint64_t delay_ms;
    bool     latency;
    bool     dynamic;
    bool     record_all_responses;
    bool     print_all_responses;
    bool     print_realtime_latency;
    char    *trace_file;     // -f: path to timestamp,rps CSV; drives varying rate
    uint64_t maxrps;         // --maxrps: scale schedule so its peak equals this value;
                             //   every entry is multiplied by (maxrps / schedule_max)
    bool     print_schedule; // [Twitter cache trace] -S: print full schedule and exit
    char    *script;
    SSL_CTX *ctx;
} cfg;

static struct {
    stats *requests;
    pthread_mutex_t mutex;
} statistics;

static struct sock sock = {
    .connect  = sock_connect,
    .close    = sock_close,
    .read     = sock_read,
    .write    = sock_write,
    .readable = sock_readable
};

static struct http_parser_settings parser_settings = {
    .on_message_complete = response_complete
};

static volatile sig_atomic_t stop = 0;

// Forward declaration: update_rate is registered from inside calibrate() but
// defined later in the file.
static int update_rate(aeEventLoop *loop, long long id, void *data);

static void handler(int sig) {
    stop = 1;
}

static void usage() {
    printf("Usage: wrk <options> <url>                                       \n"
           "  Options:                                                       \n"
           "    -c, --connections <N>  Connections to keep open              \n"
           "    -D, --dist        <S>  fixed, exp, norm, zipf                \n"
           "    -P                     Print each request's latency          \n"
           "    -p                     Print 99th latency every 0.2s to file \n"
           "    -d, --duration    <T>  Duration of test                      \n"
           "    -t, --threads     <N>  Number of threads to use              \n"
           "                                                                 \n"
           "    -s, --script      <S>  Load Lua script file                  \n"
           "    -H, --header      <H>  Add header to request                 \n"
           "    -L  --latency          Print latency statistics              \n"
           "    -T  --timeout     <T>  Socket/request timeout                \n"
           "    -B, --batch_latency    Measure latency of whole              \n"
           "                           batches of pipelined ops              \n"
           "                           (as opposed to each op)               \n"
           "    -v, --version          Print version details                 \n"
           "    -R, --rate        <T>  work rate (throughput)                \n"
           "                           in requests/sec (total)               \n"
           "                           [Required unless -f is used]          \n"
           "    -f, --trace       <F>  CSV file (timestamp,rps) to drive     \n"
           "                           rate dynamically; trace is scaled to  \n"
           "                           fit the -d duration automatically     \n"
           "    -M, --maxrps      <N>  scale trace peak to N req/s           \n"
           "                           (preserves relative shape)            \n"
           "    -S, --print-schedule   print full RPS schedule and exit      \n"
           "                           (dry run to verify -f / -M output)   \n"
           "                                                                 \n"
           "                                                                 \n"
           "  Numeric arguments may include a SI unit (1k, 1M, 1G)           \n"
           "  Time arguments may include a time unit (2s, 2m, 2h)            \n");
}

int main(int argc, char **argv) {
    char *url, **headers = zmalloc(argc * sizeof(char *));
    struct http_parser_url parts = {};

    if (parse_args(&cfg, &url, &parts, headers, argc, argv)) {
        usage();
        exit(1);
    }

    // If a trace file was given, pre-compute the per-second RPS schedule.
    // Must happen before threads start so rps_schedule is ready at calibration.
    if (cfg.trace_file) {
        load_and_scale_trace(cfg.trace_file, cfg.duration);

        // --maxrps: find the peak in the computed schedule and rescale every
        // entry proportionally so that peak == maxrps.  All relative shapes
        // (diurnal curve, spikes) are preserved; only the absolute magnitude
        // is adjusted.  Useful for targeting a specific server capacity.
        if (cfg.maxrps > 0) {
            uint64_t schedule_max = 0;
            for (uint64_t i = 0; i < schedule_len; i++)
                if (rps_schedule[i] > schedule_max)
                    schedule_max = rps_schedule[i];
            printf("Scaling schedule peak %"PRIu64" -> %"PRIu64" RPS\n",
                   schedule_max, cfg.maxrps);
            for (uint64_t i = 0; i < schedule_len; i++) {
                rps_schedule[i] = (uint64_t)(
                    (double)rps_schedule[i] * cfg.maxrps / schedule_max);
                if (rps_schedule[i] == 0) rps_schedule[i] = 1;
            }
        }

        // [Twitter cache trace] -S: print the final schedule (post maxrps
        // scaling) and exit so the user can verify values before a real run.
        if (cfg.print_schedule) {
            print_rps_schedule();
            exit(0);
        }
    }

    char *schema  = copy_url_part(url, &parts, UF_SCHEMA);
    char *host    = copy_url_part(url, &parts, UF_HOST);
    char *port    = copy_url_part(url, &parts, UF_PORT);
    char *service = port ? port : schema;

    if (!strncmp("https", schema, 5)) {
        if ((cfg.ctx = ssl_init()) == NULL) {
            fprintf(stderr, "unable to initialize SSL\n");
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        sock.connect  = ssl_connect;
        sock.close    = ssl_close;
        sock.read     = ssl_read;
        sock.write    = ssl_write;
        sock.readable = ssl_readable;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  SIG_IGN);

    pthread_mutex_init(&statistics.mutex, NULL);
    statistics.requests = stats_alloc(10);
    thread *threads = zcalloc(cfg.threads * sizeof(thread));

    hdr_init(1, MAX_LATENCY, 3, &(statistics.requests->histogram));

    lua_State *L = script_create(cfg.script, url, headers);
    if (!script_resolve(L, host, service)) {
        char *msg = strerror(errno);
        fprintf(stderr, "unable to connect to %s:%s %s\n", host, service, msg);
        exit(1);
    }

    uint64_t connections = cfg.connections / cfg.threads;
    // throughput here is req/sec per thread; divided further per connection in thread_main.
    uint64_t throughput = cfg.rate / cfg.threads;
    uint64_t stop_at     = time_us() + (cfg.duration * 1000000);
    for (uint64_t i = 0; i < cfg.threads; i++) {
        thread *t = &threads[i];
        t->tid           = i;
        t->loop          = aeCreateEventLoop(10 + cfg.connections * 3);
        t->connections   = connections;
        t->throughput    = throughput;
        t->stop_at       = stop_at;
        t->sent          = 0;
        t->complete      = 0;
        t->monitored     = 0;
        t->target        = throughput/10; //Shuang
        t->accum_latency = 0;
        t->L = script_create(cfg.script, url, headers);
        script_init(L, t, argc - optind, &argv[optind]);
        if (i == 0) {
            cfg.pipeline = script_verify_request(t->L);
            cfg.dynamic = !script_is_static(t->L);
            if (script_want_response(t->L)) {
                parser_settings.on_header_field = header_field;
                parser_settings.on_header_value = header_value;
                parser_settings.on_body         = response_body;
            }
        }
        if (!t->loop || pthread_create(&t->thread, NULL, &thread_main, t)) {
            char *msg = strerror(errno);
            fprintf(stderr, "unable to create thread %"PRIu64": %s\n", i, msg);
            exit(2);
        }
    }

    struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags   = 0,
    };
    sigfillset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    char *time = format_time_s(cfg.duration);
    printf("Running %s test @ %s\n", time, url);
    printf("  %"PRIu64" threads and %"PRIu64" connections\n",
            cfg.threads, cfg.connections);

    uint64_t start    = time_us();
    uint64_t complete = 0;
    uint64_t sent = 0;
    uint64_t bytes    = 0;
    errors errors     = { 0 };

    struct hdr_histogram* latency_histogram;
    struct hdr_histogram* real_latency_histogram;
    hdr_init(1, MAX_LATENCY, 3, &latency_histogram);
    hdr_init(1, MAX_LATENCY, 3, &real_latency_histogram);

    for (uint64_t i = 0; i < cfg.threads; i++) {
        thread *t = &threads[i];
        pthread_join(t->thread, NULL);
    }

    uint64_t runtime_us = time_us() - start;

    for (uint64_t i = 0; i < cfg.threads; i++) {
        thread *t = &threads[i];
        complete += t->complete;
        sent += t->sent;
        bytes    += t->bytes;

        errors.connect += t->errors.connect;
        errors.read    += t->errors.read;
        errors.write   += t->errors.write;
        errors.timeout += t->errors.timeout;
        errors.status  += t->errors.status;

        hdr_add(latency_histogram, t->latency_histogram);
        hdr_add(real_latency_histogram, t->real_latency_histogram);
        
        if (cfg.print_all_responses) {
            char filename[10] = {0};
            sprintf(filename, "%" PRIu64 ".txt", i);
            FILE* ff = fopen(filename, "w");
            uint64_t nnum=MAXL;
            if ((t->complete) < nnum) nnum = t->complete;
            for (uint64_t j=1; j < nnum; ++j)
                fprintf(ff, "%" PRIu64 "\n", raw_latency[i][j]);
            fclose(ff);
        }
    }

    long double runtime_s   = runtime_us / 1000000.0;
    long double sent_per_s = sent / runtime_s;
    long double req_per_s   = complete   / runtime_s;
    long double bytes_per_s = bytes      / runtime_s;

    stats *latency_stats = stats_alloc(10);
    latency_stats->min = hdr_min(latency_histogram);
    latency_stats->max = hdr_max(latency_histogram);
    latency_stats->histogram = latency_histogram;

    print_stats_header();
    print_stats("Latency", latency_stats, format_time_us);
    print_stats("Req/Sec", statistics.requests, format_metric);

    if (cfg.latency) {
        print_hdr_latency(latency_histogram,
                "Recorded Latency");
        printf("----------------------------------------------------------\n");
    }

    char *runtime_msg = format_time_us(runtime_us);

    printf("  %"PRIu64" completed requests in %s, %sB read\n",
            complete, runtime_msg, format_binary(bytes));
    if (errors.connect || errors.read || errors.write || errors.timeout) {
        printf("  Socket errors: connect %d, read %d, write %d, timeout %d\n",
               errors.connect, errors.read, errors.write, errors.timeout);
    }

    if (errors.status) {
        printf("  Non-2xx or 3xx responses: %d\n", errors.status);
    }

    // Throughput (completed) < Load (sent) when requests are still in-flight at
    // stop_at. The gap grows under high load. Latency histogram is also
    // right-censored: responses not yet received at stop_at are dropped in
    // response_complete, so the highest-latency tail is missing from stats.
    printf("Completed Requests/sec (Throughput): %9.2Lf\n", req_per_s);
    printf("Sent Requests/sec (Load): %9.2Lf\n", sent_per_s);
    // printf("Actual sent Requests %"PRIu64"\n", sent);
    printf("Transfer/sec: %10sB\n", format_binary(bytes_per_s));

    if (script_has_done(L)) {
        script_summary(L, runtime_us, complete, bytes);
        script_errors(L, &errors);
        script_done(L, latency_stats, statistics.requests);
    }

    return 0;
}

void *thread_main(void *arg) {
    thread *thread = arg;
    aeEventLoop *loop = thread->loop;

    thread->cs = zcalloc(thread->connections * sizeof(connection));
    tinymt64_init(&thread->rand, time_us());
    hdr_init(1, MAX_LATENCY, 3, &thread->latency_histogram);
    hdr_init(1, MAX_LATENCY, 3, &thread->real_latency_histogram);

    char *request = NULL;
    size_t length = 0;

    if (!cfg.dynamic) {
        script_request(thread->L, &request, &length);
    }
    
    thread->ff = NULL;
    if ((cfg.print_realtime_latency) && (thread->tid == 0)) {
        char filename[50];
        snprintf(filename, 50, "%" PRIu64 ".txt", thread->tid);
        thread->ff = fopen(filename, "w");
    }


    // Convert to req/µs per connection: (req/s per thread) / 1e6 / connections.
    // e.g. 1000 req/s total, 2 threads, 10 conns/thread → 0.00005 req/µs/conn.
    double throughput = (thread->throughput / 1000000.0) / thread->connections;

    connection *c = thread->cs;

    for (uint64_t i = 0; i < thread->connections; i++, c++) {
        c->thread     = thread;
        c->ssl        = cfg.ctx ? SSL_new(cfg.ctx) : NULL;
        c->request    = request;
        c->length     = length;
        // Mean inter-arrival time in µs for this connection: 1 / (req/s per conn).
        c->interval   = 1000000*thread->connections/thread->throughput;
        c->throughput = throughput;
        c->complete   = 0;
        c->estimate   = 0;
        c->sent       = 0;
        // Stagger connects 1 msec apart within thread:
        aeCreateTimeEvent(loop, i, delayed_initial_connect, c, NULL);
    }

    uint64_t calibrate_delay = CALIBRATE_DELAY_MS + (thread->connections);
    uint64_t timeout_delay = TIMEOUT_INTERVAL_MS + (thread->connections);

    aeCreateTimeEvent(loop, calibrate_delay, calibrate, thread, NULL);
    aeCreateTimeEvent(loop, timeout_delay, check_timeouts, thread, NULL);

    thread->start = time_us();
    aeMain(loop);

    aeDeleteEventLoop(loop);
    zfree(thread->cs);
    if (cfg.print_realtime_latency && thread->tid == 0) fclose(thread->ff);

    return NULL;
}

static int connect_socket(thread *thread, connection *c) {
    struct addrinfo *addr = thread->addr;
    struct aeEventLoop *loop = thread->loop;
    int fd, flags;

    fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (connect(fd, addr->ai_addr, addr->ai_addrlen) == -1) {
        if (errno != EINPROGRESS) goto error;
    }

    flags = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));

    flags = AE_READABLE | AE_WRITABLE;
    if (aeCreateFileEvent(loop, fd, flags, socket_connected, c) == AE_OK) {
        c->parser.data = c;
        c->fd = fd;
        return fd;
    }

  error:
    thread->errors.connect++;
    close(fd);
    return -1;
}

static int reconnect_socket(thread *thread, connection *c) {
    aeDeleteFileEvent(thread->loop, c->fd, AE_WRITABLE | AE_READABLE);
    sock.close(c);
    close(c->fd);
    return connect_socket(thread, c);
}

static int delayed_initial_connect(aeEventLoop *loop, long long id, void *data) {
    connection* c = data;
    c->thread_start = time_us();
    c->thread_next  = c->thread_start;
    connect_socket(c->thread, c);
    return AE_NOMORE;
}

static int calibrate(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;

    long double mean = hdr_mean(thread->latency_histogram);
    long double latency = hdr_value_at_percentile(
            thread->latency_histogram, 90.0) / 1000.0L;
    long double interval = MAX(latency * 2, 10);

    if (mean == 0) return CALIBRATE_DELAY_MS;

    thread->mean     = (uint64_t) mean;
    hdr_reset(thread->latency_histogram);

    thread->start    = time_us();
    thread->interval = interval;
    thread->requests = 0;

    printf("  Thread calibration: mean lat.: %.3fms, rate sampling interval: %dms\n",
            (thread->mean)/1000.0,
            thread->interval);

    aeCreateTimeEvent(loop, thread->interval, sample_rate, thread, NULL);

    // Start trace-driven rate updates now that calibration is complete.
    // schedule_start_us anchors elapsed-second calculations in update_rate.
    if (rps_schedule) {
        thread->schedule_start_us = time_us();
        aeCreateTimeEvent(loop, 0, update_rate, thread, NULL);
    }

    return AE_NOMORE;
}

// Fires every 1000ms. Looks up the RPS for the current experiment second from
// the pre-computed schedule, then updates c->interval on every connection.
// When rate increases, thread_next is reset to now to avoid a catch-up burst.
static int update_rate(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;
    uint64_t elapsed_s = (time_us() - thread->schedule_start_us) / 1000000;

    if (elapsed_s >= schedule_len) return AE_NOMORE;

    uint64_t total_rps      = rps_schedule[elapsed_s];
    uint64_t per_thread_rps = total_rps / cfg.threads;
    if (per_thread_rps == 0) per_thread_rps = 1;

    // Print one line per second so the live rate progression is visible.
    // Only thread 0 prints to avoid duplicate lines across threads.
    if (thread->tid == 0) {
        printf("[trace %5"PRIu64"s / %"PRIu64"s]  target RPS: %"PRIu64"\n",
               elapsed_s, schedule_len, total_rps);
        fflush(stdout);
    }

    uint64_t now = time_us();
    connection *c = thread->cs;
    for (uint64_t i = 0; i < thread->connections; i++, c++) {
        uint64_t new_interval = 1000000 * thread->connections / per_thread_rps;
        if (new_interval < c->interval) {
            // Rate increased: reset next-send time so we don't burst to catch up.
            c->thread_next = now;
        }
        c->interval = new_interval;
    }
    thread->throughput = per_thread_rps;

    return 1000;  // re-fire in 1000ms (one schedule step)
}

static int check_timeouts(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;
    connection *c  = thread->cs;
    uint64_t now   = time_us();

    uint64_t maxAge = now - (cfg.timeout * 1000);

    for (uint64_t i = 0; i < thread->connections; i++, c++) {
        if (maxAge > c->start) {
            thread->errors.timeout++;
        }
    }

    if (stop || now >= thread->stop_at) {
        aeStop(loop);
    }

    return TIMEOUT_INTERVAL_MS;
}

static int sample_rate(aeEventLoop *loop, long long id, void *data) {
    thread *thread = data;

    uint64_t elapsed_ms = (time_us() - thread->start) / 1000;
    uint64_t requests = (thread->requests / (double) elapsed_ms) * 1000;

    pthread_mutex_lock(&statistics.mutex);
    stats_record(statistics.requests, requests);
    pthread_mutex_unlock(&statistics.mutex);

    thread->requests = 0;
    thread->start    = time_us();

    return thread->interval;
}

static int header_field(http_parser *parser, const char *at, size_t len) {
    connection *c = parser->data;
    if (c->state == VALUE) {
        *c->headers.cursor++ = '\0';
        c->state = FIELD;
    }
    buffer_append(&c->headers, at, len);
    return 0;
}

static int header_value(http_parser *parser, const char *at, size_t len) {
    connection *c = parser->data;
    if (c->state == FIELD) {
        *c->headers.cursor++ = '\0';
        c->state = VALUE;
    }
    buffer_append(&c->headers, at, len);
    return 0;
}

static int response_body(http_parser *parser, const char *at, size_t len) {
    connection *c = parser->data;
    buffer_append(&c->body, at, len);
    return 0;
}

// gen_next selects the inter-arrival time (µs) before the next request on
// this connection. All distributions share the same mean (c->interval) but
// differ in variance and shape:
//   fixed: deterministic, zero variance — predictable but unrealistic.
//   exp:   exponential (Poisson arrivals) — memoryless, models independent
//          clients; standard assumption in queuing theory (M/M/1).
//   zipf:  heavy-tailed, bursty — models file access / social media patterns
//          where most gaps are short but occasional long pauses occur.
// At the same mean rate, fixed shows the best tail latency; exp and zipf
// expose more server-side queue buildup because of their burst structure.

uint64_t gen_zipf(connection *conn)
{
    static int first = 1;      // Static first time flag
    static double c = 0;          // Normalization constant
    static double scalar = 0;
    double z;                     // Uniform random number (0 < z < 1)
    double sum_prob;              // Sum of probabilities
    double zipf_value;            // Computed exponential value to be returned
    int n = 100;
    double alpha = 3;

    // Compute normalization constant on first call only
    if (first == 1) {
        for (int i=1; i<=n; i++)
            c = c + (1.0 / pow((double) i, alpha));
        c = 1.0 / c;
        for (int i=1; i<=n; i++) {
            double prob = c / pow((double) i, alpha);
            scalar = scalar + i*prob;
        }
        scalar = conn->interval / scalar;
        first = 0;
    }

  // Pull a uniform random number (0 < z < 1)
    do {
        z = (double)rand()/RAND_MAX;
    } while ((z == 0) || (z == 1));

    // Map z to the value
    sum_prob = 0;
    for (int i=1; i<=n; i++) {
        sum_prob = sum_prob + c / pow((double) i, alpha);
        if (sum_prob >= z) {
            zipf_value = i;
            break;
        }
    }
    return (uint64_t)(zipf_value*scalar);
}

uint64_t gen_exp(connection *c) {
    double z;
    double exp_value;
    do {
        z = (double)rand()/RAND_MAX;
    } while ((z == 0) || (z == 1));
    exp_value = (-log(z)*(c->interval));
    //printf("%.2f %"PRIu64"\n", exp_value, (uint64_t)(exp_value));
    return (uint64_t)(exp_value);
}

uint64_t gen_next(connection *c) {
    if (cfg.dist == 0) { // FIXED
        return c->interval;
    }
    else if (cfg.dist == 1) { // EXP
        return gen_exp(c);
    }
    else if (cfg.dist == 2) {
    }
    else if (cfg.dist == 3) {
       return gen_zipf(c);
    }
    return 0;
}

// Returns µs to wait before sending the next request, or 0 if it's time now.
// KEY open-loop property: thread_next advances based on c->estimate (a
// forward-looking send counter), NOT on c->complete (responses received).
// In the closed-loop version this was keyed on completions, so the schedule
// stalled whenever the server was slow. Here the schedule ticks forward
// unconditionally — the server's latency has no effect on the send rate.
static uint64_t usec_to_next_send(connection *c) {
    uint64_t now = time_us();
    //c->thread_next = c->thread_start + c->sent/c->throughput;
    //printf("%f\n", 1/c->throughput);
    if (c->estimate <= c->sent) {
        ++c->estimate;
        c->thread_next += gen_next(c);  // advance schedule by one inter-arrival interval
    }
    if ((c->thread_next) > now)
        return c->thread_next - now;
    else
        return 0;
}

static int delay_request(aeEventLoop *loop, long long id, void *data) {
    connection* c = data;
    thread *thread = c->thread;
    thread->sent++;  // counts requests dispatched (used for "Sent Requests/sec (Load)")
    uint64_t time_usec_to_wait = usec_to_next_send(c);
    if (time_usec_to_wait) {
        return round((time_usec_to_wait / 1000.0L) + 0.5); /* don't send, wait */
    }
    aeCreateFileEvent(c->thread->loop, c->fd, AE_WRITABLE, socket_writeable, c);
    return AE_NOMORE;
}

static int response_complete(http_parser *parser) {
    connection *c = parser->data;
    thread *thread = c->thread;
    uint64_t now = time_us();
    int status = parser->status_code;

    thread->complete++;
    //printf("complete %"PRIu64"\n", thread->complete);
    thread->requests++;

    if (status > 399) {
        thread->errors.status++;
    }

    if (c->headers.buffer) {
        *c->headers.cursor++ = '\0';
        script_response(thread->L, status, &c->headers, &c->body);
        c->state = FIELD;
    }

    // Responses arriving after stop_at are silently dropped here — not counted
    // in thread->complete and not recorded in the histogram. This right-censors
    // the latency distribution: the slowest requests (still in-flight at cutoff)
    // are excluded, making tail latency look better than reality under high load.
    if (now >= thread->stop_at) {
        aeStop(thread->loop);
        goto done;
    }

    // Record if needed, either last in batch or all, depending in cfg:
    if (cfg.record_all_responses) {
        // actual_latency_timing: wall-clock µs from first byte written to socket
        // until on_message_complete fires — true end-to-end RTT as seen by client.
        assert(now > c->actual_latency_start[c->complete & MAXO] );
        uint64_t actual_latency_timing = now - c->actual_latency_start[c->complete & MAXO];
        if(cfg.print_all_responses) {
            printf("%s %"PRIu64" @ %"PRIu64" took %"PRIu64" us\n",
                status > 399 ? "failed" : "complete",
                c->complete, now, actual_latency_timing);
        }
        hdr_record_value(thread->latency_histogram, actual_latency_timing);
        hdr_record_value(thread->real_latency_histogram, actual_latency_timing);
    
        thread->monitored++;
        thread->accum_latency += actual_latency_timing;
        if (thread->monitored == thread->target) {       
            if (cfg.print_realtime_latency && thread->tid == 0) {
                fprintf(thread->ff, "%" PRId64 "\n", hdr_value_at_percentile(thread->real_latency_histogram, 99));
                fflush(thread->ff);
            }
            thread->monitored = 0;
            thread->accum_latency = 0;
            hdr_reset(thread->real_latency_histogram);
        }
        if (cfg.print_all_responses && ((thread->complete) < MAXL)) 
            raw_latency[thread->tid][thread->complete] = actual_latency_timing;
    }

    // Count all responses (including pipelined ones:)
    c->complete++;
    if (!http_should_keep_alive(parser)) {
        reconnect_socket(thread, c);
        goto done;
    }

    http_parser_init(parser, HTTP_RESPONSE);

  done:
    return 0;
}

static void socket_connected(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;

    switch (sock.connect(c)) {
        case OK:    break;
        case ERROR: goto error;
        case RETRY: return;
    }

    http_parser_init(&c->parser, HTTP_RESPONSE);
    c->written = 0;

    aeCreateFileEvent(c->thread->loop, fd, AE_READABLE, socket_readable, c);

    aeCreateFileEvent(c->thread->loop, fd, AE_WRITABLE, socket_writeable, c);

    return;

  error:
    c->thread->errors.connect++;
    reconnect_socket(c->thread, c);

}

static void socket_writeable(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;
    thread *thread = c->thread;

    if (!c->written) {
        uint64_t time_usec_to_wait = usec_to_next_send(c);
        if (time_usec_to_wait) {
            int msec_to_wait = round((time_usec_to_wait / 1000.0L) + 0.5);

            // Not yet time to send. Delay:
            aeDeleteFileEvent(loop, fd, AE_WRITABLE);
            aeCreateTimeEvent(
                    thread->loop, msec_to_wait, delay_request, c, NULL);
            return;
        }
    }

    if (!c->written && cfg.dynamic) {
        script_request(thread->L, &c->request, &c->length);
    }

    char  *buf = c->request + c->written;
    size_t len = c->length  - c->written;
    size_t n;


    switch (sock.write(c, buf, len, &n)) {
        case OK:    break;
        case ERROR: goto error;
        case RETRY: return;
    }
    if (!c->written) {
        c->start = time_us();
        // Circular buffer: stores send timestamp for each in-flight request,
        // indexed by (sent % MAXO). Multiple requests can be outstanding on one
        // connection simultaneously (open-loop), so a single scalar won't do.
        // Matched against (complete % MAXO) in response_complete.
        c->actual_latency_start[c->sent & MAXO] = c->start;
        //if (c->sent) printf("sent %"PRIu64" @ %"PRIu64"\n", c->sent, c->actual_latency_start[c->sent & MAXO]-c->actual_latency_start[(c->sent-1) & MAXO]);
        //if (c->sent) printf("sent %"PRIu64" @ %"PRIu64"\n", c->sent, c->start);
        c->sent ++;
    }

    c->written += n;
    if (c->written == c->length) {
        c->written = 0;
        aeDeleteFileEvent(loop, fd, AE_WRITABLE);
        // CRITICAL open-loop change: immediately re-register the writable event
        // so the next request is scheduled without waiting for a response.
        // In the closed-loop version this re-registration only happened inside
        // response_complete once all pending responses had been received.
        aeCreateFileEvent(thread->loop, c->fd, AE_WRITABLE, socket_writeable, c);
    }
    return;

  error:
    thread->errors.write++;
    reconnect_socket(thread, c);
}


static void socket_readable(aeEventLoop *loop, int fd, void *data, int mask) {
    connection *c = data;
    size_t n;

    do {
        switch (sock.read(c, &n)) {
            case OK:    break;
            case ERROR: goto error;
            case RETRY: return;
        }

        if (http_parser_execute(&c->parser, &parser_settings, c->buf, n) != n) goto error;
        c->thread->bytes += n;
    } while (n == RECVBUF && sock.readable(c) > 0);

    return;

  error:
    c->thread->errors.read++;
    reconnect_socket(c->thread, c);
}

static uint64_t time_us() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_sec * 1000000) + t.tv_usec;
}

static char *copy_url_part(char *url, struct http_parser_url *parts, enum http_parser_url_fields field) {
    char *part = NULL;

    if (parts->field_set & (1 << field)) {
        uint16_t off = parts->field_data[field].off;
        uint16_t len = parts->field_data[field].len;
        part = zcalloc(len + 1 * sizeof(char));
        memcpy(part, &url[off], len);
    }

    return part;
}

static struct option longopts[] = {
    { "connections",    required_argument, NULL, 'c' },
    { "duration",       required_argument, NULL, 'd' },
    { "threads",        required_argument, NULL, 't' },
    { "script",         required_argument, NULL, 's' },
    { "header",         required_argument, NULL, 'H' },
    { "latency",        no_argument,       NULL, 'L' },
    { "batch_latency",  no_argument,       NULL, 'B' },
    { "timeout",        required_argument, NULL, 'T' },
    { "help",           no_argument,       NULL, 'h' },
    { "version",        no_argument,       NULL, 'v' },
    { "rate",           required_argument, NULL, 'R' },
    { "dist",           required_argument, NULL, 'D' },
    { "trace",          required_argument, NULL, 'f' },
    { "maxrps",         required_argument, NULL, 'M' },
    { "print-schedule", no_argument,       NULL, 'S' },
    { NULL,             0,                 NULL,  0  }
};

static int parse_args(struct config *cfg, char **url, struct http_parser_url *parts, char **headers, int argc, char **argv) {
    int c;
    char **header = headers;

    memset(cfg, 0, sizeof(struct config));
    cfg->threads     = 2;
    cfg->connections = 10;
    cfg->duration    = 10;
    cfg->timeout     = SOCKET_TIMEOUT_MS;
    cfg->rate        = 0;
    cfg->record_all_responses = true;
    cfg->print_all_responses = false;
    cfg->print_realtime_latency = false;
    cfg->dist = 0;

    while ((c = getopt_long(argc, argv, "t:c:d:s:D:H:T:R:f:M:SLPpBv?", longopts, NULL)) != -1) {
        switch (c) {
            case 't':
                if (scan_metric(optarg, &cfg->threads)) return -1;
                break;
            case 'c':
                if (scan_metric(optarg, &cfg->connections)) return -1;
                break;
            case 'D':
                if (!strcmp(optarg, "fixed"))  
                    cfg->dist = 0;
                if (!strcmp(optarg, "exp")) 
                    cfg->dist = 1;
                if (!strcmp(optarg, "norm")) 
                    cfg->dist = 2;
                if (!strcmp(optarg, "zipf")) 
                    cfg->dist = 3;
                break;
            case 'd':
                if (scan_time(optarg, &cfg->duration)) return -1;
                break;
            case 's':
                cfg->script = optarg;
                break;
            case 'H':
                *header++ = optarg;
                break;
            case 'P': /* Shuang: print each requests's latency */
                cfg->print_all_responses = true;
                break;
            case 'p': /* Shuang: print avg latency every 0.2s */
                cfg->print_realtime_latency = true;
                break;
            case 'L':
                cfg->latency = true;
                break;
            case 'B':
                cfg->record_all_responses = false;
                break;
            case 'T':
                if (scan_time(optarg, &cfg->timeout)) return -1;
                cfg->timeout *= 1000;
                break;
            case 'R':
                if (scan_metric(optarg, &cfg->rate)) return -1;
                break;
            case 'f':
                cfg->trace_file = optarg;
                break;
            case 'M':
                if (scan_metric(optarg, &cfg->maxrps)) return -1;
                break;
            case 'S':
                cfg->print_schedule = true;
                break;
            case 'v':
                printf("wrk %s [%s] ", VERSION, aeGetApiName());
                printf("Copyright (C) 2012 Will Glozer\n");
                break;
            case 'h':
            case '?':
            case ':':
            default:
                return -1;
        }
    }

    if (optind == argc || !cfg->threads || !cfg->duration) return -1;

    if (!script_parse_url(argv[optind], parts)) {
        fprintf(stderr, "invalid URL: %s\n", argv[optind]);
        return -1;
    }

    if (!cfg->connections || cfg->connections < cfg->threads) {
        fprintf(stderr, "number of connections must be >= threads\n");
        return -1;
    }

    // -R is required unless -f (trace file) is provided.
    // In trace mode, -R sets the initial warmup rate; the trace overrides it
    // after calibration. If -R is omitted with -f, default to 100 req/s.
    if (cfg->rate == 0) {
        if (cfg->trace_file) {
            cfg->rate = 100;
        } else {
            fprintf(stderr,
                    "Throughput MUST be specified with --rate/-R, "
                    "or use --trace/-f to drive rate from a file\n");
            return -1;
        }
    }

    *url    = argv[optind];
    *header = NULL;

    return 0;
}

static void print_stats_header() {
    printf("  Thread Stats%6s%11s%8s%12s\n", "Avg", "Stdev", "99%", "+/- Stdev");
}

static void print_units(long double n, char *(*fmt)(long double), int width) {
    char *msg = fmt(n);
    int len = strlen(msg), pad = 2;

    if (isalpha(msg[len-1])) pad--;
    if (isalpha(msg[len-2])) pad--;
    width -= pad;

    printf("%*.*s%.*s", width, width, msg, pad, "  ");

    free(msg);
}

static void print_stats(char *name, stats *stats, char *(*fmt)(long double)) {
    uint64_t max = stats->max;
    long double mean  = stats_summarize(stats);
    long double stdev = stats_stdev(stats, mean);

    printf("    %-10s", name);
    print_units(mean,  fmt, 8);
    print_units(stdev, fmt, 10);
    print_units(stats_percentile(stats, 99.0), fmt, 9);
    printf("%8.2Lf%%\n", stats_within_stdev(stats, mean, stdev, 1));
}

static void print_hdr_latency(struct hdr_histogram* histogram, const char* description) {
    long double percentiles[] = { 50.0, 75.0, 90.0, 99.0, 99.9, 99.99, 99.999, 100.0};
    printf("  Latency Distribution (HdrHistogram - %s)\n", description);
    for (size_t i = 0; i < sizeof(percentiles) / sizeof(long double); i++) {
        long double p = percentiles[i];
        int64_t n = hdr_value_at_percentile(histogram, p);
        printf("%7.3Lf%%", p);
        print_units(n, format_time_us, 10);
        printf("\n");
    }
    // printf("\n%s\n", "  Detailed Percentile spectrum:");
    // hdr_percentiles_print(histogram, stdout, 5, 1000.0, CLASSIC);
}

static void print_stats_latency(stats *stats) {
    long double percentiles[] = { 50.0, 75.0, 90.0, 99.0, 99.9, 99.99, 99.999, 100.0 };
    printf("  Latency Distribution\n");
    for (size_t i = 0; i < sizeof(percentiles) / sizeof(long double); i++) {
        long double p = percentiles[i];
        uint64_t n = stats_percentile(stats, p);
        printf("%7.3Lf%%", p);
        print_units(n, format_time_us, 10);
        printf("\n");
    }
}
