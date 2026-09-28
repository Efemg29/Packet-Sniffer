#ifndef NET_ANALYZER_ANALYZER_H
#define NET_ANALYZER_ANALYZER_H

#include "detector.h"
#include "parser.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Shared traffic metrics (spec 3, "Shared Metrics State").
 *
 * Threads and roles:
 *   - one writer (the dissector) calls ana_record();
 *   - one ticker (the main thread) calls ana_tick() periodically to refresh
 *     the packet and byte rates;
 *   - any thread may call ana_push_alert(), ana_snapshot(), ana_packets()
 *     and ana_alerts_since().
 *
 * Counters are C11 atomics published under a sequence lock, so
 * ana_snapshot() always returns a mutually consistent set (for example
 * packets == the sum of proto[]) without ever blocking the writer; readers
 * retry instead. The two rates are published the same way by the ticker.
 * Alerts are rare and go through a small mutex-protected ring.
 */

#define ANA_CACHELINE     64
#define ANA_ALERT_CAP     64     /* most recent alerts kept for readers */
#define ANA_RATE_SAMPLES  11     /* 10 intervals: 1 s at a 100 ms tick */

enum ana_proto {
    ANA_PROTO_TCP = 0,
    ANA_PROTO_UDP,
    ANA_PROTO_ICMP,
    ANA_PROTO_OTHER,             /* non-IPv4, other IP protocols, fragments */
    ANA_PROTO_COUNT
};

struct ana_snapshot {
    uint64_t packets;
    uint64_t bytes;              /* on-wire bytes */
    uint64_t proto[ANA_PROTO_COUNT];
    uint64_t ok;
    uint64_t truncated;
    uint64_t malformed;
    uint64_t alerts;             /* alerts pushed since start */
    double   pps;                /* over the last ANA_RATE_SAMPLES - 1 ticks */
    double   bytes_per_sec;
};

struct ana_alert_rec {
    uint64_t seq;                /* 1, 2, 3, ... in push order */
    struct det_alert alert;
};

struct ana_rate_sample {
    uint64_t t_ns;
    uint64_t packets;
    uint64_t bytes;
};

struct analyzer {
    /* Written by the ana_record() thread only. */
    _Alignas(ANA_CACHELINE) atomic_uint seq;
    atomic_uint_fast64_t packets;
    atomic_uint_fast64_t bytes;
    atomic_uint_fast64_t proto[ANA_PROTO_COUNT];
    atomic_uint_fast64_t ok;
    atomic_uint_fast64_t truncated;
    atomic_uint_fast64_t malformed;

    /* Written by the ana_tick() thread only, under their own sequence
     * lock; rates are stored as the bit pattern of a double. */
    _Alignas(ANA_CACHELINE) atomic_uint rate_seq;
    atomic_uint_fast64_t pps_bits;
    atomic_uint_fast64_t bps_bits;
    struct ana_rate_sample samples[ANA_RATE_SAMPLES];
    unsigned sample_head;        /* oldest sample */
    unsigned sample_count;

    _Alignas(ANA_CACHELINE) pthread_mutex_t alert_lock;
    uint64_t next_alert_seq;
    atomic_uint_fast64_t alerts_total;
    struct ana_alert_rec alerts[ANA_ALERT_CAP];
};

/* Returns 0, or an errno value from pthread_mutex_init(). */
int  ana_init(struct analyzer *a);
void ana_destroy(struct analyzer *a);

/* Writer only. Count one dissected frame of wire_len on-wire bytes. */
void ana_record(struct analyzer *a, const struct pkt_info *info,
                uint32_t wire_len);

/* Ticker only. now_ns must come from a monotonic clock. */
void ana_tick(struct analyzer *a, uint64_t now_ns);

/* Any thread. */
void ana_push_alert(struct analyzer *a, const struct det_alert *alert);
void ana_snapshot(struct analyzer *a, struct ana_snapshot *out);
uint64_t ana_packets(struct analyzer *a);

/*
 * Copy up to max alerts with seq > after_seq, oldest first, into out.
 * Alerts older than the last ANA_ALERT_CAP are gone. Pass the seq of the
 * last alert you received to poll incrementally (0 to start).
 */
size_t ana_alerts_since(struct analyzer *a, uint64_t after_seq,
                        struct ana_alert_rec *out, size_t max);

const char *ana_proto_str(enum ana_proto p);

#endif
