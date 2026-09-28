#ifndef NET_ANALYZER_DETECTOR_H
#define NET_ANALYZER_DETECTOR_H

#include "parser.h"

#include <stdint.h>

/*
 * Port-scan detector (spec 4.3).
 *
 * Tracks, per IPv4 source address, the TCP connection attempts (SYN set,
 * ACK clear) it sent within a sliding time window, and how many distinct
 * destination ports they targeted. A source is flagged PORT_SCAN_DETECTED
 * when, within the window, syn_count > syn_threshold AND
 * distinct_ports > port_threshold.
 *
 * All state lives inside struct detector (about 2.4 MiB with the defaults),
 * so the caller decides where it is stored; det_observe() never allocates.
 * The table holds DET_MAX_SOURCES sources; when it is full, the least
 * recently active source is evicted.
 *
 * Not thread-safe: one thread owns a detector.
 */

#define DET_MAX_SOURCES     1024
#define DET_HASH_BUCKETS    2048     /* power of two */

/*
 * SYNs remembered per source. syn_count saturates here, far above the
 * default threshold; distinct_ports is then computed over the most recent
 * DET_EVENT_CAP SYNs of the window.
 */
#define DET_EVENT_CAP       128
#define DET_PORT_SLOTS      256      /* power of two, >= 2 * DET_EVENT_CAP */

#define DET_DEFAULT_WINDOW_NS      1000000000ULL   /* 1.0 s */
#define DET_DEFAULT_SYN_THRESHOLD  30
#define DET_DEFAULT_PORT_THRESHOLD 20
#define DET_DEFAULT_REALERT_NS     5000000000ULL   /* 5 s */

enum det_event_type {
    DET_NONE = 0,
    DET_PORT_SCAN_DETECTED
};

struct det_config {
    uint64_t window_ns;
    uint32_t syn_threshold;       /* alert when syn_count > this */
    uint32_t port_threshold;      /* ... and distinct_ports > this */
    /*
     * While a source stays above both thresholds it is re-reported at most
     * once per realert_ns. A source that drops below either threshold is
     * re-armed and alerts again as soon as it crosses them.
     */
    uint64_t realert_ns;
};

struct det_alert {
    enum det_event_type type;
    uint32_t src_ip;              /* network byte order */
    uint32_t syn_count;           /* within the window at alert time */
    uint32_t distinct_ports;
    uint16_t last_dst_port;       /* host byte order */
    uint64_t ts_ns;               /* timestamp of the triggering packet */
};

struct det_source_stats {
    uint32_t syn_count;
    uint32_t distinct_ports;
    int      alerting;            /* currently above both thresholds */
};

struct det_stats {
    uint64_t syns_seen;
    uint64_t alerts;
    uint64_t evictions;
    uint32_t tracked;             /* sources currently in the table */
};

struct det_port_slot {
    uint16_t port;
    uint16_t refs;                /* 0 = empty */
};

struct det_source {
    uint32_t ip;
    uint32_t hash_next;           /* index into sources[], or DET_NIL */
    uint32_t lru_prev;
    uint32_t lru_next;
    uint64_t last_alert_ns;
    uint16_t ev_head;             /* index of the oldest event */
    uint16_t ev_count;
    uint16_t distinct;
    uint8_t  in_use;
    uint8_t  alerting;
    uint64_t ev_ts[DET_EVENT_CAP];
    uint16_t ev_port[DET_EVENT_CAP];
    struct det_port_slot ports[DET_PORT_SLOTS];
};

struct detector {
    struct det_config cfg;
    uint64_t last_ns;             /* clamps timestamps that go backwards */
    uint32_t lru_head;            /* most recently active */
    uint32_t lru_tail;            /* next eviction victim */
    uint32_t free_head;           /* unused entries, linked via hash_next */
    struct det_stats stats;
    uint32_t buckets[DET_HASH_BUCKETS];
    struct det_source sources[DET_MAX_SOURCES];
};

/* Fill cfg with the spec defaults. */
void det_default_config(struct det_config *cfg);

/* Reset d. cfg may be NULL for the defaults. Not for the hot path. */
void det_init(struct detector *d, const struct det_config *cfg);

/*
 * Feed one dissected packet seen at now_ns. Only IPv4 TCP packets with SYN
 * set and ACK clear are tracked; everything else returns immediately.
 * Returns 1 and fills *alert when the packet triggers an alert, else 0.
 */
int det_observe(struct detector *d, const struct pkt_info *info,
                uint64_t now_ns, struct det_alert *alert);

/* Same as det_observe() for one connection attempt src_ip -> dst_port. */
int det_observe_syn(struct detector *d, uint32_t src_ip, uint16_t dst_port,
                    uint64_t now_ns, struct det_alert *alert);

/*
 * Window state of src_ip as of now_ns (expired SYNs are not counted).
 * Returns 0, or -1 if src_ip is not tracked.
 */
int det_query(const struct detector *d, uint32_t src_ip, uint64_t now_ns,
              struct det_source_stats *out);

void det_get_stats(const struct detector *d, struct det_stats *out);

const char *det_event_str(enum det_event_type type);

#endif
