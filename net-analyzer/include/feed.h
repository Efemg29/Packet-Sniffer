#ifndef NET_ANALYZER_FEED_H
#define NET_ANALYZER_FEED_H

#include "parser.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Packet feed for the dashboard: a fixed ring of the most recent
 * FEED_CAP dissected frames.
 *
 * One writer (the dissector) calls feed_push(); any thread may poll with
 * feed_since(). Entries hold the parsed summary, not the frame bytes, and
 * are formatted by the reader, so the writer only copies about 100 bytes
 * per frame under an uncontended mutex. Nothing here allocates after
 * feed_init().
 */

#define FEED_CAP 1024                /* power of two */

struct feed_entry {
    uint64_t seq;                    /* 1, 2, 3, ... in push order */
    struct timespec ts;              /* capture time (CLOCK_REALTIME) */
    uint32_t wire_len;               /* on-wire length */
    uint8_t  pkttype;                /* sll_pkttype */
    struct pkt_info info;
};

struct feed {
    pthread_mutex_t lock;
    uint64_t last_seq;               /* seq of the newest entry, 0 if none */
    struct feed_entry entries[FEED_CAP];
};

/* Returns 0, or an errno value from pthread_mutex_init(). */
int  feed_init(struct feed *f);
void feed_destroy(struct feed *f);

/* Writer only. */
void feed_push(struct feed *f, const struct timespec *ts, uint8_t pkttype,
               uint32_t wire_len, const struct pkt_info *info);

/*
 * Copy entries with seq > after_seq into out, oldest first. When more than
 * max qualify, only the newest max are copied. Returns the number copied;
 * *last_seq (if not NULL) receives the newest seq in the feed.
 */
size_t feed_since(struct feed *f, uint64_t after_seq, struct feed_entry *out,
                  size_t max, uint64_t *last_seq);

/*
 * Column widths of feed_format(): time, dir, proto, source, destination,
 * length, then free-form info.
 */
#define FEED_COL_TIME   12
#define FEED_COL_DIR    3
#define FEED_COL_PROTO  5
#define FEED_COL_ADDR   21
#define FEED_COL_LEN    6

/* One aligned row for the feed panel (no newline). snprintf semantics. */
int feed_format(const struct feed_entry *e, char *out, size_t out_len);

/* Header row matching feed_format(). */
int feed_format_header(char *out, size_t out_len);

#endif
