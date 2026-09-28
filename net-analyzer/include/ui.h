#ifndef NET_ANALYZER_UI_H
#define NET_ANALYZER_UI_H

#include "analyzer.h"
#include "feed.h"
#include "ring_buffer.h"

#include <stdatomic.h>

/*
 * ncurses dashboard (spec 4.5), rendered by Thread 3 at 10 Hz.
 *
 *   top     traffic stats: throughput, totals, protocol breakdown
 *   middle  scrollable feed of the last FEED_CAP frames
 *   bottom  anomaly alerts, highlighted
 *
 * Only the UI thread touches curses. It reads shared state through
 * ana_snapshot(), ana_alerts_since(), feed_since() and rb_get_stats(), so
 * it never blocks the capture path for more than one feed copy.
 *
 * Signals stay with the main thread: it sets *stop on SIGINT/SIGTERM and
 * *resize on SIGWINCH, and ui_run() polls both every frame. Pressing q sets
 * *stop itself.
 */

struct ui_config {
    struct analyzer *ana;
    struct feed *feed;
    struct ring_buffer *ring;        /* optional; shows live ring drops */
    const char *iface;               /* NULL = all interfaces */
    const char *pcap_path;           /* NULL = not writing */
    atomic_int *stop;
    atomic_int *resize;
};

struct ui_state;

struct ui {
    struct ui_config cfg;
    void *screen;                    /* SCREEN * */
    struct ui_state *st;
};

/*
 * Take over the terminal (stdin/stdout must be a tty). Call before
 * starting the UI thread. Returns 0, or -1 with a message on stderr.
 */
int ui_open(struct ui *u, const struct ui_config *cfg);

/* Thread 3 entry point: renders until *stop is set. arg is a struct ui *. */
void *ui_run(void *arg);

/* Restore the terminal. Idempotent; call after joining the UI thread. */
void ui_close(struct ui *u);

#endif
