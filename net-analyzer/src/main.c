#include "analyzer.h"
#include "config.h"
#include "detector.h"
#include "feed.h"
#include "parser.h"
#include "pcap_writer.h"
#include "ring_buffer.h"
#include "ui.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_RING_SLOTS 256

/* Set by the signal thread, by the worker on -c, by q in the TUI, or on a
 * fatal error. */
static atomic_int g_stop;
/* Set by the signal thread on SIGWINCH; consumed by the UI thread. */
static atomic_int g_resize;

struct options {
    const char *iface;
    const char *pcap_path;            /* -w; NULL = off */
    unsigned long long max_packets;   /* 0 = unlimited */
    size_t ring_slots;
    int promisc;
    int quiet;
    int stats;
    int console;                      /* -n, or implied; see parse_args */
};

struct capture {
    int fd;
    const struct options *opt;
    struct ring_buffer ring;
    atomic_int ingest_done;
    int ingest_rc;
    int tui;                          /* ncurses dashboard owns the screen */
    struct analyzer ana;              /* shared metrics; see analyzer.h */
    struct feed feed;                 /* worker -> UI packet feed */
    struct detector det;              /* owned by the worker */
    struct pcap_writer pcap;          /* owned by the worker once started */
    int pcap_on;
    struct ui ui;
};

/*
 * Receive target when the ring is full. Static so the hot path never
 * allocates; only the ingestion thread touches it.
 */
static uint8_t g_overflow[MAX_PACKET_LEN];

static void request_stop(void)
{
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);
}

static int stop_requested(void)
{
    return atomic_load_explicit(&g_stop, memory_order_relaxed);
}

static int has_cap_net_raw(void)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    if (geteuid() == 0)
        return 1;

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) != 0)
        return 0;
    return (data[CAP_TO_INDEX(CAP_NET_RAW)].effective &
            CAP_TO_MASK(CAP_NET_RAW)) != 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-i IFACE] [-c COUNT] [-b SLOTS] [-w FILE] [-p] [-n] [-q] [-s] [-h]\n"
            "  -i IFACE  capture only on IFACE (default: all interfaces)\n"
            "  -c COUNT  stop after COUNT packets\n"
            "  -b SLOTS  ring buffer slots, 64 KiB each (default: %d)\n"
            "  -w FILE   also write every captured frame to FILE (libpcap format)\n"
            "  -p        put IFACE into promiscuous mode (requires -i)\n"
            "  -n        console mode: print lines instead of the ncurses dashboard\n"
            "  -q        console mode, quiet: do not print packets (alerts still print)\n"
            "  -s        console mode, plus a traffic stats line on stderr every second\n"
            "  -h        show this help\n"
            "The dashboard is used when stdin and stdout are terminals and none of\n"
            "-n, -q, -s is given. In the dashboard: q quits, arrows/PgUp/PgDn/g/G\n"
            "scroll the packet feed, p pauses it.\n",
            prog, DEFAULT_RING_SLOTS);
}

static int parse_args(int argc, char **argv, struct options *opt)
{
    int c;
    char *end;

    memset(opt, 0, sizeof(*opt));
    opt->ring_slots = DEFAULT_RING_SLOTS;
    while ((c = getopt(argc, argv, "i:c:b:w:pnqsh")) != -1) {
        switch (c) {
        case 'i':
            opt->iface = optarg;
            break;
        case 'w':
            if (optarg[0] == '\0') {
                fprintf(stderr, "-w needs a file name\n");
                return -1;
            }
            opt->pcap_path = optarg;
            break;
        case 'n':
            opt->console = 1;
            break;
        case 'c':
            errno = 0;
            opt->max_packets = strtoull(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || end == optarg || optarg[0] == '-') {
                fprintf(stderr, "invalid packet count: %s\n", optarg);
                return -1;
            }
            break;
        case 'b': {
            unsigned long long v;

            errno = 0;
            v = strtoull(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || end == optarg ||
                optarg[0] == '-' || v < 2 || v > 16384) {
                fprintf(stderr, "invalid slot count (2..16384): %s\n", optarg);
                return -1;
            }
            opt->ring_slots = (size_t)v;
            break;
        }
        case 'p':
            opt->promisc = 1;
            break;
        case 'q':
            opt->quiet = 1;
            break;
        case 's':
            opt->stats = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            return -1;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
        return -1;
    }
    if (opt->promisc && opt->iface == NULL) {
        fprintf(stderr, "-p requires -i IFACE\n");
        return -1;
    }
    if (opt->quiet || opt->stats || !isatty(STDIN_FILENO) ||
        !isatty(STDOUT_FILENO))
        opt->console = 1;
    return 0;
}

static int open_capture_socket(const struct options *opt)
{
    int fd;
    struct timeval tv = { 0, 250000 };

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    /* Bounds how long the ingestion thread can block before it re-checks
     * g_stop. */
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(fd);
        return -1;
    }

    if (opt->iface != NULL) {
        struct sockaddr_ll sll;
        unsigned int ifindex = if_nametoindex(opt->iface);

        if (ifindex == 0) {
            fprintf(stderr, "unknown interface '%s': %s\n", opt->iface,
                    strerror(errno));
            close(fd);
            return -1;
        }

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = (int)ifindex;
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
            perror("bind");
            close(fd);
            return -1;
        }

        if (opt->promisc) {
            struct packet_mreq mr;

            memset(&mr, 0, sizeof(mr));
            mr.mr_ifindex = (int)ifindex;
            mr.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,
                           sizeof(mr)) != 0) {
                perror("setsockopt(PACKET_ADD_MEMBERSHIP)");
                close(fd);
                return -1;
            }
        }
    }
    return fd;
}

static void print_packet(const struct rb_slot *s, const struct pkt_info *info)
{
    struct tm tm;
    char line[256];

    localtime_r(&s->ts.tv_sec, &tm);
    pkt_format(info, line, sizeof(line));
    printf("%02d:%02d:%02d.%06ld %-3s %s\n", tm.tm_hour, tm.tm_min,
           tm.tm_sec, s->ts.tv_nsec / 1000L,
           s->pkttype == PACKET_OUTGOING ? "OUT" : "IN", line);
}

static uint64_t ts_ns(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

static void print_alert(const struct rb_slot *s, const struct det_alert *a,
                        const struct det_config *cfg)
{
    struct tm tm;
    char src[INET_ADDRSTRLEN];

    localtime_r(&s->ts.tv_sec, &tm);
    inet_ntop(AF_INET, &a->src_ip, src, sizeof(src));
    printf("%02d:%02d:%02d.%06ld !!! ALERT %s src=%s syns=%u ports=%u "
           "window=%.1fs last_dport=%u\n",
           tm.tm_hour, tm.tm_min, tm.tm_sec, s->ts.tv_nsec / 1000L,
           det_event_str(a->type), src, a->syn_count, a->distinct_ports,
           (double)cfg->window_ns / 1e9, a->last_dst_port);
    fflush(stdout);
}

static void fill_slot(struct rb_slot *s, size_t wire_len,
                      const struct sockaddr_ll *from)
{
    s->cap_len = (uint32_t)(wire_len < MAX_PACKET_LEN ? wire_len
                                                      : MAX_PACKET_LEN);
    s->orig_len = wire_len > UINT32_MAX ? UINT32_MAX : (uint32_t)wire_len;
    s->pkttype = from->sll_pkttype;
    clock_gettime(CLOCK_REALTIME, &s->ts);
}

/* Thread 1: socket -> ring. The only producer. */
static void *ingest_thread(void *arg)
{
    struct capture *cap = arg;
    struct ring_buffer *rb = &cap->ring;

    while (!stop_requested()) {
        struct sockaddr_ll from;
        socklen_t from_len = sizeof(from);
        struct rb_slot *slot = rb_reserve(rb);
        uint8_t *dst = slot != NULL ? slot->data : g_overflow;
        ssize_t n;

        n = recvfrom(cap->fd, dst, MAX_PACKET_LEN, MSG_TRUNC,
                     (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("recvfrom");
            cap->ingest_rc = -1;
            request_stop();
            break;
        }

        if (slot == NULL) {
            /* The ring was full when we started waiting; the worker may have
             * freed a slot while we were blocked in recvfrom(). */
            slot = rb_reserve(rb);
            if (slot == NULL) {
                rb_record_drop(rb);
                continue;
            }
            memcpy(slot->data, g_overflow,
                   (size_t)n < MAX_PACKET_LEN ? (size_t)n : MAX_PACKET_LEN);
        }
        fill_slot(slot, (size_t)n, &from);
        rb_commit(rb);
    }

    atomic_store_explicit(&cap->ingest_done, 1, memory_order_release);
    return NULL;
}

static void idle_backoff(unsigned *spins)
{
    static const struct timespec nap = { 0, 100000 };   /* 100 us */

    if (*spins < 64) {
        (*spins)++;
        sched_yield();
    } else {
        nanosleep(&nap, NULL);
    }
}

/* Thread 2: ring -> parser -> stdout. The only consumer. */
static void *worker_thread(void *arg)
{
    struct capture *cap = arg;
    struct ring_buffer *rb = &cap->ring;
    const struct options *opt = cap->opt;
    struct pkt_info info;
    struct det_alert alert;
    unsigned spins = 0;

    for (;;) {
        const struct rb_slot *s = rb_peek(rb);

        if (s == NULL) {
            /* Drain everything already queued before exiting. */
            if (atomic_load_explicit(&cap->ingest_done, memory_order_acquire) &&
                (s = rb_peek(rb)) == NULL)
                break;
            if (s == NULL) {
                /* Flush once per idle period, not per frame, so the file
                 * stays current under light traffic without a syscall per
                 * packet under load. */
                if (cap->pcap_on && cap->pcap.unflushed != 0)
                    pcap_flush(&cap->pcap);
                idle_backoff(&spins);
                continue;
            }
        }
        spins = 0;

        parse_packet(s->data, s->cap_len, &info);
        ana_record(&cap->ana, &info, s->orig_len);
        if (cap->pcap_on)
            pcap_write(&cap->pcap, &s->ts, s->data, s->cap_len, s->orig_len);
        if (cap->tui)
            feed_push(&cap->feed, &s->ts, s->pkttype, s->orig_len, &info);
        else if (!opt->quiet)
            print_packet(s, &info);
        /* Outgoing frames are skipped so loopback traffic, which is seen
         * once as OUT and once as IN, is only counted once. */
        if (s->pkttype != PACKET_OUTGOING &&
            det_observe(&cap->det, &info, ts_ns(&s->ts), &alert)) {
            ana_push_alert(&cap->ana, &alert);
            if (!cap->tui)
                print_alert(s, &alert, &cap->det.cfg);
        }
        rb_release(rb);

        if (opt->max_packets != 0 &&
            ana_packets(&cap->ana) >= opt->max_packets) {
            request_stop();
            break;
        }
    }
    fflush(stdout);
    return NULL;
}

static void print_stats_line(struct analyzer *ana)
{
    struct ana_snapshot sn;
    double total;

    ana_snapshot(ana, &sn);
    total = sn.packets ? (double)sn.packets : 1.0;
    fprintf(stderr,
            "[stats] %.0f pkt/s %.1f KB/s | total %llu pkts %llu bytes | "
            "TCP %.1f%% UDP %.1f%% ICMP %.1f%% Other %.1f%% | alerts %llu\n",
            sn.pps, sn.bytes_per_sec / 1024.0,
            (unsigned long long)sn.packets, (unsigned long long)sn.bytes,
            100.0 * (double)sn.proto[ANA_PROTO_TCP] / total,
            100.0 * (double)sn.proto[ANA_PROTO_UDP] / total,
            100.0 * (double)sn.proto[ANA_PROTO_ICMP] / total,
            100.0 * (double)sn.proto[ANA_PROTO_OTHER] / total,
            (unsigned long long)sn.alerts);
}

/*
 * Runs on the main thread with SIGINT/SIGTERM/SIGWINCH blocked process-wide,
 * so it is the only place those signals are ever handled. It is also the
 * analyzer's rate ticker.
 */
static void wait_for_stop(struct capture *cap, const sigset_t *set)
{
    static const struct timespec tick = { 0, 100000000 };  /* 100 ms */
    uint64_t next_print = 0;

    while (!stop_requested()) {
        struct timespec now;
        uint64_t now_ns;
        int sig = sigtimedwait(set, NULL, &tick);

        if (sig == SIGINT || sig == SIGTERM)
            request_stop();
        else if (sig == SIGWINCH)
            atomic_store_explicit(&g_resize, 1, memory_order_relaxed);

        clock_gettime(CLOCK_MONOTONIC, &now);
        now_ns = ts_ns(&now);
        ana_tick(&cap->ana, now_ns);
        if (cap->opt->stats && now_ns >= next_print) {
            if (next_print != 0)
                print_stats_line(&cap->ana);
            next_print = now_ns + 1000000000ULL;
        }
    }
}

static void print_summary(struct capture *cap)
{
    struct rb_stats rs;
    struct tpacket_stats ks;
    socklen_t ks_len = sizeof(ks);
    unsigned long long offered;

    struct ana_snapshot sn;
    struct det_stats ds;

    rb_get_stats(&cap->ring, &rs);
    offered = (unsigned long long)(rs.pushed + rs.dropped);
    ana_snapshot(&cap->ana, &sn);
    det_get_stats(&cap->det, &ds);

    fprintf(stderr,
            "\n%llu packets dissected: %llu ok, %llu truncated, %llu malformed\n",
            (unsigned long long)sn.packets, (unsigned long long)sn.ok,
            (unsigned long long)sn.truncated, (unsigned long long)sn.malformed);
    fprintf(stderr,
            "traffic: %llu bytes | TCP %llu, UDP %llu, ICMP %llu, Other %llu\n",
            (unsigned long long)sn.bytes,
            (unsigned long long)sn.proto[ANA_PROTO_TCP],
            (unsigned long long)sn.proto[ANA_PROTO_UDP],
            (unsigned long long)sn.proto[ANA_PROTO_ICMP],
            (unsigned long long)sn.proto[ANA_PROTO_OTHER]);
    fprintf(stderr,
            "detector: %llu SYNs from %u tracked sources, %llu evicted, "
            "%llu alerts\n",
            (unsigned long long)ds.syns_seen, ds.tracked,
            (unsigned long long)ds.evictions, (unsigned long long)sn.alerts);
    fprintf(stderr,
            "ring (%zu slots): %llu queued, %llu dropped (%.3f%%), %zu left unprocessed\n",
            cap->ring.capacity, (unsigned long long)rs.pushed,
            (unsigned long long)rs.dropped,
            offered ? 100.0 * (double)rs.dropped / (double)offered : 0.0,
            rs.in_use);

    memset(&ks, 0, sizeof(ks));
    if (getsockopt(cap->fd, SOL_PACKET, PACKET_STATISTICS, &ks, &ks_len) == 0)
        fprintf(stderr, "kernel: %u packets, %u dropped by socket\n",
                ks.tp_packets, ks.tp_drops);
}

/* Returns 0, or -1 if the pcap file hit an error at any point. */
static int finish_pcap(struct capture *cap)
{
    int err;

    if (!cap->pcap_on)
        return 0;
    err = pcap_close(&cap->pcap);
    cap->pcap_on = 0;
    if (err != 0) {
        fprintf(stderr, "pcap: error writing %s after %llu packets: %s\n",
                cap->opt->pcap_path, (unsigned long long)cap->pcap.packets,
                strerror(err));
        return -1;
    }
    fprintf(stderr, "pcap: %llu packets, %llu bytes written to %s\n",
            (unsigned long long)cap->pcap.packets,
            (unsigned long long)cap->pcap.bytes, cap->opt->pcap_path);
    return 0;
}

static void cleanup(struct capture *cap)
{
    finish_pcap(cap);
    feed_destroy(&cap->feed);
    ana_destroy(&cap->ana);
    rb_destroy(&cap->ring);
    close(cap->fd);
}

int main(int argc, char **argv)
{
    struct options opt;
    static struct capture cap;
    pthread_t ingest, worker, ui_tid;
    sigset_t sigs;
    int err, rc;

    if (parse_args(argc, argv, &opt) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!has_cap_net_raw()) {
        fprintf(stderr,
                "error: raw packet capture requires root or CAP_NET_RAW.\n"
                "  run with sudo, or: sudo setcap cap_net_raw+ep %s\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    /* Block before spawning threads so they inherit the mask and the main
     * thread's sigtimedwait() is the sole receiver. */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGWINCH);
    err = pthread_sigmask(SIG_BLOCK, &sigs, NULL);
    if (err != 0) {
        fprintf(stderr, "pthread_sigmask: %s\n", strerror(err));
        return EXIT_FAILURE;
    }

    cap.opt = &opt;
    cap.tui = !opt.console;
    cap.fd = open_capture_socket(&opt);
    if (cap.fd < 0)
        return EXIT_FAILURE;

    if (rb_init(&cap.ring, opt.ring_slots) != 0) {
        perror("ring buffer");
        close(cap.fd);
        return EXIT_FAILURE;
    }
    atomic_init(&cap.ingest_done, 0);
    err = ana_init(&cap.ana);
    if (err != 0) {
        fprintf(stderr, "analyzer: %s\n", strerror(err));
        rb_destroy(&cap.ring);
        close(cap.fd);
        return EXIT_FAILURE;
    }
    err = feed_init(&cap.feed);
    if (err != 0) {
        fprintf(stderr, "feed: %s\n", strerror(err));
        ana_destroy(&cap.ana);
        rb_destroy(&cap.ring);
        close(cap.fd);
        return EXIT_FAILURE;
    }
    det_init(&cap.det, NULL);

    if (opt.pcap_path != NULL) {
        err = pcap_open(&cap.pcap, opt.pcap_path);
        if (err != 0) {
            fprintf(stderr, "pcap: cannot write %s: %s\n", opt.pcap_path,
                    strerror(err));
            cleanup(&cap);
            return EXIT_FAILURE;
        }
        cap.pcap_on = 1;
    }

    if (cap.tui) {
        struct ui_config uc = {
            .ana = &cap.ana, .feed = &cap.feed, .ring = &cap.ring,
            .iface = opt.iface, .pcap_path = opt.pcap_path,
            .stop = &g_stop, .resize = &g_resize,
        };

        if (ui_open(&cap.ui, &uc) != 0) {
            cleanup(&cap);
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "capturing on %s%s, %zu ring slots%s%s (Ctrl-C to stop)\n",
                opt.iface ? opt.iface : "all interfaces",
                opt.promisc ? " [promiscuous]" : "", cap.ring.capacity,
                opt.pcap_path ? ", writing " : "",
                opt.pcap_path ? opt.pcap_path : "");
    }

    err = pthread_create(&worker, NULL, worker_thread, &cap);
    if (err == 0) {
        err = pthread_create(&ingest, NULL, ingest_thread, &cap);
        if (err != 0) {
            atomic_store(&cap.ingest_done, 1);
            pthread_join(worker, NULL);
        }
    }
    if (err == 0 && cap.tui) {
        err = pthread_create(&ui_tid, NULL, ui_run, &cap.ui);
        if (err != 0) {
            request_stop();
            pthread_join(ingest, NULL);
            pthread_join(worker, NULL);
        }
    }
    if (err != 0) {
        ui_close(&cap.ui);
        fprintf(stderr, "pthread_create: %s\n", strerror(err));
        cleanup(&cap);
        return EXIT_FAILURE;
    }

    wait_for_stop(&cap, &sigs);

    /* Ingestion exits within one SO_RCVTIMEO tick; the worker then drains.
     * The UI exits within one 100 ms frame and restores the terminal before
     * the summary is printed. */
    if (cap.tui)
        pthread_join(ui_tid, NULL);
    ui_close(&cap.ui);
    pthread_join(ingest, NULL);
    pthread_join(worker, NULL);

    fflush(stdout);
    print_summary(&cap);
    rc = finish_pcap(&cap);
    cleanup(&cap);
    return cap.ingest_rc == 0 && rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
