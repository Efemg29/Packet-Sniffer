#include "config.h"
#include "parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

/* Static so the hot path never allocates. */
static uint8_t g_frame[MAX_PACKET_LEN];

struct options {
    const char *iface;
    unsigned long long max_packets;   /* 0 = unlimited */
    int promisc;
};

struct counters {
    unsigned long long seen;
    unsigned long long ok;
    unsigned long long truncated;
    unsigned long long malformed;
};

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    /* No SA_RESTART: recvfrom() must return EINTR so the loop can exit. */
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0)
        return -1;
    return 0;
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
            "Usage: %s [-i IFACE] [-c COUNT] [-p] [-h]\n"
            "  -i IFACE  capture only on IFACE (default: all interfaces)\n"
            "  -c COUNT  stop after COUNT packets\n"
            "  -p        put IFACE into promiscuous mode (requires -i)\n"
            "  -h        show this help\n",
            prog);
}

static int parse_args(int argc, char **argv, struct options *opt)
{
    int c;
    char *end;

    memset(opt, 0, sizeof(*opt));
    while ((c = getopt(argc, argv, "i:c:ph")) != -1) {
        switch (c) {
        case 'i':
            opt->iface = optarg;
            break;
        case 'c':
            errno = 0;
            opt->max_packets = strtoull(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || end == optarg || optarg[0] == '-') {
                fprintf(stderr, "invalid packet count: %s\n", optarg);
                return -1;
            }
            break;
        case 'p':
            opt->promisc = 1;
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

    /* Bounds how long a signal can go unnoticed if it lands between the
     * g_stop check and recvfrom(). */
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

static void print_packet(const struct pkt_info *info, int outgoing)
{
    struct timespec ts;
    struct tm tm;
    char line[256];

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    pkt_format(info, line, sizeof(line));
    printf("%02d:%02d:%02d.%06ld %-3s %s\n", tm.tm_hour, tm.tm_min,
           tm.tm_sec, ts.tv_nsec / 1000L, outgoing ? "OUT" : "IN", line);
}

static void count(struct counters *c, enum pkt_status st)
{
    c->seen++;
    switch (st) {
    case PKT_OK:          c->ok++; break;
    case PKT_TRUNCATED:   c->truncated++; break;
    case PKT_MALFORMED:   c->malformed++; break;
    case PKT_INVALID_ARG: break;
    }
}

static int capture_loop(int fd, const struct options *opt,
                        struct counters *ctr)
{
    struct pkt_info info;

    while (!g_stop) {
        struct sockaddr_ll from;
        socklen_t from_len = sizeof(from);
        ssize_t n;
        size_t cap;

        n = recvfrom(fd, g_frame, sizeof(g_frame), MSG_TRUNC,
                     (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("recvfrom");
            return -1;
        }

        /* With MSG_TRUNC, n is the on-wire length and may exceed the buffer. */
        cap = (size_t)n < sizeof(g_frame) ? (size_t)n : sizeof(g_frame);
        count(ctr, parse_packet(g_frame, cap, &info));
        print_packet(&info, from.sll_pkttype == PACKET_OUTGOING);

        if (opt->max_packets != 0 && ctr->seen >= opt->max_packets)
            break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct options opt;
    struct counters ctr;
    int fd, rc;

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

    if (install_signal_handlers() != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    fd = open_capture_socket(&opt);
    if (fd < 0)
        return EXIT_FAILURE;

    fprintf(stderr, "capturing on %s%s (Ctrl-C to stop)\n",
            opt.iface ? opt.iface : "all interfaces",
            opt.promisc ? " [promiscuous]" : "");

    memset(&ctr, 0, sizeof(ctr));
    rc = capture_loop(fd, &opt, &ctr);

    close(fd);
    fflush(stdout);
    fprintf(stderr,
            "\n%llu packets captured: %llu ok, %llu truncated, %llu malformed\n",
            ctr.seen, ctr.ok, ctr.truncated, ctr.malformed);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
