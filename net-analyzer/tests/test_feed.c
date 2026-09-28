#include "feed.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                         \
    do {                                                                    \
        g_checks++;                                                         \
        if (!(cond)) {                                                      \
            g_failures++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__,       \
                    #cond);                                                 \
        }                                                                   \
    } while (0)

#define CHECK_EQ(a, b) CHECK((long long)(a) == (long long)(b))
#define CHECK_HAS(s, sub)                                                   \
    do {                                                                    \
        CHECK(strstr((s), (sub)) != NULL);                                  \
        if (strstr((s), (sub)) == NULL)                                     \
            fprintf(stderr, "    in \"%s\"\n", (s));                        \
    } while (0)

#define RUN(fn)                                                             \
    do {                                                                    \
        int before = g_failures;                                            \
        fn();                                                               \
        printf("%-44s %s\n", #fn, g_failures == before ? "ok" : "FAILED");  \
    } while (0)

static struct feed g_feed;
static struct feed_entry g_out[FEED_CAP];

static void push_n(struct feed *f, uint64_t first, uint64_t n)
{
    struct pkt_info info;
    struct timespec ts = { 0, 0 };
    uint64_t i;

    memset(&info, 0, sizeof(info));
    for (i = 0; i < n; i++) {
        uint64_t k = first + i;

        info.src_port = (uint16_t)k;
        ts.tv_sec = (time_t)k;
        feed_push(f, &ts, PACKET_HOST, (uint32_t)k, &info);
    }
}

static void test_empty(void)
{
    uint64_t last = 99;

    CHECK_EQ(feed_init(&g_feed), 0);
    CHECK_EQ(feed_since(&g_feed, 0, g_out, FEED_CAP, &last), 0);
    CHECK_EQ(last, 0);
    feed_destroy(&g_feed);
}

static void test_incremental(void)
{
    uint64_t last;
    size_t n;

    feed_init(&g_feed);
    push_n(&g_feed, 1, 5);
    n = feed_since(&g_feed, 0, g_out, FEED_CAP, &last);
    CHECK_EQ(n, 5);
    CHECK_EQ(last, 5);
    CHECK_EQ(g_out[0].seq, 1);
    CHECK_EQ(g_out[4].seq, 5);
    CHECK_EQ(g_out[4].wire_len, 5);
    CHECK_EQ(g_out[4].info.src_port, 5);

    n = feed_since(&g_feed, 3, g_out, FEED_CAP, NULL);
    CHECK_EQ(n, 2);
    CHECK_EQ(g_out[0].seq, 4);

    /* Only the newest max are returned, still oldest first. */
    n = feed_since(&g_feed, 0, g_out, 2, NULL);
    CHECK_EQ(n, 2);
    CHECK_EQ(g_out[0].seq, 4);
    CHECK_EQ(g_out[1].seq, 5);

    CHECK_EQ(feed_since(&g_feed, 5, g_out, FEED_CAP, NULL), 0);
    CHECK_EQ(feed_since(&g_feed, 500, g_out, FEED_CAP, NULL), 0);
    CHECK_EQ(feed_since(&g_feed, 0, g_out, 0, NULL), 0);
    feed_destroy(&g_feed);
}

static void test_overflow_keeps_newest(void)
{
    uint64_t last;
    size_t n, i, bad = 0;

    feed_init(&g_feed);
    push_n(&g_feed, 1, 3000);
    n = feed_since(&g_feed, 0, g_out, FEED_CAP, &last);
    CHECK_EQ(n, FEED_CAP);
    CHECK_EQ(last, 3000);
    for (i = 0; i < n; i++)
        if (g_out[i].seq != 3000 - FEED_CAP + 1 + i ||
            g_out[i].wire_len != (uint32_t)g_out[i].seq)
            bad++;
    CHECK_EQ(bad, 0);

    /* A reader that fell behind by more than FEED_CAP skips the gap. */
    n = feed_since(&g_feed, 10, g_out, FEED_CAP, NULL);
    CHECK_EQ(n, FEED_CAP);
    CHECK_EQ(g_out[0].seq, 3000 - FEED_CAP + 1);
    feed_destroy(&g_feed);
}

static struct feed_entry entry(enum pkt_l3 l3, enum pkt_l4 l4)
{
    struct feed_entry e;

    memset(&e, 0, sizeof(e));
    e.seq = 1;
    e.ts.tv_sec = 1700000000;
    e.ts.tv_nsec = 123456789;
    e.pkttype = PACKET_HOST;
    e.wire_len = 74;
    e.info.l3 = l3;
    e.info.l4 = l4;
    e.info.src_ip = htonl(0x0a000001);
    e.info.dst_ip = htonl(0x0a000002);
    return e;
}

static void test_format_rows(void)
{
    char line[256], hdr[256];
    struct feed_entry e;
    const char *d;

    e = entry(PKT_L3_IPV4, PKT_L4_TCP);
    e.info.src_port = 1234;
    e.info.dst_port = 80;
    e.info.tcp_flags = 0x12;            /* SYN + ACK */
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, ".123 ");
    CHECK_HAS(line, " IN  TCP ");
    CHECK_HAS(line, "10.0.0.1:1234");
    CHECK_HAS(line, "-> 10.0.0.2:80");
    CHECK_HAS(line, "    74 [SA]");

    /* The destination column starts where the header says it does. */
    feed_format_header(hdr, sizeof(hdr));
    d = strstr(line, "10.0.0.2");
    CHECK(d != NULL && strstr(hdr, "DESTINATION") != NULL);
    if (d != NULL && strstr(hdr, "DESTINATION") != NULL)
        CHECK_EQ(d - line, strstr(hdr, "DESTINATION") - hdr);
    d = strstr(line, "[SA]");
    if (d != NULL && strstr(hdr, "FLAGS") != NULL)
        CHECK_EQ(d - line, strstr(hdr, "FLAGS") - hdr);

    e = entry(PKT_L3_IPV4, PKT_L4_UDP);
    e.pkttype = PACKET_OUTGOING;
    e.info.src_port = 5353;
    e.info.dst_port = 53;
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, " OUT UDP ");
    CHECK_HAS(line, "10.0.0.1:5353");

    e = entry(PKT_L3_IPV4, PKT_L4_ICMP);
    e.info.icmp_type = 8;
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, "ICMP");
    CHECK_HAS(line, "type=8 code=0");
    CHECK(strstr(line, "10.0.0.1:") == NULL);

    e = entry(PKT_L3_ARP, PKT_L4_NONE);
    e.info.ethertype = 0x0806;
    e.info.src_mac[0] = 0xaa;
    e.info.dst_mac[5] = 0xff;
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, "ARP");
    CHECK_HAS(line, "aa:00:00:00:00:00");
    CHECK_HAS(line, "00:00:00:00:00:ff");
    CHECK_HAS(line, "type=0x0806");

    e = entry(PKT_L3_IPV4, PKT_L4_TCP);
    e.info.status = PKT_TRUNCATED;
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, "[truncated]");

    e = entry(PKT_L3_NONE, PKT_L4_NONE);
    e.info.status = PKT_TRUNCATED;
    feed_format(&e, line, sizeof(line));
    CHECK_HAS(line, "ETH");
    CHECK_HAS(line, "[truncated]");

    /* Truncating output buffers stay terminated and report full length. */
    e = entry(PKT_L3_IPV4, PKT_L4_TCP);
    CHECK(feed_format(&e, line, 10) > 10);
    CHECK_EQ(strlen(line), 9);
}

struct stress {
    struct feed *f;
    uint64_t iters;
    uint64_t bad;
    uint64_t seen;
};

static void *writer(void *arg)
{
    struct stress *s = arg;
    struct pkt_info info;
    struct timespec ts;
    uint64_t k;

    memset(&info, 0, sizeof(info));
    for (k = 1; k <= s->iters; k++) {
        info.src_ip = (uint32_t)k;
        info.dst_ip = (uint32_t)~k;
        info.src_port = (uint16_t)k;
        ts.tv_sec = (time_t)k;
        ts.tv_nsec = (long)(k % 1000000000ULL);
        feed_push(s->f, &ts, PACKET_HOST, (uint32_t)k, &info);
    }
    return NULL;
}

static void *reader(void *arg)
{
    static struct feed_entry buf[FEED_CAP];
    struct stress *s = arg;
    uint64_t after = 0, last = 0;

    while (after < s->iters) {
        size_t n = feed_since(s->f, after, buf, FEED_CAP, &last), i;

        for (i = 0; i < n; i++) {
            const struct feed_entry *e = &buf[i];
            uint64_t k = e->seq;

            if (k <= after || e->wire_len != (uint32_t)k ||
                e->info.src_ip != (uint32_t)k ||
                e->info.dst_ip != (uint32_t)~k ||
                e->info.src_port != (uint16_t)k ||
                e->ts.tv_sec != (time_t)k)
                s->bad++;
            after = k;
            s->seen++;
        }
        if (last < after)
            s->bad++;
    }
    return NULL;
}

static void test_concurrent(void)
{
    struct stress s = { &g_feed, 1000000, 0, 0 };
    const char *env = getenv("FEED_STRESS_ITERS");
    pthread_t w, r;

    if (env != NULL && atoll(env) > 0)
        s.iters = (uint64_t)atoll(env);
    feed_init(&g_feed);
    pthread_create(&r, NULL, reader, &s);
    pthread_create(&w, NULL, writer, &s);
    pthread_join(w, NULL);
    pthread_join(r, NULL);
    CHECK_EQ(s.bad, 0);
    CHECK(s.seen > 0 && s.seen <= s.iters);
    feed_destroy(&g_feed);
}

int main(void)
{
    RUN(test_empty);
    RUN(test_incremental);
    RUN(test_overflow_keeps_newest);
    RUN(test_format_rows);
    RUN(test_concurrent);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
