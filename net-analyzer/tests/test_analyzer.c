#include "analyzer.h"

#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
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
#define CHECK_NEAR(a, b) CHECK(fabs((double)(a) - (double)(b)) < 1e-6)

#define RUN(fn)                                                             \
    do {                                                                    \
        int before = g_failures;                                            \
        fn();                                                               \
        printf("%-44s %s\n", #fn, g_failures == before ? "ok" : "FAILED");  \
    } while (0)

#define MS 1000000ULL

static struct analyzer g_ana;

static struct pkt_info pkt(enum pkt_l3 l3, enum pkt_l4 l4, enum pkt_status st)
{
    struct pkt_info p;

    memset(&p, 0, sizeof(p));
    p.status = st;
    p.l3 = l3;
    p.l4 = l4;
    return p;
}

static struct det_alert alert_n(uint32_t n)
{
    struct det_alert a;

    memset(&a, 0, sizeof(a));
    a.type = DET_PORT_SCAN_DETECTED;
    a.src_ip = n;
    a.syn_count = 31 + n;
    a.distinct_ports = 21;
    a.ts_ns = n;
    return a;
}

static void test_initial_state(void)
{
    struct ana_snapshot s;
    struct ana_alert_rec r[4];
    int i;

    CHECK_EQ(ana_init(&g_ana), 0);
    memset(&s, 0xff, sizeof(s));
    ana_snapshot(&g_ana, &s);
    CHECK_EQ(s.packets, 0);
    CHECK_EQ(s.bytes, 0);
    for (i = 0; i < ANA_PROTO_COUNT; i++)
        CHECK_EQ(s.proto[i], 0);
    CHECK_EQ(s.ok + s.truncated + s.malformed, 0);
    CHECK_EQ(s.alerts, 0);
    CHECK_NEAR(s.pps, 0.0);
    CHECK_NEAR(s.bytes_per_sec, 0.0);
    CHECK_EQ(ana_packets(&g_ana), 0);
    CHECK_EQ(ana_alerts_since(&g_ana, 0, r, 4), 0);
    CHECK(strcmp(ana_proto_str(ANA_PROTO_OTHER), "Other") == 0);
    ana_destroy(&g_ana);
}

static void test_protocol_and_status_counts(void)
{
    struct ana_snapshot s;
    struct pkt_info p;

    ana_init(&g_ana);
    p = pkt(PKT_L3_IPV4, PKT_L4_TCP, PKT_OK);
    ana_record(&g_ana, &p, 60);
    ana_record(&g_ana, &p, 1514);
    p = pkt(PKT_L3_IPV4, PKT_L4_UDP, PKT_OK);
    ana_record(&g_ana, &p, 100);
    p = pkt(PKT_L3_IPV4, PKT_L4_ICMP, PKT_TRUNCATED);
    ana_record(&g_ana, &p, 98);
    p = pkt(PKT_L3_IPV4, PKT_L4_OTHER, PKT_OK);        /* e.g. GRE */
    ana_record(&g_ana, &p, 70);
    p = pkt(PKT_L3_IPV4, PKT_L4_NONE, PKT_OK);         /* later fragment */
    ana_record(&g_ana, &p, 1500);
    p = pkt(PKT_L3_IPV6, PKT_L4_NONE, PKT_OK);
    ana_record(&g_ana, &p, 86);
    p = pkt(PKT_L3_ARP, PKT_L4_NONE, PKT_OK);
    ana_record(&g_ana, &p, 42);
    p = pkt(PKT_L3_NONE, PKT_L4_NONE, PKT_TRUNCATED);  /* runt frame */
    ana_record(&g_ana, &p, 5);
    p = pkt(PKT_L3_IPV4, PKT_L4_NONE, PKT_MALFORMED);  /* ihl < 5 */
    ana_record(&g_ana, &p, 34);

    ana_snapshot(&g_ana, &s);
    CHECK_EQ(s.packets, 10);
    CHECK_EQ(ana_packets(&g_ana), 10);
    CHECK_EQ(s.bytes, 60 + 1514 + 100 + 98 + 70 + 1500 + 86 + 42 + 5 + 34);
    CHECK_EQ(s.proto[ANA_PROTO_TCP], 2);
    CHECK_EQ(s.proto[ANA_PROTO_UDP], 1);
    CHECK_EQ(s.proto[ANA_PROTO_ICMP], 1);
    CHECK_EQ(s.proto[ANA_PROTO_OTHER], 6);
    CHECK_EQ(s.ok, 7);
    CHECK_EQ(s.truncated, 2);
    CHECK_EQ(s.malformed, 1);
    ana_destroy(&g_ana);
}

static void record_n(int n, uint32_t len)
{
    struct pkt_info p = pkt(PKT_L3_IPV4, PKT_L4_UDP, PKT_OK);
    int i;

    for (i = 0; i < n; i++)
        ana_record(&g_ana, &p, len);
}

static void test_rates(void)
{
    struct ana_snapshot s;
    uint64_t t = 5000 * MS;
    int i;

    ana_init(&g_ana);
    /* A single sample has no interval yet. */
    ana_tick(&g_ana, t);
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 0.0);

    /* 100 packets of 1000 bytes in 100 ms. */
    record_n(100, 1000);
    t += 100 * MS;
    ana_tick(&g_ana, t);
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 1000.0);
    CHECK_NEAR(s.bytes_per_sec, 1e6);

    /* Steady 50 pkt / 100 ms of 200 bytes for 2 s: once the 1 s window has
     * rolled past the first burst the rate is exactly the steady one. */
    for (i = 0; i < 20; i++) {
        record_n(50, 200);
        t += 100 * MS;
        ana_tick(&g_ana, t);
    }
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 500.0);
    CHECK_NEAR(s.bytes_per_sec, 100000.0);

    /* Half-way through an idle second the rate has halved... */
    for (i = 0; i < 5; i++) {
        t += 100 * MS;
        ana_tick(&g_ana, t);
    }
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 250.0);

    /* ...and a full idle window later it is zero. */
    for (i = 0; i < 5; i++) {
        t += 100 * MS;
        ana_tick(&g_ana, t);
    }
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 0.0);
    CHECK_NEAR(s.bytes_per_sec, 0.0);

    /* A repeated timestamp does not divide by zero. */
    ana_init(&g_ana);
    ana_tick(&g_ana, t);
    record_n(5, 10);
    ana_tick(&g_ana, t);
    ana_snapshot(&g_ana, &s);
    CHECK_NEAR(s.pps, 0.0);
    ana_destroy(&g_ana);
}

static void test_alert_queue(void)
{
    struct ana_alert_rec r[ANA_ALERT_CAP + 8];
    struct ana_snapshot s;
    struct det_alert a;
    size_t n, i;
    uint32_t k;

    ana_init(&g_ana);
    for (k = 1; k <= 3; k++) {
        a = alert_n(k);
        ana_push_alert(&g_ana, &a);
    }
    n = ana_alerts_since(&g_ana, 0, r, 8);
    CHECK_EQ(n, 3);
    for (i = 0; i < n; i++) {
        CHECK_EQ(r[i].seq, i + 1);
        CHECK_EQ(r[i].alert.src_ip, i + 1);
        CHECK_EQ(r[i].alert.type, DET_PORT_SCAN_DETECTED);
    }
    n = ana_alerts_since(&g_ana, 2, r, 8);
    CHECK_EQ(n, 1);
    CHECK_EQ(r[0].seq, 3);
    CHECK_EQ(ana_alerts_since(&g_ana, 3, r, 8), 0);
    CHECK_EQ(ana_alerts_since(&g_ana, 99, r, 8), 0);
    /* max is honoured. */
    CHECK_EQ(ana_alerts_since(&g_ana, 0, r, 2), 2);
    CHECK_EQ(r[1].seq, 2);

    /* Overflow keeps the newest ANA_ALERT_CAP. */
    for (k = 4; k <= 100; k++) {
        a = alert_n(k);
        ana_push_alert(&g_ana, &a);
    }
    n = ana_alerts_since(&g_ana, 0, r, ANA_ALERT_CAP + 8);
    CHECK_EQ(n, ANA_ALERT_CAP);
    CHECK_EQ(r[0].seq, 100 - ANA_ALERT_CAP + 1);
    CHECK_EQ(r[n - 1].seq, 100);
    CHECK_EQ(r[n - 1].alert.src_ip, 100);
    for (i = 1; i < n; i++)
        CHECK_EQ(r[i].seq, r[i - 1].seq + 1);
    /* A reader that fell behind resumes at the oldest one still kept. */
    n = ana_alerts_since(&g_ana, 10, r, ANA_ALERT_CAP + 8);
    CHECK_EQ(n, ANA_ALERT_CAP);
    n = ana_alerts_since(&g_ana, 90, r, ANA_ALERT_CAP + 8);
    CHECK_EQ(n, 10);
    CHECK_EQ(r[0].seq, 91);

    ana_snapshot(&g_ana, &s);
    CHECK_EQ(s.alerts, 100);
    ana_destroy(&g_ana);
}

/* ---- concurrency -------------------------------------------------------- */

#define STRESS_LEN 100u

static uint64_t g_iters = 2000000;
static atomic_int g_done;
static atomic_int g_bad;
static atomic_uint_fast64_t g_snapshots;

static void *writer(void *arg)
{
    static const enum pkt_l4 l4s[] = { PKT_L4_TCP, PKT_L4_UDP, PKT_L4_ICMP,
                                       PKT_L4_NONE, PKT_L4_TCP };
    static const enum pkt_status sts[] = { PKT_OK, PKT_OK, PKT_TRUNCATED,
                                           PKT_MALFORMED };
    uint64_t i;

    (void)arg;
    for (i = 0; i < g_iters; i++) {
        struct pkt_info p = pkt(PKT_L3_IPV4, l4s[i % 5], sts[i % 4]);

        ana_record(&g_ana, &p, STRESS_LEN);
    }
    atomic_store(&g_done, 1);
    return NULL;
}

static void *reader(void *arg)
{
    uint64_t last = 0;

    (void)arg;
    for (;;) {
        struct ana_snapshot s;
        uint64_t sum = 0;
        int i, done = atomic_load(&g_done);

        ana_snapshot(&g_ana, &s);
        for (i = 0; i < ANA_PROTO_COUNT; i++)
            sum += s.proto[i];
        /* A torn snapshot would break these cross-field invariants. */
        if (sum != s.packets || s.ok + s.truncated + s.malformed != s.packets ||
            s.bytes != s.packets * STRESS_LEN || s.packets < last ||
            s.packets > g_iters)
            atomic_fetch_add(&g_bad, 1);
        last = s.packets;
        atomic_fetch_add(&g_snapshots, 1);
        if (done)
            break;
    }
    return NULL;
}

static void *ticker(void *arg)
{
    uint64_t t = 0;

    (void)arg;
    while (!atomic_load(&g_done)) {
        struct ana_snapshot s;

        t += 100 * MS;
        ana_tick(&g_ana, t);
        ana_snapshot(&g_ana, &s);
        /* Both rates come from one consistent sample pair. */
        if (s.pps < 0.0 ||
            fabs(s.bytes_per_sec - s.pps * STRESS_LEN) >
                1e-9 * (s.bytes_per_sec + 1.0))
            atomic_fetch_add(&g_bad, 1);
    }
    return NULL;
}

#define STRESS_ALERTS 5000u

static void *alert_pusher(void *arg)
{
    uint32_t k;

    (void)arg;
    for (k = 1; k <= STRESS_ALERTS; k++) {
        struct det_alert a = alert_n(k);

        ana_push_alert(&g_ana, &a);
    }
    return NULL;
}

static void *alert_poller(void *arg)
{
    uint64_t last = 0;
    struct ana_alert_rec r[16];

    (void)arg;
    while (last < STRESS_ALERTS) {
        size_t i, n = ana_alerts_since(&g_ana, last, r, 16);

        for (i = 0; i < n; i++) {
            /* In order, never repeated, payload matches its seq. */
            if (r[i].seq <= last || r[i].alert.src_ip != r[i].seq)
                atomic_fetch_add(&g_bad, 1);
            last = r[i].seq;
        }
    }
    return NULL;
}

static void test_concurrent_snapshots(void)
{
    pthread_t w, rd[2], tk, ap, pl;
    struct ana_snapshot s;
    const char *env = getenv("ANA_STRESS_ITERS");
    int i;

    if (env != NULL && atoi(env) > 0)
        g_iters = (uint64_t)atoi(env);
    ana_init(&g_ana);
    atomic_init(&g_done, 0);
    atomic_init(&g_bad, 0);
    atomic_init(&g_snapshots, 0);

    for (i = 0; i < 2; i++)
        CHECK_EQ(pthread_create(&rd[i], NULL, reader, NULL), 0);
    CHECK_EQ(pthread_create(&tk, NULL, ticker, NULL), 0);
    CHECK_EQ(pthread_create(&pl, NULL, alert_poller, NULL), 0);
    CHECK_EQ(pthread_create(&ap, NULL, alert_pusher, NULL), 0);
    CHECK_EQ(pthread_create(&w, NULL, writer, NULL), 0);

    pthread_join(w, NULL);
    for (i = 0; i < 2; i++)
        pthread_join(rd[i], NULL);
    pthread_join(tk, NULL);
    pthread_join(ap, NULL);
    pthread_join(pl, NULL);

    ana_snapshot(&g_ana, &s);
    CHECK_EQ(atomic_load(&g_bad), 0);
    CHECK(atomic_load(&g_snapshots) > 2);
    CHECK_EQ(s.packets, g_iters);
    CHECK_EQ(s.alerts, STRESS_ALERTS);
    printf("  %llu packets, %llu consistent snapshots, %u alerts\n",
           (unsigned long long)s.packets,
           (unsigned long long)atomic_load(&g_snapshots), STRESS_ALERTS);
    ana_destroy(&g_ana);
}

int main(void)
{
    RUN(test_initial_state);
    RUN(test_protocol_and_status_counts);
    RUN(test_rates);
    RUN(test_alert_queue);
    RUN(test_concurrent_snapshots);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
