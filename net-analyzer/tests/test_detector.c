#include "detector.h"

#include <arpa/inet.h>
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

#define RUN(fn)                                                             \
    do {                                                                    \
        int before = g_failures;                                            \
        fn();                                                               \
        printf("%-44s %s\n", #fn, g_failures == before ? "ok" : "FAILED");  \
    } while (0)

#define MS 1000000ULL
#define SEC 1000000000ULL
#define T0 (1700000000ULL * SEC)

/* ~2.4 MiB each: keep them out of the stack. */
static struct detector g_det;

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return htonl((uint32_t)a << 24 | (uint32_t)b << 16 | (uint32_t)c << 8 | d);
}

static struct pkt_info tcp_pkt(uint32_t src, uint16_t dport, uint8_t flags)
{
    struct pkt_info p;

    memset(&p, 0, sizeof(p));
    p.status = PKT_OK;
    p.l3 = PKT_L3_IPV4;
    p.l4 = PKT_L4_TCP;
    p.src_ip = src;
    p.dst_ip = ip4(127, 0, 0, 1);
    p.src_port = 40000;
    p.dst_port = dport;
    p.tcp_flags = flags;
    return p;
}

/* Sends n SYNs to ports base..base+n-1 (mod ports_mod if nonzero), 1 ms
 * apart starting at t. Returns the number of alerts raised. */
static int burst(struct detector *d, uint32_t src, uint16_t base, int n,
                 unsigned ports_mod, uint64_t t, struct det_alert *last)
{
    int i, alerts = 0;

    for (i = 0; i < n; i++) {
        uint16_t port = (uint16_t)(ports_mod ? base + (unsigned)i % ports_mod
                                             : base + (unsigned)i);

        alerts += det_observe_syn(d, src, port, t + (uint64_t)i * MS, last);
    }
    return alerts;
}

static const struct det_source *find_source(const struct detector *d,
                                            uint32_t ip)
{
    int i;

    for (i = 0; i < DET_MAX_SOURCES; i++)
        if (d->sources[i].in_use && d->sources[i].ip == ip)
            return &d->sources[i];
    return NULL;
}

/* ---- thresholds --------------------------------------------------------- */

static void test_default_config(void)
{
    struct det_config c;

    det_default_config(&c);
    CHECK_EQ(c.window_ns, SEC);
    CHECK_EQ(c.syn_threshold, 30);
    CHECK_EQ(c.port_threshold, 20);
    CHECK(strcmp(det_event_str(DET_PORT_SCAN_DETECTED),
                 "PORT_SCAN_DETECTED") == 0);
    CHECK(strcmp(det_event_str(DET_NONE), "NONE") == 0);
}

static void test_syn_threshold_is_strict(void)
{
    struct det_alert a;
    uint32_t src = ip4(10, 0, 0, 1);

    det_init(&g_det, NULL);
    /* 30 SYNs to 30 ports: syn_count == 30 is not > 30. */
    CHECK_EQ(burst(&g_det, src, 1000, 30, 0, T0, &a), 0);
    /* The 31st crosses it. */
    memset(&a, 0, sizeof(a));
    CHECK_EQ(det_observe_syn(&g_det, src, 1030, T0 + 30 * MS, &a), 1);
    CHECK_EQ(a.type, DET_PORT_SCAN_DETECTED);
    CHECK_EQ(a.src_ip, src);
    CHECK_EQ(a.syn_count, 31);
    CHECK_EQ(a.distinct_ports, 31);
    CHECK_EQ(a.last_dst_port, 1030);
    CHECK_EQ(a.ts_ns, T0 + 30 * MS);
}

static void test_port_threshold_is_strict(void)
{
    struct det_alert a;
    struct det_source_stats st;
    uint32_t src = ip4(10, 0, 0, 2);

    det_init(&g_det, NULL);
    /* 60 SYNs cycling over exactly 20 ports: distinct == 20 is not > 20. */
    CHECK_EQ(burst(&g_det, src, 2000, 60, 20, T0, &a), 0);
    CHECK_EQ(det_query(&g_det, src, T0 + 59 * MS, &st), 0);
    CHECK_EQ(st.syn_count, 60);
    CHECK_EQ(st.distinct_ports, 20);
    CHECK(!st.alerting);
    /* A 21st distinct port crosses it. */
    CHECK_EQ(det_observe_syn(&g_det, src, 2020, T0 + 60 * MS, &a), 1);
    CHECK_EQ(a.syn_count, 61);
    CHECK_EQ(a.distinct_ports, 21);
}

static void test_many_ports_few_syns(void)
{
    struct det_alert a;

    det_init(&g_det, NULL);
    /* 25 distinct ports but only 25 SYNs: needs both conditions. */
    CHECK_EQ(burst(&g_det, ip4(10, 0, 0, 3), 1, 25, 0, T0, &a), 0);
}

static void test_single_port_flood(void)
{
    struct det_alert a;

    det_init(&g_det, NULL);
    /* A SYN flood against one service is not a port scan. */
    CHECK_EQ(burst(&g_det, ip4(10, 0, 0, 4), 80, 1000, 1, T0, &a), 0);
}

static void test_only_initial_syns_count(void)
{
    struct det_alert a;
    struct det_stats ds;
    struct pkt_info p;
    uint32_t src = ip4(10, 0, 0, 5);
    int i, alerts = 0;

    det_init(&g_det, NULL);
    for (i = 0; i < 200; i++) {
        uint64_t t = T0 + (uint64_t)i * MS;

        /* SYN-ACK (a server answering), plain ACK, RST: all ignored. */
        p = tcp_pkt(src, (uint16_t)(3000 + i), PKT_TCP_SYN | PKT_TCP_ACK);
        alerts += det_observe(&g_det, &p, t, &a);
        p = tcp_pkt(src, (uint16_t)(3000 + i), PKT_TCP_ACK);
        alerts += det_observe(&g_det, &p, t, &a);
        p = tcp_pkt(src, (uint16_t)(3000 + i), PKT_TCP_RST);
        alerts += det_observe(&g_det, &p, t, &a);
        /* UDP to many ports is not a SYN scan. */
        p = tcp_pkt(src, (uint16_t)(3000 + i), 0);
        p.l4 = PKT_L4_UDP;
        alerts += det_observe(&g_det, &p, t, &a);
        /* Non-IPv4 frames never reach the table. */
        p = tcp_pkt(src, (uint16_t)(3000 + i), PKT_TCP_SYN);
        p.l3 = PKT_L3_IPV6;
        alerts += det_observe(&g_det, &p, t, &a);
    }
    CHECK_EQ(alerts, 0);
    det_get_stats(&g_det, &ds);
    CHECK_EQ(ds.syns_seen, 0);
    CHECK_EQ(ds.tracked, 0);

    /* SYN with other flags (e.g. ECN setup SYN+ECE+CWR) still counts. */
    for (i = 0; i < 31; i++) {
        p = tcp_pkt(src, (uint16_t)(4000 + i),
                    PKT_TCP_SYN | PKT_TCP_ECE | PKT_TCP_CWR);
        alerts += det_observe(&g_det, &p, T0 + (uint64_t)i * MS, &a);
    }
    CHECK_EQ(alerts, 1);
    CHECK_EQ(a.syn_count, 31);
}

/* ---- sliding window ----------------------------------------------------- */

static void test_window_expiry_boundary(void)
{
    struct det_source_stats st;
    uint32_t src = ip4(10, 0, 1, 1);

    det_init(&g_det, NULL);
    det_observe_syn(&g_det, src, 1, T0, NULL);
    CHECK_EQ(det_query(&g_det, src, T0 + SEC - 1, &st), 0);
    CHECK_EQ(st.syn_count, 1);
    CHECK_EQ(st.distinct_ports, 1);
    /* Exactly one window later the event is out. */
    CHECK_EQ(det_query(&g_det, src, T0 + SEC, &st), 0);
    CHECK_EQ(st.syn_count, 0);
    CHECK_EQ(st.distinct_ports, 0);
    CHECK_EQ(det_query(&g_det, ip4(1, 2, 3, 4), T0, &st), -1);
}

static void test_expired_syns_do_not_accumulate(void)
{
    struct det_alert a;
    struct det_source_stats st;
    const struct det_source *s;
    uint32_t src = ip4(10, 0, 1, 2);

    det_init(&g_det, NULL);
    /* 30 SYNs, then the 31st arrives just after the first expired. */
    CHECK_EQ(burst(&g_det, src, 100, 30, 0, T0, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 200, T0 + SEC, &a), 0);
    CHECK_EQ(det_query(&g_det, src, T0 + SEC, &st), 0);
    CHECK_EQ(st.syn_count, 30);
    s = find_source(&g_det, src);
    CHECK(s != NULL);
    if (s != NULL) {
        CHECK_EQ(s->ev_count, 30);
        CHECK_EQ(s->distinct, 30);
    }

    /* After a long pause the whole window has emptied. */
    CHECK_EQ(det_observe_syn(&g_det, src, 300, T0 + 10 * SEC, &a), 0);
    CHECK_EQ(det_query(&g_det, src, T0 + 10 * SEC, &st), 0);
    CHECK_EQ(st.syn_count, 1);
    CHECK_EQ(st.distinct_ports, 1);
}

static void test_slow_scan_stays_below(void)
{
    struct det_alert a;
    int i, alerts = 0;
    uint32_t src = ip4(10, 0, 1, 3);

    det_init(&g_det, NULL);
    /* 20 SYN/s to fresh ports for 10 s: 200 ports but at most 20 per
     * window. */
    for (i = 0; i < 200; i++)
        alerts += det_observe_syn(&g_det, src, (uint16_t)(1 + i),
                                  T0 + (uint64_t)i * 50 * MS, &a);
    CHECK_EQ(alerts, 0);
}

static void test_window_slides_across_second_boundary(void)
{
    struct det_alert a;
    uint32_t src = ip4(10, 0, 1, 4);

    det_init(&g_det, NULL);
    /* 16 SYNs just before a whole second and 16 just after: a tumbling
     * 1 s bucket would see 16 + 16 and miss this; a sliding window sees 32
     * within 200 ms. */
    CHECK_EQ(burst(&g_det, src, 500, 16, 0, T0 + 850 * MS, &a), 0);
    CHECK_EQ(burst(&g_det, src, 600, 16, 0, T0 + 1050 * MS, &a), 1);
    CHECK_EQ(a.syn_count, 31);
    CHECK_EQ(a.distinct_ports, 31);
}

static void test_custom_window(void)
{
    struct det_config c;
    struct det_alert a;
    uint32_t src = ip4(10, 0, 1, 5);

    det_default_config(&c);
    c.window_ns = 100 * MS;
    c.syn_threshold = 5;
    c.port_threshold = 3;
    det_init(&g_det, &c);
    /* 6 SYNs 30 ms apart span 150 ms > window: never more than 4 at once. */
    CHECK_EQ(det_observe_syn(&g_det, src, 1, T0, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 2, T0 + 30 * MS, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 3, T0 + 60 * MS, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 4, T0 + 90 * MS, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 5, T0 + 120 * MS, &a), 0);
    CHECK_EQ(det_observe_syn(&g_det, src, 6, T0 + 150 * MS, &a), 0);
    /* 6 SYNs 10 ms apart fit in the window. */
    CHECK_EQ(burst(&g_det, src, 10, 6, 0, T0 + SEC, &a), 1);
    CHECK_EQ(a.syn_count, 6);
}

static void test_clock_going_backwards(void)
{
    struct det_alert a;
    struct det_source_stats st;
    uint32_t src = ip4(10, 0, 1, 6);
    int i, alerts = 0;

    det_init(&g_det, NULL);
    det_observe_syn(&g_det, src, 1, T0 + 5 * SEC, &a);
    /* A wall-clock step back must not underflow window arithmetic: the
     * detector clamps to the latest time it has seen. */
    for (i = 0; i < 40; i++)
        alerts += det_observe_syn(&g_det, src, (uint16_t)(10 + i), T0, &a);
    CHECK_EQ(alerts, 1);
    CHECK_EQ(det_query(&g_det, src, T0, &st), 0);
    CHECK_EQ(st.syn_count, 41);
}

/* ---- alert cadence ------------------------------------------------------ */

static void test_one_alert_per_episode_then_realert(void)
{
    struct det_alert a;
    uint32_t src = ip4(10, 0, 2, 1);
    int i, alerts = 0;

    det_init(&g_det, NULL);
    /* A sustained 1000 SYN/s scan for 12 s over 12000 ports. */
    for (i = 0; i < 12000; i++)
        alerts += det_observe_syn(&g_det, src, (uint16_t)(1 + i),
                                  T0 + (uint64_t)i * MS, &a);
    /* First alert at the 31st SYN, then one every 5 s while it continues. */
    CHECK_EQ(alerts, 3);

    /* It stops for 2 s, which re-arms the source, then resumes. */
    CHECK_EQ(det_observe_syn(&g_det, src, 1, T0 + 14 * SEC, &a), 0);
    CHECK_EQ(burst(&g_det, src, 20000, 40, 0, T0 + 14 * SEC + MS, &a), 1);
}

static void test_independent_sources(void)
{
    struct det_alert a;
    uint32_t attacker = ip4(192, 168, 1, 66);
    int i, client_alerts = 0, attacker_alerts = 0;

    det_init(&g_det, NULL);
    /* 50 clients each open 10 connections to one service (plus one client
     * browsing 25 ports slowly), interleaved with an attacker hitting 40
     * ports: only the attacker is flagged. */
    for (i = 0; i < 500; i++) {
        uint32_t client = ip4(172, 16, 0, (uint8_t)(1 + i % 50));

        client_alerts += det_observe_syn(&g_det, client,
                                         (uint16_t)(8000 + i % 10),
                                         T0 + (uint64_t)i * MS, &a);
        if (i % 20 == 0)
            client_alerts += det_observe_syn(&g_det, ip4(172, 16, 1, 1),
                                             (uint16_t)(9000 + i / 20),
                                             T0 + (uint64_t)i * MS, &a);
        if (i < 40 &&
            det_observe_syn(&g_det, attacker, (uint16_t)(1 + i),
                            T0 + (uint64_t)i * MS, &a)) {
            CHECK_EQ(a.src_ip, attacker);
            attacker_alerts++;
        }
    }
    CHECK_EQ(client_alerts, 0);
    CHECK_EQ(attacker_alerts, 1);
}

/* ---- table capacity and LRU --------------------------------------------- */

static void test_lru_eviction_order(void)
{
    struct det_stats ds;
    struct det_source_stats st;
    uint32_t i;

    det_init(&g_det, NULL);
    for (i = 0; i < DET_MAX_SOURCES; i++)
        det_observe_syn(&g_det, htonl(0x0A000000u + i), 80, T0 + i, NULL);
    det_get_stats(&g_det, &ds);
    CHECK_EQ(ds.tracked, DET_MAX_SOURCES);
    CHECK_EQ(ds.evictions, 0);

    /* Touch the oldest source so the second-oldest becomes the victim. */
    det_observe_syn(&g_det, htonl(0x0A000000u), 81, T0 + 5000, NULL);
    det_observe_syn(&g_det, htonl(0x0B000000u), 80, T0 + 5001, NULL);
    det_get_stats(&g_det, &ds);
    CHECK_EQ(ds.tracked, DET_MAX_SOURCES);
    CHECK_EQ(ds.evictions, 1);
    CHECK_EQ(det_query(&g_det, htonl(0x0A000000u), T0 + 5001, &st), 0);
    CHECK_EQ(st.syn_count, 2);
    CHECK_EQ(det_query(&g_det, htonl(0x0A000001u), T0 + 5001, &st), -1);
    CHECK_EQ(det_query(&g_det, htonl(0x0A000002u), T0 + 5001, &st), 0);
    CHECK_EQ(det_query(&g_det, htonl(0x0B000000u), T0 + 5001, &st), 0);
    CHECK_EQ(st.syn_count, 1);

    /* Further new sources evict in insertion order: 2, 3, 4. */
    for (i = 0; i < 3; i++)
        det_observe_syn(&g_det, htonl(0x0C000000u + i), 80, T0 + 6000 + i,
                        NULL);
    for (i = 2; i <= 4; i++)
        CHECK_EQ(det_query(&g_det, htonl(0x0A000000u + i), T0 + 7000, &st),
                 -1);
    CHECK_EQ(det_query(&g_det, htonl(0x0A000005u), T0 + 7000, &st), 0);
}

static void test_evicted_source_starts_fresh(void)
{
    struct det_alert a;
    struct det_source_stats st;
    uint32_t victim = ip4(10, 9, 9, 9);
    uint32_t i;

    det_init(&g_det, NULL);
    CHECK_EQ(burst(&g_det, victim, 1, 25, 0, T0, &a), 0);
    for (i = 0; i < DET_MAX_SOURCES; i++)
        det_observe_syn(&g_det, htonl(0x0A000000u + i), 80, T0 + 30 * MS, NULL);
    CHECK_EQ(det_query(&g_det, victim, T0 + 30 * MS, &st), -1);
    /* Back with 25 more: its earlier 25 were forgotten, so no alert. */
    CHECK_EQ(burst(&g_det, victim, 100, 25, 0, T0 + 40 * MS, &a), 0);
    CHECK_EQ(det_query(&g_det, victim, T0 + 70 * MS, &st), 0);
    CHECK_EQ(st.syn_count, 25);
    CHECK_EQ(st.distinct_ports, 25);
}

static void test_many_sources_churn(void)
{
    struct det_alert a;
    struct det_stats ds;
    uint32_t attacker = ip4(203, 0, 113, 7);
    uint32_t i;
    int alerts = 0, attacker_alerts = 0;

    det_init(&g_det, NULL);
    /* 100k one-off sources (e.g. a SYN flood with random spoofed sources),
     * 10 per ms, with a scanner mixed in every 2 ms. The scanner keeps
     * itself hot in the LRU and is still detected; nobody else is. */
    for (i = 0; i < 100000; i++) {
        uint64_t t = T0 + (uint64_t)i * 100000;   /* 100 us */

        alerts += det_observe_syn(&g_det, htonl(0x64000000u + i),
                                  (uint16_t)(1 + i % 60000), t, &a);
        if (i % 20 == 0 && i < 2000 &&
            det_observe_syn(&g_det, attacker, (uint16_t)(1 + i / 20), t, &a)) {
            CHECK_EQ(a.src_ip, attacker);
            attacker_alerts++;
        }
    }
    CHECK_EQ(alerts, 0);
    CHECK_EQ(attacker_alerts, 1);
    det_get_stats(&g_det, &ds);
    CHECK_EQ(ds.tracked, DET_MAX_SOURCES);
    CHECK_EQ(ds.evictions, 100000 + 1 - DET_MAX_SOURCES);
    CHECK_EQ(ds.syns_seen, 100000 + 100);
    CHECK_EQ(ds.alerts, 1);
}

static void test_many_simultaneous_scanners(void)
{
    struct det_alert a;
    struct det_stats ds;
    uint32_t i, j;
    int alerts = 0;

    det_init(&g_det, NULL);
    /* Every table entry scans at once, round-robin: all 1024 are flagged
     * exactly once. */
    for (j = 0; j < 40; j++)
        for (i = 0; i < DET_MAX_SOURCES; i++)
            alerts += det_observe_syn(&g_det, htonl(0x0A000000u + i),
                                      (uint16_t)(1 + j),
                                      T0 + j * 10 * MS + i, &a);
    CHECK_EQ(alerts, DET_MAX_SOURCES);
    det_get_stats(&g_det, &ds);
    CHECK_EQ(ds.evictions, 0);
}

/* ---- event cap and the port multiset ------------------------------------ */

static void test_event_cap_saturates(void)
{
    struct det_alert a;
    struct det_source_stats st;
    uint32_t src = ip4(10, 0, 3, 1);
    int alerts;

    det_init(&g_det, NULL);
    /* 1000 SYNs at 1000/s: far more than DET_EVENT_CAP per window. */
    alerts = burst(&g_det, src, 1, 1000, 0, T0, &a);
    CHECK_EQ(alerts, 1);
    CHECK_EQ(det_query(&g_det, src, T0 + 999 * MS, &st), 0);
    CHECK_EQ(st.syn_count, DET_EVENT_CAP);
    CHECK_EQ(st.distinct_ports, DET_EVENT_CAP);
    CHECK(st.alerting);
}

/* Randomised cross-check of the incremental distinct-port count (hash
 * multiset with backward-shift deletion) against a brute-force recount. */
static void test_distinct_ports_match_recount(void)
{
    struct det_config c;
    struct det_source_stats st;
    const struct det_source *s;
    uint32_t src = ip4(10, 0, 3, 2);
    uint64_t t = T0;
    uint32_t rnd = 12345;
    int i, bad = 0;

    det_default_config(&c);
    c.syn_threshold = 1000000;       /* just exercise the counting */
    det_init(&g_det, &c);
    for (i = 0; i < 100000; i++) {
        uint16_t port;

        rnd = rnd * 1103515245u + 12345u;
        /* Few distinct values collide heavily in the 256-slot table; a
         * wide range exercises wrap-around of probe chains. */
        port = (uint16_t)((i & 1) ? (rnd >> 16) % 300 : (rnd >> 8));
        t += (rnd >> 24) * 50000ULL;    /* 0..12.75 ms steps */
        det_observe_syn(&g_det, src, port, t, NULL);
        s = find_source(&g_det, src);   /* the only entry: index 0 */
        if (s == NULL || det_query(&g_det, src, t, &st) != 0 ||
            s->distinct != st.distinct_ports || s->ev_count != st.syn_count)
            bad++;
    }
    CHECK_EQ(bad, 0);
}

int main(void)
{
    RUN(test_default_config);
    RUN(test_syn_threshold_is_strict);
    RUN(test_port_threshold_is_strict);
    RUN(test_many_ports_few_syns);
    RUN(test_single_port_flood);
    RUN(test_only_initial_syns_count);
    RUN(test_window_expiry_boundary);
    RUN(test_expired_syns_do_not_accumulate);
    RUN(test_slow_scan_stays_below);
    RUN(test_window_slides_across_second_boundary);
    RUN(test_custom_window);
    RUN(test_clock_going_backwards);
    RUN(test_one_alert_per_episode_then_realert);
    RUN(test_independent_sources);
    RUN(test_lru_eviction_order);
    RUN(test_evicted_source_starts_fresh);
    RUN(test_many_sources_churn);
    RUN(test_many_simultaneous_scanners);
    RUN(test_event_cap_saturates);
    RUN(test_distinct_ports_match_recount);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
