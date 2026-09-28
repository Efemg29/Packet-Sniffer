#include "ring_buffer.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
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

/* ---- helpers ------------------------------------------------------------ */

/* Deterministic per-sequence frame length in [1, MAX_PACKET_LEN]. */
static uint32_t seq_len(uint64_t seq)
{
    uint64_t x = seq * 0x9E3779B97F4A7C15ULL;

    /* Mostly small frames, with an occasional full-size one. */
    if ((seq & 1023) == 7)
        return MAX_PACKET_LEN;
    return (uint32_t)(1 + (x >> 40) % 1600);
}

static uint8_t seq_byte(uint64_t seq, size_t i)
{
    return (uint8_t)(seq * 31 + i * 7);
}

/* Writes the sequence number into the first bytes plus a checkable tail. */
static void fill(struct rb_slot *s, uint64_t seq)
{
    uint32_t len = seq_len(seq);
    size_t i;

    s->cap_len = len;
    s->orig_len = len + 4;
    s->pkttype = (uint8_t)(seq & 7);
    s->ts.tv_sec = (time_t)seq;
    s->ts.tv_nsec = (long)(seq % 1000000000);
    for (i = 0; i < len && i < 8; i++)
        s->data[i] = (uint8_t)(seq >> (8 * i));
    for (; i < len; i++)
        s->data[i] = seq_byte(seq, i);
}

static int verify(const struct rb_slot *s, uint64_t seq)
{
    uint32_t len = seq_len(seq);
    uint64_t got = 0;
    size_t i;

    if (s->cap_len != len || s->orig_len != len + 4 ||
        s->pkttype != (uint8_t)(seq & 7) || s->ts.tv_sec != (time_t)seq ||
        s->ts.tv_nsec != (long)(seq % 1000000000))
        return 0;
    for (i = 0; i < len && i < 8; i++)
        got |= (uint64_t)s->data[i] << (8 * i);
    if (len >= 8 && got != seq)
        return 0;
    /* Checking every byte of every frame is slow under TSan; sample. */
    for (; i < len; i += 1 + (i >> 4))
        if (s->data[i] != seq_byte(seq, i))
            return 0;
    return s->data[len - 1] == (len > 8 ? seq_byte(seq, len - 1)
                                        : (uint8_t)(seq >> (8 * (len - 1))));
}

/* ---- single-threaded tests --------------------------------------------- */

static void test_init_rounds_to_pow2(void)
{
    struct ring_buffer rb;

    CHECK_EQ(rb_init(&rb, 5), 0);
    CHECK_EQ(rb.capacity, 8);
    CHECK_EQ(rb.mask, 7);
    rb_destroy(&rb);

    CHECK_EQ(rb_init(&rb, 1), 0);
    CHECK_EQ(rb.capacity, 2);
    rb_destroy(&rb);

    CHECK_EQ(rb_init(&rb, 16), 0);
    CHECK_EQ(rb.capacity, 16);
    rb_destroy(&rb);
}

static void test_init_rejects_bad_args(void)
{
    struct ring_buffer rb;

    errno = 0;
    CHECK_EQ(rb_init(&rb, 0), -1);
    CHECK_EQ(errno, EINVAL);
    errno = 0;
    CHECK_EQ(rb_init(NULL, 4), -1);
    CHECK_EQ(errno, EINVAL);
    errno = 0;
    CHECK_EQ(rb_init(&rb, SIZE_MAX), -1);
    CHECK_EQ(errno, EOVERFLOW);
}

static void test_destroy_is_idempotent(void)
{
    struct ring_buffer rb;

    CHECK_EQ(rb_init(&rb, 4), 0);
    rb_destroy(&rb);
    rb_destroy(&rb);
    rb_destroy(NULL);
    CHECK(rb.slots == NULL);
}

static void test_empty_ring(void)
{
    struct ring_buffer rb;
    struct rb_stats st;

    CHECK_EQ(rb_init(&rb, 4), 0);
    CHECK(rb_peek(&rb) == NULL);
    rb_get_stats(&rb, &st);
    CHECK_EQ(st.pushed, 0);
    CHECK_EQ(st.popped, 0);
    CHECK_EQ(st.dropped, 0);
    CHECK_EQ(st.in_use, 0);
    rb_destroy(&rb);
}

static void test_fifo_order(void)
{
    struct ring_buffer rb;
    uint64_t i;

    CHECK_EQ(rb_init(&rb, 8), 0);
    for (i = 0; i < 5; i++) {
        struct rb_slot *s = rb_reserve(&rb);

        CHECK(s != NULL);
        if (s == NULL)
            break;
        fill(s, i);
        rb_commit(&rb);
    }
    for (i = 0; i < 5; i++) {
        const struct rb_slot *s = rb_peek(&rb);

        CHECK(s != NULL);
        if (s == NULL)
            break;
        CHECK(verify(s, i));
        rb_release(&rb);
    }
    CHECK(rb_peek(&rb) == NULL);
    rb_destroy(&rb);
}

static void test_reserve_without_commit_is_invisible(void)
{
    struct ring_buffer rb;
    struct rb_slot *a, *b;

    CHECK_EQ(rb_init(&rb, 4), 0);
    a = rb_reserve(&rb);
    CHECK(a != NULL);
    CHECK(rb_peek(&rb) == NULL);
    /* Reserving again without commit hands back the same slot. */
    b = rb_reserve(&rb);
    CHECK(a == b);
    rb_destroy(&rb);
}

static void test_full_ring_and_drops(void)
{
    struct ring_buffer rb;
    struct rb_stats st;
    size_t i;

    CHECK_EQ(rb_init(&rb, 4), 0);
    for (i = 0; i < 4; i++) {
        struct rb_slot *s = rb_reserve(&rb);

        CHECK(s != NULL);
        if (s == NULL)
            break;
        fill(s, i);
        rb_commit(&rb);
    }
    CHECK(rb_reserve(&rb) == NULL);
    rb_record_drop(&rb);
    rb_record_drop(&rb);
    CHECK(rb_reserve(&rb) == NULL);

    rb_get_stats(&rb, &st);
    CHECK_EQ(st.pushed, 4);
    CHECK_EQ(st.dropped, 2);
    CHECK_EQ(st.in_use, 4);

    /* Freeing one slot makes exactly one slot reservable again. */
    CHECK(rb_peek(&rb) != NULL);
    rb_release(&rb);
    CHECK(rb_reserve(&rb) != NULL);
    rb_commit(&rb);
    CHECK(rb_reserve(&rb) == NULL);

    for (i = 1; i < 4; i++) {
        const struct rb_slot *s = rb_peek(&rb);

        CHECK(s != NULL && verify(s, i));
        rb_release(&rb);
    }
    rb_get_stats(&rb, &st);
    CHECK_EQ(st.pushed, 5);
    CHECK_EQ(st.popped, 4);
    CHECK_EQ(st.in_use, 1);
    rb_destroy(&rb);
}

static void test_wraparound(void)
{
    struct ring_buffer rb;
    uint64_t produced = 0, consumed = 0;
    int round;

    CHECK_EQ(rb_init(&rb, 4), 0);
    /* Uneven batch sizes so head/tail cross the mask boundary many times. */
    for (round = 0; round < 1000; round++) {
        int burst = 1 + round % 4, k;

        for (k = 0; k < burst; k++) {
            struct rb_slot *s = rb_reserve(&rb);

            if (s == NULL)
                break;
            fill(s, produced++);
            rb_commit(&rb);
        }
        for (k = 0; k < 1 + (round * 7) % 4; k++) {
            const struct rb_slot *s = rb_peek(&rb);

            if (s == NULL)
                break;
            if (!verify(s, consumed)) {
                CHECK(!"payload mismatch after wraparound");
                rb_destroy(&rb);
                return;
            }
            consumed++;
            rb_release(&rb);
        }
    }
    CHECK(produced > 1000);
    CHECK(produced - consumed <= rb.capacity);
    rb_destroy(&rb);
}

static void test_slot_holds_max_packet(void)
{
    struct ring_buffer rb;
    struct rb_slot *s;
    const struct rb_slot *r;

    CHECK_EQ(rb_init(&rb, 2), 0);
    s = rb_reserve(&rb);
    CHECK(s != NULL);
    if (s == NULL) {
        rb_destroy(&rb);
        return;
    }
    CHECK_EQ(sizeof(s->data), MAX_PACKET_LEN);
    memset(s->data, 0xAB, MAX_PACKET_LEN);
    s->cap_len = MAX_PACKET_LEN;
    s->orig_len = 70000;
    rb_commit(&rb);
    r = rb_peek(&rb);
    CHECK(r != NULL && r->cap_len == MAX_PACKET_LEN && r->orig_len == 70000);
    CHECK(r != NULL && r->data[0] == 0xAB && r->data[MAX_PACKET_LEN - 1] == 0xAB);
    rb_release(&rb);
    rb_destroy(&rb);
}

static void test_slots_do_not_overlap(void)
{
    struct ring_buffer rb;
    size_t i;

    CHECK_EQ(rb_init(&rb, 4), 0);
    for (i = 0; i + 1 < rb.capacity; i++)
        CHECK((const uint8_t *)&rb.slots[i + 1] >=
              rb.slots[i].data + MAX_PACKET_LEN);
    /* head and tail must live on different cache lines. */
    CHECK((size_t)((const char *)&rb.tail - (const char *)&rb.head) >=
          RB_CACHELINE);
    rb_destroy(&rb);
}

/* ---- multi-threaded stress --------------------------------------------- */

struct stress {
    struct ring_buffer rb;
    uint64_t total;           /* packets the producer offers */
    int lossy;                /* 1: drop when full; 0: spin until space */
    uint64_t produced;        /* written by producer only */
    uint64_t consumed;        /* written by consumer only */
    uint64_t errors;          /* written by consumer only */
    atomic_int producer_done;
};

static void *stress_producer(void *arg)
{
    struct stress *st = arg;
    uint64_t seq = 0, offered;

    for (offered = 0; offered < st->total; offered++) {
        struct rb_slot *s;

        while ((s = rb_reserve(&st->rb)) == NULL) {
            if (st->lossy)
                break;
            sched_yield();
        }
        if (s == NULL) {
            rb_record_drop(&st->rb);
            continue;
        }
        fill(s, seq++);
        rb_commit(&st->rb);
    }
    st->produced = seq;
    atomic_store_explicit(&st->producer_done, 1, memory_order_release);
    return NULL;
}

static void *stress_consumer(void *arg)
{
    struct stress *st = arg;
    uint64_t expect = 0;

    for (;;) {
        const struct rb_slot *s = rb_peek(&st->rb);

        if (s == NULL) {
            if (atomic_load_explicit(&st->producer_done, memory_order_acquire) &&
                (s = rb_peek(&st->rb)) == NULL)
                break;
            if (s == NULL) {
                sched_yield();
                continue;
            }
        }
        /* Seq numbers are dense because drops never consume a seq. */
        if (!verify(s, expect))
            st->errors++;
        expect++;
        rb_release(&st->rb);
        /* Slow the consumer down now and then so the ring fills up. */
        if (st->lossy && (expect & 63) == 0)
            sched_yield();
    }
    st->consumed = expect;
    return NULL;
}

static void run_stress(size_t slots, uint64_t total, int lossy)
{
    struct stress st;
    struct rb_stats rs;
    pthread_t p, c;

    memset(&st, 0, sizeof(st));
    st.total = total;
    st.lossy = lossy;
    atomic_init(&st.producer_done, 0);
    CHECK_EQ(rb_init(&st.rb, slots), 0);

    CHECK_EQ(pthread_create(&c, NULL, stress_consumer, &st), 0);
    CHECK_EQ(pthread_create(&p, NULL, stress_producer, &st), 0);
    pthread_join(p, NULL);
    pthread_join(c, NULL);

    rb_get_stats(&st.rb, &rs);
    CHECK_EQ(st.errors, 0);
    CHECK_EQ(st.consumed, st.produced);
    CHECK_EQ(rs.pushed, st.produced);
    CHECK_EQ(rs.popped, st.consumed);
    CHECK_EQ(rs.pushed + rs.dropped, total);
    CHECK_EQ(rs.in_use, 0);
    if (!lossy)
        CHECK_EQ(rs.dropped, 0);
    printf("    %zu slots, %llu offered: %llu delivered, %llu dropped\n",
           st.rb.capacity, (unsigned long long)total,
           (unsigned long long)rs.pushed, (unsigned long long)rs.dropped);
    rb_destroy(&st.rb);
}

static uint64_t stress_iters(void)
{
    const char *e = getenv("RB_STRESS_ITERS");

    return e != NULL ? strtoull(e, NULL, 10) : 1000000ULL;
}

static void test_stress_lossless(void)
{
    run_stress(8, stress_iters(), 0);
    run_stress(2, stress_iters() / 4, 0);
}

static void test_stress_lossy(void)
{
    run_stress(16, stress_iters(), 1);
}

int main(void)
{
    RUN(test_init_rounds_to_pow2);
    RUN(test_init_rejects_bad_args);
    RUN(test_destroy_is_idempotent);
    RUN(test_empty_ring);
    RUN(test_fifo_order);
    RUN(test_reserve_without_commit_is_invisible);
    RUN(test_full_ring_and_drops);
    RUN(test_wraparound);
    RUN(test_slot_holds_max_packet);
    RUN(test_slots_do_not_overlap);
    RUN(test_stress_lossless);
    RUN(test_stress_lossy);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
