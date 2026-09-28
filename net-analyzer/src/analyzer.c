#include "analyzer.h"

#include <string.h>

#define RELAXED memory_order_relaxed

static void bump(atomic_uint_fast64_t *c, uint64_t n)
{
    /* Single writer: a plain load + store is enough and avoids a locked RMW. */
    atomic_store_explicit(c, atomic_load_explicit(c, RELAXED) + n, RELAXED);
}

static enum ana_proto classify(const struct pkt_info *info)
{
    if (info->l3 != PKT_L3_IPV4)
        return ANA_PROTO_OTHER;
    switch (info->l4) {
    case PKT_L4_TCP:  return ANA_PROTO_TCP;
    case PKT_L4_UDP:  return ANA_PROTO_UDP;
    case PKT_L4_ICMP: return ANA_PROTO_ICMP;
    case PKT_L4_NONE:
    case PKT_L4_OTHER:
        break;
    }
    return ANA_PROTO_OTHER;
}

static uint64_t dbl_bits(double v)
{
    uint64_t b;

    memcpy(&b, &v, sizeof(b));
    return b;
}

static double bits_dbl(uint64_t b)
{
    double v;

    memcpy(&v, &b, sizeof(v));
    return v;
}

int ana_init(struct analyzer *a)
{
    int i;

    memset(a, 0, sizeof(*a));
    atomic_init(&a->seq, 0);
    atomic_init(&a->packets, 0);
    atomic_init(&a->bytes, 0);
    for (i = 0; i < ANA_PROTO_COUNT; i++)
        atomic_init(&a->proto[i], 0);
    atomic_init(&a->ok, 0);
    atomic_init(&a->truncated, 0);
    atomic_init(&a->malformed, 0);
    atomic_init(&a->rate_seq, 0);
    atomic_init(&a->pps_bits, dbl_bits(0.0));
    atomic_init(&a->bps_bits, dbl_bits(0.0));
    atomic_init(&a->alerts_total, 0);
    a->next_alert_seq = 1;
    return pthread_mutex_init(&a->alert_lock, NULL);
}

void ana_destroy(struct analyzer *a)
{
    pthread_mutex_destroy(&a->alert_lock);
}

void ana_record(struct analyzer *a, const struct pkt_info *info,
                uint32_t wire_len)
{
    unsigned s = atomic_load_explicit(&a->seq, RELAXED);

    atomic_store_explicit(&a->seq, s + 1, RELAXED);
    atomic_thread_fence(memory_order_release);

    bump(&a->packets, 1);
    bump(&a->bytes, wire_len);
    bump(&a->proto[classify(info)], 1);
    switch (info->status) {
    case PKT_OK:          bump(&a->ok, 1); break;
    case PKT_TRUNCATED:   bump(&a->truncated, 1); break;
    case PKT_MALFORMED:   bump(&a->malformed, 1); break;
    case PKT_INVALID_ARG: break;
    }

    atomic_store_explicit(&a->seq, s + 2, memory_order_release);
}

/* Consistent read of the ana_record() counters (sequence-lock reader). */
static void read_counters(struct analyzer *a, struct ana_snapshot *out)
{
    unsigned s1, s2;
    int i;

    for (;;) {
        s1 = atomic_load_explicit(&a->seq, memory_order_acquire);
        if (s1 & 1u)
            continue;
        out->packets = atomic_load_explicit(&a->packets, RELAXED);
        out->bytes = atomic_load_explicit(&a->bytes, RELAXED);
        for (i = 0; i < ANA_PROTO_COUNT; i++)
            out->proto[i] = atomic_load_explicit(&a->proto[i], RELAXED);
        out->ok = atomic_load_explicit(&a->ok, RELAXED);
        out->truncated = atomic_load_explicit(&a->truncated, RELAXED);
        out->malformed = atomic_load_explicit(&a->malformed, RELAXED);
        atomic_thread_fence(memory_order_acquire);
        s2 = atomic_load_explicit(&a->seq, RELAXED);
        if (s1 == s2)
            return;
    }
}

void ana_tick(struct analyzer *a, uint64_t now_ns)
{
    struct ana_snapshot c;
    struct ana_rate_sample cur;
    const struct ana_rate_sample *old;
    double pps = 0.0, bps = 0.0;
    unsigned rs;

    read_counters(a, &c);
    cur.t_ns = now_ns;
    cur.packets = c.packets;
    cur.bytes = c.bytes;

    if (a->sample_count == ANA_RATE_SAMPLES) {
        a->sample_head = (a->sample_head + 1) % ANA_RATE_SAMPLES;
        a->sample_count--;
    }
    a->samples[(a->sample_head + a->sample_count) % ANA_RATE_SAMPLES] = cur;
    a->sample_count++;

    old = &a->samples[a->sample_head];
    if (cur.t_ns > old->t_ns) {
        double dt = (double)(cur.t_ns - old->t_ns) / 1e9;

        pps = (double)(cur.packets - old->packets) / dt;
        bps = (double)(cur.bytes - old->bytes) / dt;
    }
    rs = atomic_load_explicit(&a->rate_seq, RELAXED);
    atomic_store_explicit(&a->rate_seq, rs + 1, RELAXED);
    atomic_thread_fence(memory_order_release);
    atomic_store_explicit(&a->pps_bits, dbl_bits(pps), RELAXED);
    atomic_store_explicit(&a->bps_bits, dbl_bits(bps), RELAXED);
    atomic_store_explicit(&a->rate_seq, rs + 2, memory_order_release);
}

void ana_snapshot(struct analyzer *a, struct ana_snapshot *out)
{
    unsigned s1, s2;

    read_counters(a, out);
    out->alerts = atomic_load_explicit(&a->alerts_total, RELAXED);
    for (;;) {
        s1 = atomic_load_explicit(&a->rate_seq, memory_order_acquire);
        if (s1 & 1u)
            continue;
        out->pps = bits_dbl(atomic_load_explicit(&a->pps_bits, RELAXED));
        out->bytes_per_sec =
            bits_dbl(atomic_load_explicit(&a->bps_bits, RELAXED));
        atomic_thread_fence(memory_order_acquire);
        s2 = atomic_load_explicit(&a->rate_seq, RELAXED);
        if (s1 == s2)
            return;
    }
}

uint64_t ana_packets(struct analyzer *a)
{
    return atomic_load_explicit(&a->packets, RELAXED);
}

void ana_push_alert(struct analyzer *a, const struct det_alert *alert)
{
    struct ana_alert_rec *r;

    pthread_mutex_lock(&a->alert_lock);
    r = &a->alerts[(a->next_alert_seq - 1) % ANA_ALERT_CAP];
    r->seq = a->next_alert_seq++;
    r->alert = *alert;
    atomic_fetch_add_explicit(&a->alerts_total, 1, RELAXED);
    pthread_mutex_unlock(&a->alert_lock);
}

size_t ana_alerts_since(struct analyzer *a, uint64_t after_seq,
                        struct ana_alert_rec *out, size_t max)
{
    uint64_t first, last, seq;
    size_t n = 0;

    pthread_mutex_lock(&a->alert_lock);
    last = a->next_alert_seq - 1;
    first = last > ANA_ALERT_CAP ? last - ANA_ALERT_CAP + 1 : 1;
    if (after_seq >= first)
        first = after_seq + 1;
    for (seq = first; seq <= last && n < max; seq++)
        out[n++] = a->alerts[(seq - 1) % ANA_ALERT_CAP];
    pthread_mutex_unlock(&a->alert_lock);
    return n;
}

const char *ana_proto_str(enum ana_proto p)
{
    switch (p) {
    case ANA_PROTO_TCP:   return "TCP";
    case ANA_PROTO_UDP:   return "UDP";
    case ANA_PROTO_ICMP:  return "ICMP";
    case ANA_PROTO_OTHER: return "Other";
    case ANA_PROTO_COUNT: break;
    }
    return "?";
}
