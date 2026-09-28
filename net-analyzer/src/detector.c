#include "detector.h"

#include <string.h>

#define DET_NIL UINT32_MAX

_Static_assert((DET_HASH_BUCKETS & (DET_HASH_BUCKETS - 1)) == 0,
               "DET_HASH_BUCKETS must be a power of two");
_Static_assert((DET_PORT_SLOTS & (DET_PORT_SLOTS - 1)) == 0,
               "DET_PORT_SLOTS must be a power of two");
_Static_assert(DET_PORT_SLOTS >= 2 * DET_EVENT_CAP,
               "port table must stay at most half full");
_Static_assert(DET_EVENT_CAP <= UINT16_MAX, "event indices are uint16_t");

static uint32_t ip_bucket(uint32_t ip)
{
    return ((ip * 0x9E3779B1u) >> 21) & (DET_HASH_BUCKETS - 1);
}

static uint32_t port_home(uint16_t port)
{
    return (((uint32_t)port * 40503u) >> 8) & (DET_PORT_SLOTS - 1);
}

/* ---- per-source distinct-port multiset (linear probing) ----------------- */

static uint32_t port_find(const struct det_source *s, uint16_t port)
{
    uint32_t i = port_home(port);

    while (s->ports[i].refs != 0 && s->ports[i].port != port)
        i = (i + 1) & (DET_PORT_SLOTS - 1);
    return i;
}

static void port_add(struct det_source *s, uint16_t port)
{
    uint32_t i = port_find(s, port);

    if (s->ports[i].refs == 0) {
        s->ports[i].port = port;
        s->distinct++;
    }
    s->ports[i].refs++;
}

static void port_remove(struct det_source *s, uint16_t port)
{
    uint32_t i = port_find(s, port);
    uint32_t j = i;

    if (s->ports[i].refs == 0)
        return;
    if (--s->ports[i].refs != 0)
        return;
    s->distinct--;

    /* Backward-shift deletion keeps every probe chain unbroken. */
    for (;;) {
        uint32_t k;

        j = (j + 1) & (DET_PORT_SLOTS - 1);
        if (s->ports[j].refs == 0)
            break;
        k = port_home(s->ports[j].port);
        if (i <= j ? (i < k && k <= j) : (i < k || k <= j))
            continue;
        s->ports[i] = s->ports[j];
        i = j;
    }
    s->ports[i].refs = 0;
}

/* ---- sliding window ----------------------------------------------------- */

static void pop_oldest(struct det_source *s)
{
    port_remove(s, s->ev_port[s->ev_head]);
    s->ev_head = (uint16_t)((s->ev_head + 1) % DET_EVENT_CAP);
    s->ev_count--;
}

static void expire(struct det_source *s, uint64_t now_ns, uint64_t window_ns)
{
    while (s->ev_count != 0 && now_ns - s->ev_ts[s->ev_head] >= window_ns)
        pop_oldest(s);
}

static void push_event(struct det_source *s, uint16_t port, uint64_t now_ns)
{
    uint32_t idx;

    if (s->ev_count == DET_EVENT_CAP)
        pop_oldest(s);
    idx = (s->ev_head + s->ev_count) % DET_EVENT_CAP;
    s->ev_ts[idx] = now_ns;
    s->ev_port[idx] = port;
    s->ev_count++;
    port_add(s, port);
}

/* ---- source table + LRU ------------------------------------------------- */

static void lru_unlink(struct detector *d, uint32_t idx)
{
    struct det_source *s = &d->sources[idx];

    if (s->lru_prev != DET_NIL)
        d->sources[s->lru_prev].lru_next = s->lru_next;
    else
        d->lru_head = s->lru_next;
    if (s->lru_next != DET_NIL)
        d->sources[s->lru_next].lru_prev = s->lru_prev;
    else
        d->lru_tail = s->lru_prev;
    s->lru_prev = s->lru_next = DET_NIL;
}

static void lru_push_front(struct detector *d, uint32_t idx)
{
    struct det_source *s = &d->sources[idx];

    s->lru_prev = DET_NIL;
    s->lru_next = d->lru_head;
    if (d->lru_head != DET_NIL)
        d->sources[d->lru_head].lru_prev = idx;
    d->lru_head = idx;
    if (d->lru_tail == DET_NIL)
        d->lru_tail = idx;
}

static uint32_t lookup(const struct detector *d, uint32_t ip)
{
    uint32_t idx = d->buckets[ip_bucket(ip)];

    while (idx != DET_NIL && d->sources[idx].ip != ip)
        idx = d->sources[idx].hash_next;
    return idx;
}

static void hash_unlink(struct detector *d, uint32_t idx)
{
    uint32_t *link = &d->buckets[ip_bucket(d->sources[idx].ip)];

    while (*link != idx)
        link = &d->sources[*link].hash_next;
    *link = d->sources[idx].hash_next;
}

static uint32_t acquire_entry(struct detector *d, uint32_t ip)
{
    uint32_t idx;
    uint32_t b = ip_bucket(ip);
    struct det_source *s;

    if (d->free_head != DET_NIL) {
        idx = d->free_head;
        d->free_head = d->sources[idx].hash_next;
        d->stats.tracked++;
    } else {
        idx = d->lru_tail;
        hash_unlink(d, idx);
        lru_unlink(d, idx);
        d->stats.evictions++;
    }

    s = &d->sources[idx];
    s->ip = ip;
    s->ev_head = 0;
    s->ev_count = 0;
    s->distinct = 0;
    s->in_use = 1;
    s->alerting = 0;
    s->last_alert_ns = 0;
    memset(s->ports, 0, sizeof(s->ports));

    s->hash_next = d->buckets[b];
    d->buckets[b] = idx;
    lru_push_front(d, idx);
    return idx;
}

/* ---- public API --------------------------------------------------------- */

void det_default_config(struct det_config *cfg)
{
    cfg->window_ns = DET_DEFAULT_WINDOW_NS;
    cfg->syn_threshold = DET_DEFAULT_SYN_THRESHOLD;
    cfg->port_threshold = DET_DEFAULT_PORT_THRESHOLD;
    cfg->realert_ns = DET_DEFAULT_REALERT_NS;
}

void det_init(struct detector *d, const struct det_config *cfg)
{
    uint32_t i;

    memset(d, 0, sizeof(*d));
    if (cfg != NULL)
        d->cfg = *cfg;
    else
        det_default_config(&d->cfg);
    if (d->cfg.window_ns == 0)
        d->cfg.window_ns = 1;

    d->lru_head = d->lru_tail = DET_NIL;
    for (i = 0; i < DET_HASH_BUCKETS; i++)
        d->buckets[i] = DET_NIL;
    for (i = 0; i < DET_MAX_SOURCES; i++) {
        d->sources[i].hash_next = i + 1 < DET_MAX_SOURCES ? i + 1 : DET_NIL;
        d->sources[i].lru_prev = d->sources[i].lru_next = DET_NIL;
    }
    d->free_head = 0;
}

int det_observe_syn(struct detector *d, uint32_t src_ip, uint16_t dst_port,
                    uint64_t now_ns, struct det_alert *alert)
{
    uint32_t idx;
    struct det_source *s;
    int above;

    if (now_ns < d->last_ns)
        now_ns = d->last_ns;
    d->last_ns = now_ns;
    d->stats.syns_seen++;

    idx = lookup(d, src_ip);
    if (idx == DET_NIL) {
        idx = acquire_entry(d, src_ip);
    } else if (d->lru_head != idx) {
        lru_unlink(d, idx);
        lru_push_front(d, idx);
    }
    s = &d->sources[idx];

    expire(s, now_ns, d->cfg.window_ns);
    push_event(s, dst_port, now_ns);

    above = s->ev_count > d->cfg.syn_threshold &&
            s->distinct > d->cfg.port_threshold;
    if (!above) {
        s->alerting = 0;
        return 0;
    }
    if (s->alerting && now_ns - s->last_alert_ns < d->cfg.realert_ns)
        return 0;

    s->alerting = 1;
    s->last_alert_ns = now_ns;
    d->stats.alerts++;
    if (alert != NULL) {
        alert->type = DET_PORT_SCAN_DETECTED;
        alert->src_ip = src_ip;
        alert->syn_count = s->ev_count;
        alert->distinct_ports = s->distinct;
        alert->last_dst_port = dst_port;
        alert->ts_ns = now_ns;
    }
    return 1;
}

int det_observe(struct detector *d, const struct pkt_info *info,
                uint64_t now_ns, struct det_alert *alert)
{
    if (info->l3 != PKT_L3_IPV4 || info->l4 != PKT_L4_TCP)
        return 0;
    if ((info->tcp_flags & (PKT_TCP_SYN | PKT_TCP_ACK)) != PKT_TCP_SYN)
        return 0;
    return det_observe_syn(d, info->src_ip, info->dst_port, now_ns, alert);
}

int det_query(const struct detector *d, uint32_t src_ip, uint64_t now_ns,
              struct det_source_stats *out)
{
    uint8_t seen[65536 / 8];
    uint32_t idx = lookup(d, src_ip);
    const struct det_source *s;
    uint32_t i;

    if (idx == DET_NIL)
        return -1;
    s = &d->sources[idx];
    if (now_ns < d->last_ns)
        now_ns = d->last_ns;

    memset(seen, 0, sizeof(seen));
    memset(out, 0, sizeof(*out));
    for (i = 0; i < s->ev_count; i++) {
        uint32_t e = (s->ev_head + i) % DET_EVENT_CAP;
        uint16_t p = s->ev_port[e];

        if (now_ns - s->ev_ts[e] >= d->cfg.window_ns)
            continue;
        out->syn_count++;
        if (!(seen[p >> 3] & (1u << (p & 7)))) {
            seen[p >> 3] |= (uint8_t)(1u << (p & 7));
            out->distinct_ports++;
        }
    }
    out->alerting = out->syn_count > d->cfg.syn_threshold &&
                    out->distinct_ports > d->cfg.port_threshold;
    return 0;
}

void det_get_stats(const struct detector *d, struct det_stats *out)
{
    *out = d->stats;
}

const char *det_event_str(enum det_event_type type)
{
    switch (type) {
    case DET_PORT_SCAN_DETECTED: return "PORT_SCAN_DETECTED";
    case DET_NONE:               break;
    }
    return "NONE";
}
