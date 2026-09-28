#include "feed.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>

#define RELAXED memory_order_relaxed

int feed_init(struct feed *f)
{
    size_t i, w;

    atomic_init(&f->last_seq, 0);
    for (i = 0; i < FEED_CAP; i++) {
        atomic_init(&f->slots[i].ver, 0);
        for (w = 0; w < FEED_WORDS; w++)
            atomic_init(&f->slots[i].words[w], 0);
    }
    return 0;
}

void feed_destroy(struct feed *f)
{
    (void)f;
}

void feed_push(struct feed *f, const struct timespec *ts, uint8_t pkttype,
               uint32_t wire_len, const struct pkt_info *info)
{
    uint64_t words[FEED_WORDS];
    struct feed_entry e;
    uint64_t seq = atomic_load_explicit(&f->last_seq, RELAXED) + 1;
    struct feed_slot *s = &f->slots[seq & (FEED_CAP - 1)];
    size_t w;

    memset(&e, 0, sizeof(e));
    e.seq = seq;
    e.ts = *ts;
    e.wire_len = wire_len;
    e.pkttype = pkttype;
    e.info = *info;
    memset(words, 0, sizeof(words));
    memcpy(words, &e, sizeof(e));

    /* Release stores on the words (rather than a fence) order the odd
     * version before them; this is free on x86 and TSan models it. */
    atomic_store_explicit(&s->ver, 2 * seq - 1, RELAXED);
    for (w = 0; w < FEED_WORDS; w++)
        atomic_store_explicit(&s->words[w], words[w], memory_order_release);
    atomic_store_explicit(&s->ver, 2 * seq, memory_order_release);
    atomic_store_explicit(&f->last_seq, seq, memory_order_release);
}

/* Returns 1 and fills *out if slot still holds seq, intact. */
static int read_slot(const struct feed_slot *s, uint64_t seq,
                     struct feed_entry *out)
{
    uint64_t words[FEED_WORDS];
    uint64_t v1, v2;
    size_t w;

    v1 = atomic_load_explicit(&s->ver, memory_order_acquire);
    if (v1 != 2 * seq)
        return 0;
    for (w = 0; w < FEED_WORDS; w++)
        words[w] = atomic_load_explicit(&s->words[w], memory_order_acquire);
    v2 = atomic_load_explicit(&s->ver, RELAXED);
    if (v1 != v2)
        return 0;
    memcpy(out, words, sizeof(*out));
    return 1;
}

size_t feed_since(struct feed *f, uint64_t after_seq, struct feed_entry *out,
                  size_t max, uint64_t *last_seq)
{
    uint64_t first, last, seq;
    size_t n = 0;

    last = atomic_load_explicit(&f->last_seq, memory_order_acquire);
    first = last >= FEED_CAP ? last - FEED_CAP + 1 : 1;
    if (after_seq + 1 > first)
        first = after_seq + 1;
    if (last >= first && max != 0 && last - first + 1 > max)
        first = last - max + 1;
    for (seq = first; seq <= last && n < max; seq++)
        n += (size_t)read_slot(&f->slots[seq & (FEED_CAP - 1)], seq, &out[n]);

    if (last_seq != NULL)
        *last_seq = last;
    return n;
}

static void fmt_mac(char *out, size_t len, const uint8_t *m)
{
    snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void fmt_endpoint(char *out, size_t len, uint32_t ip, int with_port,
                         uint16_t port)
{
    char addr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip, addr, sizeof(addr));
    if (with_port)
        snprintf(out, len, "%s:%u", addr, port);
    else
        snprintf(out, len, "%s", addr);
}

int feed_format(const struct feed_entry *e, char *out, size_t out_len)
{
    const struct pkt_info *p = &e->info;
    char tbuf[64], src[32], dst[32], info[48], flags[9];
    struct tm tm;
    time_t sec = e->ts.tv_sec;
    unsigned ms = (unsigned)((unsigned long)e->ts.tv_nsec / 1000000UL) % 1000u;
    int ports = p->l4 == PKT_L4_TCP || p->l4 == PKT_L4_UDP;
    size_t used;

    localtime_r(&sec, &tm);
    snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d.%03u", tm.tm_hour,
             tm.tm_min, tm.tm_sec, ms);

    info[0] = '\0';
    if (p->l3 == PKT_L3_IPV4) {
        fmt_endpoint(src, sizeof(src), p->src_ip, ports, p->src_port);
        fmt_endpoint(dst, sizeof(dst), p->dst_ip, ports, p->dst_port);
        switch (p->l4) {
        case PKT_L4_TCP:
            pkt_tcp_flags_str(p->tcp_flags, flags, sizeof(flags));
            snprintf(info, sizeof(info), "[%s]", flags);
            break;
        case PKT_L4_ICMP:
            snprintf(info, sizeof(info), "type=%u code=%u", p->icmp_type,
                     p->icmp_code);
            break;
        case PKT_L4_OTHER:
            snprintf(info, sizeof(info), "proto=%u", p->ip_proto);
            break;
        case PKT_L4_UDP:
            break;
        case PKT_L4_NONE:
            if (p->frag_offset != 0)
                snprintf(info, sizeof(info), "frag=%u", p->frag_offset);
            break;
        }
    } else if (p->l3 != PKT_L3_NONE) {
        fmt_mac(src, sizeof(src), p->src_mac);
        fmt_mac(dst, sizeof(dst), p->dst_mac);
        snprintf(info, sizeof(info), "type=0x%04x", p->ethertype);
    } else {
        snprintf(src, sizeof(src), "-");
        snprintf(dst, sizeof(dst), "-");
    }
    if (p->status != PKT_OK) {
        used = strlen(info);
        snprintf(info + used, sizeof(info) - used, "%s[%s]",
                 used ? " " : "", pkt_status_str(p->status));
    }

    return snprintf(out, out_len, "%-*s %-*s %-*s %-*s -> %-*s %*u %s",
                    FEED_COL_TIME, tbuf,
                    FEED_COL_DIR, e->pkttype == PACKET_OUTGOING ? "OUT" : "IN",
                    FEED_COL_PROTO, pkt_l4_str(p),
                    FEED_COL_ADDR, src, FEED_COL_ADDR, dst,
                    FEED_COL_LEN, e->wire_len, info);
}

int feed_format_header(char *out, size_t out_len)
{
    return snprintf(out, out_len, "%-*s %-*s %-*s %-*s    %-*s %*s %s",
                    FEED_COL_TIME, "TIME", FEED_COL_DIR, "DIR",
                    FEED_COL_PROTO, "PROTO", FEED_COL_ADDR, "SOURCE",
                    FEED_COL_ADDR, "DESTINATION", FEED_COL_LEN, "LEN",
                    "FLAGS/INFO");
}
