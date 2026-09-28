#include "feed.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>

int feed_init(struct feed *f)
{
    memset(f->entries, 0, sizeof(f->entries));
    f->last_seq = 0;
    return pthread_mutex_init(&f->lock, NULL);
}

void feed_destroy(struct feed *f)
{
    pthread_mutex_destroy(&f->lock);
}

void feed_push(struct feed *f, const struct timespec *ts, uint8_t pkttype,
               uint32_t wire_len, const struct pkt_info *info)
{
    struct feed_entry *e;

    pthread_mutex_lock(&f->lock);
    e = &f->entries[(f->last_seq + 1) & (FEED_CAP - 1)];
    e->seq = f->last_seq + 1;
    e->ts = *ts;
    e->wire_len = wire_len;
    e->pkttype = pkttype;
    e->info = *info;
    f->last_seq = e->seq;
    pthread_mutex_unlock(&f->lock);
}

size_t feed_since(struct feed *f, uint64_t after_seq, struct feed_entry *out,
                  size_t max, uint64_t *last_seq)
{
    uint64_t first, last, seq;
    size_t n = 0;

    pthread_mutex_lock(&f->lock);
    last = f->last_seq;
    first = last >= FEED_CAP ? last - FEED_CAP + 1 : 1;
    if (after_seq + 1 > first)
        first = after_seq + 1;
    if (last >= first && max != 0 && last - first + 1 > max)
        first = last - max + 1;
    for (seq = first; seq <= last && n < max; seq++)
        out[n++] = f->entries[seq & (FEED_CAP - 1)];
    pthread_mutex_unlock(&f->lock);

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
