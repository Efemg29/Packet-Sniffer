#include "parser.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * Headers are copied into properly aligned locals with memcpy rather than
 * cast in place: capture buffers give no alignment guarantee for L3/L4.
 */

static enum pkt_status parse_tcp(const uint8_t *p, size_t avail,
                                 size_t declared, struct pkt_info *info)
{
    struct tcphdr th;
    size_t thl;

    info->l4 = PKT_L4_TCP;
    if (avail < sizeof(th))
        return declared < sizeof(th) ? PKT_MALFORMED : PKT_TRUNCATED;

    memcpy(&th, p, sizeof(th));
    info->src_port = ntohs(th.th_sport);
    info->dst_port = ntohs(th.th_dport);
    info->tcp_flags = th.th_flags;

    thl = (size_t)th.th_off * 4u;
    info->tcp_hdr_len = (uint8_t)thl;
    if (th.th_off < 5 || thl > declared)
        return PKT_MALFORMED;
    if (thl > avail)
        return PKT_TRUNCATED;

    info->payload_len = (uint32_t)(declared - thl);
    info->payload_captured = (uint32_t)(avail - thl);
    return PKT_OK;
}

static enum pkt_status parse_udp(const uint8_t *p, size_t avail,
                                 size_t declared, struct pkt_info *info)
{
    struct udphdr uh;
    size_t ulen;

    info->l4 = PKT_L4_UDP;
    if (avail < sizeof(uh))
        return declared < sizeof(uh) ? PKT_MALFORMED : PKT_TRUNCATED;

    memcpy(&uh, p, sizeof(uh));
    info->src_port = ntohs(uh.uh_sport);
    info->dst_port = ntohs(uh.uh_dport);
    ulen = ntohs(uh.uh_ulen);
    info->udp_len = (uint16_t)ulen;

    if (ulen < sizeof(uh) || ulen > declared)
        return PKT_MALFORMED;

    info->payload_len = (uint32_t)(ulen - sizeof(uh));
    info->payload_captured =
        (uint32_t)((ulen < avail ? ulen : avail) - sizeof(uh));
    return PKT_OK;
}

static enum pkt_status parse_icmp(const uint8_t *p, size_t avail,
                                  size_t declared, struct pkt_info *info)
{
    struct icmphdr ih;

    info->l4 = PKT_L4_ICMP;
    if (avail < sizeof(ih))
        return declared < sizeof(ih) ? PKT_MALFORMED : PKT_TRUNCATED;

    memcpy(&ih, p, sizeof(ih));
    info->icmp_type = ih.type;
    info->icmp_code = ih.code;
    info->payload_len = (uint32_t)(declared - sizeof(ih));
    info->payload_captured = (uint32_t)(avail - sizeof(ih));
    return PKT_OK;
}

static enum pkt_status parse_ipv4(const uint8_t *p, size_t avail,
                                  struct pkt_info *info)
{
    struct iphdr ih;
    size_t hdr_len, total_len, ip_end, l4_avail, l4_declared;
    uint16_t frag;

    info->l3 = PKT_L3_IPV4;
    if (avail < sizeof(ih))
        return PKT_TRUNCATED;

    memcpy(&ih, p, sizeof(ih));
    if (ih.version != 4 || ih.ihl < 5)
        return PKT_MALFORMED;

    hdr_len = (size_t)ih.ihl * 4u;
    total_len = ntohs(ih.tot_len);
    frag = ntohs(ih.frag_off);

    info->ip_hdr_len = (uint8_t)hdr_len;
    info->ip_total_len = (uint16_t)total_len;
    info->ttl = ih.ttl;
    info->ip_proto = ih.protocol;
    info->src_ip = ih.saddr;
    info->dst_ip = ih.daddr;
    info->frag_offset = (uint16_t)((frag & IP_OFFMASK) * 8u);
    info->more_fragments = (frag & IP_MF) ? 1 : 0;

    if (total_len < hdr_len)
        return PKT_MALFORMED;
    if (hdr_len > avail)
        return PKT_TRUNCATED;

    /* Bytes past tot_len are Ethernet padding, not IP payload. */
    ip_end = total_len < avail ? total_len : avail;
    l4_avail = ip_end - hdr_len;
    l4_declared = total_len - hdr_len;
    p += hdr_len;

    if (info->frag_offset != 0) {
        info->payload_len = (uint32_t)l4_declared;
        info->payload_captured = (uint32_t)l4_avail;
        return PKT_OK;
    }

    switch (ih.protocol) {
    case IPPROTO_TCP:
        return parse_tcp(p, l4_avail, l4_declared, info);
    case IPPROTO_UDP:
        return parse_udp(p, l4_avail, l4_declared, info);
    case IPPROTO_ICMP:
        return parse_icmp(p, l4_avail, l4_declared, info);
    default:
        info->l4 = PKT_L4_OTHER;
        info->payload_len = (uint32_t)l4_declared;
        info->payload_captured = (uint32_t)l4_avail;
        return PKT_OK;
    }
}

enum pkt_status parse_packet(const uint8_t *buf, size_t len,
                             struct pkt_info *info)
{
    struct ethhdr eh;

    if (info == NULL)
        return PKT_INVALID_ARG;
    memset(info, 0, sizeof(*info));
    if (buf == NULL) {
        info->status = PKT_INVALID_ARG;
        return info->status;
    }

    info->cap_len = len;
    if (len < sizeof(eh)) {
        info->status = PKT_TRUNCATED;
        return info->status;
    }

    memcpy(&eh, buf, sizeof(eh));
    memcpy(info->dst_mac, eh.h_dest, PKT_MAC_LEN);
    memcpy(info->src_mac, eh.h_source, PKT_MAC_LEN);
    info->ethertype = ntohs(eh.h_proto);

    switch (info->ethertype) {
    case ETH_P_IP:
        info->status = parse_ipv4(buf + sizeof(eh), len - sizeof(eh), info);
        break;
    case ETH_P_IPV6:
        info->l3 = PKT_L3_IPV6;
        info->status = PKT_OK;
        break;
    case ETH_P_ARP:
        info->l3 = PKT_L3_ARP;
        info->status = PKT_OK;
        break;
    default:
        info->l3 = PKT_L3_OTHER;
        info->status = PKT_OK;
        break;
    }
    return info->status;
}

const char *pkt_status_str(enum pkt_status status)
{
    switch (status) {
    case PKT_OK:          return "ok";
    case PKT_TRUNCATED:   return "truncated";
    case PKT_MALFORMED:   return "malformed";
    case PKT_INVALID_ARG: return "invalid-arg";
    }
    return "unknown";
}

const char *pkt_l4_str(const struct pkt_info *info)
{
    switch (info->l3) {
    case PKT_L3_NONE:  return "ETH";
    case PKT_L3_IPV6:  return "IPv6";
    case PKT_L3_ARP:   return "ARP";
    case PKT_L3_OTHER: return "ETH";
    case PKT_L3_IPV4:  break;
    }
    switch (info->l4) {
    case PKT_L4_TCP:   return "TCP";
    case PKT_L4_UDP:   return "UDP";
    case PKT_L4_ICMP:  return "ICMP";
    case PKT_L4_OTHER: return "IPv4";
    case PKT_L4_NONE:  break;
    }
    return info->frag_offset != 0 ? "FRAG" : "IPv4";
}

void pkt_tcp_flags_str(uint8_t flags, char *out, size_t out_len)
{
    static const struct { uint8_t bit; char ch; } map[] = {
        { PKT_TCP_SYN, 'S' }, { PKT_TCP_FIN, 'F' }, { PKT_TCP_RST, 'R' },
        { PKT_TCP_PSH, 'P' }, { PKT_TCP_ACK, 'A' }, { PKT_TCP_URG, 'U' },
        { PKT_TCP_ECE, 'E' }, { PKT_TCP_CWR, 'C' },
    };
    size_t n = 0;

    if (out == NULL || out_len == 0)
        return;
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((flags & map[i].bit) && n + 1 < out_len)
            out[n++] = map[i].ch;
    }
    if (n == 0 && out_len > 1)
        out[n++] = '.';
    out[n] = '\0';
}

struct fmt_buf {
    char *out;
    size_t cap;
    size_t used;   /* may exceed cap; mirrors snprintf semantics */
};

#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static void fmt_append(struct fmt_buf *fb, const char *fmt, ...)
{
    va_list ap;
    size_t room = fb->used < fb->cap ? fb->cap - fb->used : 0;
    char *dst = room ? fb->out + fb->used : NULL;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(dst, room, fmt, ap);
    va_end(ap);
    if (n > 0)
        fb->used += (size_t)n;
}

static void fmt_mac(struct fmt_buf *fb, const uint8_t *m)
{
    fmt_append(fb, "%02x:%02x:%02x:%02x:%02x:%02x",
               m[0], m[1], m[2], m[3], m[4], m[5]);
}

int pkt_format(const struct pkt_info *info, char *out, size_t out_len)
{
    struct fmt_buf fb = { out, out_len, 0 };
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN], flags[9];

    if (out != NULL && out_len > 0)
        out[0] = '\0';
    if (info == NULL)
        return 0;

    fmt_append(&fb, "%-4s ", pkt_l4_str(info));

    if (info->l3 != PKT_L3_IPV4) {
        if (info->l3 != PKT_L3_NONE) {
            fmt_mac(&fb, info->src_mac);
            fmt_append(&fb, " -> ");
            fmt_mac(&fb, info->dst_mac);
            fmt_append(&fb, " type=0x%04x ", info->ethertype);
        }
        fmt_append(&fb, "len=%zu", info->cap_len);
    } else {
        inet_ntop(AF_INET, &info->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &info->dst_ip, dst, sizeof(dst));
        if (info->l4 == PKT_L4_TCP || info->l4 == PKT_L4_UDP)
            fmt_append(&fb, "%s:%u -> %s:%u", src, info->src_port,
                       dst, info->dst_port);
        else
            fmt_append(&fb, "%s -> %s", src, dst);

        fmt_append(&fb, " len=%zu ttl=%u", info->cap_len, info->ttl);

        switch (info->l4) {
        case PKT_L4_TCP:
            pkt_tcp_flags_str(info->tcp_flags, flags, sizeof(flags));
            fmt_append(&fb, " flags=[%s]", flags);
            break;
        case PKT_L4_ICMP:
            fmt_append(&fb, " type=%u code=%u", info->icmp_type,
                       info->icmp_code);
            break;
        case PKT_L4_OTHER:
            fmt_append(&fb, " proto=%u", info->ip_proto);
            break;
        case PKT_L4_UDP:
        case PKT_L4_NONE:
            break;
        }
        if (info->status == PKT_OK)
            fmt_append(&fb, " payload=%u", info->payload_len);
        if (info->frag_offset != 0 || info->more_fragments)
            fmt_append(&fb, " frag=%u%s", info->frag_offset,
                       info->more_fragments ? "+" : "");
    }

    if (info->status != PKT_OK)
        fmt_append(&fb, " [%s]", pkt_status_str(info->status));

    return fb.used > (size_t)0x7fffffff ? 0x7fffffff : (int)fb.used;
}
