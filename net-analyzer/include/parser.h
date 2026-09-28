#ifndef NET_ANALYZER_PARSER_H
#define NET_ANALYZER_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PKT_MAC_LEN 6

/* EtherType values (host byte order). */
#define PKT_ETHERTYPE_IPV4 0x0800
#define PKT_ETHERTYPE_ARP  0x0806
#define PKT_ETHERTYPE_IPV6 0x86DD

/* TCP flag bits exactly as they appear in byte 13 of the TCP header. */
#define PKT_TCP_FIN 0x01
#define PKT_TCP_SYN 0x02
#define PKT_TCP_RST 0x04
#define PKT_TCP_PSH 0x08
#define PKT_TCP_ACK 0x10
#define PKT_TCP_URG 0x20
#define PKT_TCP_ECE 0x40
#define PKT_TCP_CWR 0x80

enum pkt_status {
    PKT_OK = 0,        /* every recognised layer parsed cleanly */
    PKT_TRUNCATED,     /* capture ended before a header was complete */
    PKT_MALFORMED,     /* a header field is internally inconsistent */
    PKT_INVALID_ARG    /* NULL buffer or output pointer */
};

enum pkt_l3 {
    PKT_L3_NONE = 0,   /* no L2 header parsed */
    PKT_L3_IPV4,
    PKT_L3_IPV6,       /* recognised by EtherType only; not dissected */
    PKT_L3_ARP,
    PKT_L3_OTHER
};

enum pkt_l4 {
    PKT_L4_NONE = 0,   /* no L3 payload reached (or non-first fragment) */
    PKT_L4_TCP,
    PKT_L4_UDP,
    PKT_L4_ICMP,
    PKT_L4_OTHER
};

struct pkt_info {
    enum pkt_status status;
    size_t cap_len;           /* bytes handed to the parser */

    /* L2 */
    uint8_t  dst_mac[PKT_MAC_LEN];
    uint8_t  src_mac[PKT_MAC_LEN];
    uint16_t ethertype;       /* host byte order */

    /* L3 */
    enum pkt_l3 l3;
    uint32_t src_ip;          /* network byte order, ready for inet_ntop */
    uint32_t dst_ip;          /* network byte order */
    uint8_t  ttl;
    uint8_t  ip_proto;
    uint8_t  ip_hdr_len;      /* bytes, ihl * 4 */
    uint16_t ip_total_len;    /* as declared in the header */
    uint16_t frag_offset;     /* in bytes */
    uint8_t  more_fragments;  /* MF bit */

    /* L4 */
    enum pkt_l4 l4;
    uint16_t src_port;        /* host byte order */
    uint16_t dst_port;        /* host byte order */
    uint8_t  tcp_flags;       /* PKT_TCP_* bitmask */
    uint8_t  tcp_hdr_len;     /* bytes, doff * 4 */
    uint16_t udp_len;         /* as declared in the header */
    uint8_t  icmp_type;
    uint8_t  icmp_code;

    /*
     * L4 payload bytes according to the headers. May exceed what was
     * actually captured; see payload_captured.
     */
    uint32_t payload_len;
    uint32_t payload_captured;
};

/*
 * Dissect one Ethernet frame. Never reads outside buf[0, len). Fields for
 * layers that were not reached are zeroed. Returns info->status.
 */
enum pkt_status parse_packet(const uint8_t *buf, size_t len,
                             struct pkt_info *info);

const char *pkt_status_str(enum pkt_status status);
const char *pkt_l4_str(const struct pkt_info *info);

/* Render TCP flags as e.g. "SA" into out (needs >= 9 bytes). */
void pkt_tcp_flags_str(uint8_t flags, char *out, size_t out_len);

/*
 * Write a one-line human-readable summary (no trailing newline).
 * Returns the snprintf-style length that would have been written.
 */
int pkt_format(const struct pkt_info *info, char *out, size_t out_len);

#endif
