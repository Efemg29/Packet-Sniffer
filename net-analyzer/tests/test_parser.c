#include "parser.h"

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

/* ---- frame builders ---------------------------------------------------- */

enum { ETH_LEN = 14, IP_LEN = 20, TCP_LEN = 20, UDP_LEN = 8, ICMP_LEN = 8 };

static const uint8_t MAC_DST[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t MAC_SRC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static size_t build_eth(uint8_t *f, uint16_t ethertype)
{
    memcpy(f, MAC_DST, 6);
    memcpy(f + 6, MAC_SRC, 6);
    put16(f + 12, ethertype);
    return ETH_LEN;
}

/* 10.0.0.1 -> 10.0.0.2, header at f + ETH_LEN. */
static void build_ipv4(uint8_t *f, uint8_t proto, uint16_t l4_len)
{
    uint8_t *ip = f + ETH_LEN;

    build_eth(f, PKT_ETHERTYPE_IPV4);
    memset(ip, 0, IP_LEN);
    ip[0] = 0x45;
    put16(ip + 2, (uint16_t)(IP_LEN + l4_len));
    ip[8] = 64;
    ip[9] = proto;
    ip[12] = 10; ip[15] = 1;
    ip[16] = 10; ip[19] = 2;
}

static size_t build_tcp(uint8_t *f, uint8_t flags, uint16_t payload)
{
    uint8_t *tcp = f + ETH_LEN + IP_LEN;

    build_ipv4(f, 6, (uint16_t)(TCP_LEN + payload));
    memset(tcp, 0, TCP_LEN);
    put16(tcp, 43210);
    put16(tcp + 2, 443);
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    memset(tcp + TCP_LEN, 'x', payload);
    return ETH_LEN + IP_LEN + TCP_LEN + payload;
}

static size_t build_udp(uint8_t *f, uint16_t payload)
{
    uint8_t *udp = f + ETH_LEN + IP_LEN;

    build_ipv4(f, 17, (uint16_t)(UDP_LEN + payload));
    put16(udp, 5353);
    put16(udp + 2, 53);
    put16(udp + 4, (uint16_t)(UDP_LEN + payload));
    put16(udp + 6, 0);
    memset(udp + UDP_LEN, 'u', payload);
    return ETH_LEN + IP_LEN + UDP_LEN + payload;
}

static size_t build_icmp(uint8_t *f, uint8_t type, uint8_t code,
                         uint16_t payload)
{
    uint8_t *ic = f + ETH_LEN + IP_LEN;

    build_ipv4(f, 1, (uint16_t)(ICMP_LEN + payload));
    memset(ic, 0, ICMP_LEN);
    ic[0] = type;
    ic[1] = code;
    memset(ic + ICMP_LEN, 'i', payload);
    return ETH_LEN + IP_LEN + ICMP_LEN + payload;
}

static uint8_t frame[2048];
static struct pkt_info info;

/* ---- happy paths ------------------------------------------------------- */

static void test_ethernet_fields(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK(memcmp(info.dst_mac, MAC_DST, 6) == 0);
    CHECK(memcmp(info.src_mac, MAC_SRC, 6) == 0);
    CHECK_EQ(info.ethertype, PKT_ETHERTYPE_IPV4);
    CHECK_EQ(info.cap_len, n);
}

static void test_ipv4_fields(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.l3, PKT_L3_IPV4);
    CHECK_EQ(info.src_ip, htonl(0x0A000001));
    CHECK_EQ(info.dst_ip, htonl(0x0A000002));
    CHECK_EQ(info.ttl, 64);
    CHECK_EQ(info.ip_proto, 6);
    CHECK_EQ(info.ip_hdr_len, 20);
    CHECK_EQ(info.ip_total_len, 40);
}

static void test_tcp_syn_ack_with_payload(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN | PKT_TCP_ACK | PKT_TCP_PSH, 100);

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.l4, PKT_L4_TCP);
    CHECK_EQ(info.src_port, 43210);
    CHECK_EQ(info.dst_port, 443);
    CHECK_EQ(info.tcp_flags, PKT_TCP_SYN | PKT_TCP_ACK | PKT_TCP_PSH);
    CHECK_EQ(info.tcp_hdr_len, 20);
    CHECK_EQ(info.payload_len, 100);
    CHECK_EQ(info.payload_captured, 100);
}

static void test_tcp_all_flags(void)
{
    uint8_t all = PKT_TCP_FIN | PKT_TCP_SYN | PKT_TCP_RST | PKT_TCP_PSH |
                  PKT_TCP_ACK | PKT_TCP_URG;
    size_t n = build_tcp(frame, all, 0);
    char s[9];

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.tcp_flags, all);
    pkt_tcp_flags_str(info.tcp_flags, s, sizeof(s));
    CHECK(strcmp(s, "SFRPAU") == 0);
    pkt_tcp_flags_str(0, s, sizeof(s));
    CHECK(strcmp(s, ".") == 0);
}

static void test_tcp_with_options(void)
{
    /* doff = 8: 12 bytes of options (NOPs) before 10 bytes of payload. */
    uint8_t *ip = frame + ETH_LEN;
    uint8_t *tcp = ip + IP_LEN;
    size_t n = build_tcp(frame, PKT_TCP_ACK, 22);

    tcp[12] = 8 << 4;
    memset(tcp + TCP_LEN, 0x01, 12);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.tcp_hdr_len, 32);
    CHECK_EQ(info.payload_len, 10);
}

static void test_ip_options(void)
{
    /* ihl = 6: 4 bytes of IP options shift the TCP header. */
    uint8_t *ip = frame + ETH_LEN;
    uint8_t *tcp;
    size_t n;

    build_ipv4(frame, 6, TCP_LEN + 4);
    ip[0] = 0x46;
    put16(ip + 2, IP_LEN + 4 + TCP_LEN + 4);
    memset(ip + IP_LEN, 0x01, 4);
    tcp = ip + IP_LEN + 4;
    memset(tcp, 0, TCP_LEN);
    put16(tcp, 1111);
    put16(tcp + 2, 2222);
    tcp[12] = 5 << 4;
    tcp[13] = PKT_TCP_FIN;
    n = ETH_LEN + IP_LEN + 4 + TCP_LEN + 4;

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.ip_hdr_len, 24);
    CHECK_EQ(info.src_port, 1111);
    CHECK_EQ(info.dst_port, 2222);
    CHECK_EQ(info.tcp_flags, PKT_TCP_FIN);
    CHECK_EQ(info.payload_len, 4);
}

static void test_udp(void)
{
    size_t n = build_udp(frame, 33);

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.l4, PKT_L4_UDP);
    CHECK_EQ(info.src_port, 5353);
    CHECK_EQ(info.dst_port, 53);
    CHECK_EQ(info.udp_len, 41);
    CHECK_EQ(info.payload_len, 33);
    CHECK_EQ(info.payload_captured, 33);
}

static void test_icmp_echo(void)
{
    size_t n = build_icmp(frame, 8, 0, 56);

    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.l4, PKT_L4_ICMP);
    CHECK_EQ(info.icmp_type, 8);
    CHECK_EQ(info.icmp_code, 0);
    CHECK_EQ(info.payload_len, 56);
}

static void test_ethernet_padding_ignored(void)
{
    /* Minimum-size Ethernet frame: 60 bytes, IP tot_len says 28. */
    size_t n = build_udp(frame, 0);

    memset(frame + n, 0, 60 - n);
    CHECK_EQ(parse_packet(frame, 60, &info), PKT_OK);
    CHECK_EQ(info.payload_len, 0);
    CHECK_EQ(info.payload_captured, 0);
}

static void test_ipv6_recognised(void)
{
    size_t n = build_eth(frame, PKT_ETHERTYPE_IPV6);

    memset(frame + n, 0, 40);
    CHECK_EQ(parse_packet(frame, n + 40, &info), PKT_OK);
    CHECK_EQ(info.l3, PKT_L3_IPV6);
    CHECK_EQ(info.l4, PKT_L4_NONE);
    CHECK(strcmp(pkt_l4_str(&info), "IPv6") == 0);
}

static void test_arp_and_other_ethertypes(void)
{
    size_t n = build_eth(frame, PKT_ETHERTYPE_ARP);

    CHECK_EQ(parse_packet(frame, n + 28, &info), PKT_OK);
    CHECK_EQ(info.l3, PKT_L3_ARP);

    n = build_eth(frame, 0x88CC); /* LLDP */
    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.l3, PKT_L3_OTHER);
    CHECK_EQ(info.ethertype, 0x88CC);
}

static void test_other_ip_protocol(void)
{
    build_ipv4(frame, 47 /* GRE */, 4);
    CHECK_EQ(parse_packet(frame, ETH_LEN + IP_LEN + 4, &info), PKT_OK);
    CHECK_EQ(info.l4, PKT_L4_OTHER);
    CHECK_EQ(info.ip_proto, 47);
    CHECK_EQ(info.payload_len, 4);
}

static void test_first_fragment_parses_l4(void)
{
    size_t n = build_udp(frame, 16);

    put16(frame + ETH_LEN + 6, 0x2000); /* MF, offset 0 */
    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.more_fragments, 1);
    CHECK_EQ(info.frag_offset, 0);
    CHECK_EQ(info.l4, PKT_L4_UDP);
}

static void test_non_first_fragment_skips_l4(void)
{
    size_t n = build_udp(frame, 16);

    put16(frame + ETH_LEN + 6, 185); /* offset 185 * 8 = 1480, no MF */
    CHECK_EQ(parse_packet(frame, n, &info), PKT_OK);
    CHECK_EQ(info.frag_offset, 1480);
    CHECK_EQ(info.more_fragments, 0);
    CHECK_EQ(info.l4, PKT_L4_NONE);
    CHECK_EQ(info.src_port, 0);
    CHECK_EQ(info.payload_len, 24);
    CHECK(strcmp(pkt_l4_str(&info), "FRAG") == 0);
}

/* ---- truncated / malformed ---------------------------------------------- */

static void test_null_and_empty(void)
{
    CHECK_EQ(parse_packet(NULL, 100, &info), PKT_INVALID_ARG);
    CHECK_EQ(parse_packet(frame, 10, NULL), PKT_INVALID_ARG);
    CHECK_EQ(parse_packet(frame, 0, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l3, PKT_L3_NONE);
}

static void test_truncated_ethernet(void)
{
    build_eth(frame, PKT_ETHERTYPE_IPV4);
    CHECK_EQ(parse_packet(frame, ETH_LEN - 1, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l3, PKT_L3_NONE);
    CHECK_EQ(info.ethertype, 0);
}

static void test_truncated_ipv4_header(void)
{
    build_tcp(frame, PKT_TCP_SYN, 0);
    CHECK_EQ(parse_packet(frame, ETH_LEN + 19, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l3, PKT_L3_IPV4);
    CHECK_EQ(info.l4, PKT_L4_NONE);
    CHECK_EQ(info.src_ip, 0);
}

static void test_ihl_below_minimum(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    for (uint8_t ihl = 0; ihl < 5; ihl++) {
        frame[ETH_LEN] = (uint8_t)(0x40 | ihl);
        CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
        CHECK_EQ(info.l4, PKT_L4_NONE);
    }
}

static void test_ihl_exceeds_capture(void)
{
    /* ihl = 15 (60 bytes) but only 40 bytes of IP captured. */
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    frame[ETH_LEN] = 0x4F;
    put16(frame + ETH_LEN + 2, 60);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l4, PKT_L4_NONE);
}

static void test_wrong_ip_version(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    frame[ETH_LEN] = 0x65;
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_total_len_below_header(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    put16(frame + ETH_LEN + 2, 19);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
    CHECK_EQ(info.l4, PKT_L4_NONE);
}

static void test_snapped_capture_reports_declared_payload(void)
{
    /* 1000-byte payload declared, only 50 bytes captured. */
    size_t n = build_tcp(frame, PKT_TCP_ACK, 1000);

    CHECK(n > ETH_LEN + IP_LEN + TCP_LEN + 50);
    CHECK_EQ(parse_packet(frame, ETH_LEN + IP_LEN + TCP_LEN + 50, &info),
             PKT_OK);
    CHECK_EQ(info.payload_len, 1000);
    CHECK_EQ(info.payload_captured, 50);
}

static void test_truncated_tcp_header(void)
{
    build_tcp(frame, PKT_TCP_SYN, 0);
    CHECK_EQ(parse_packet(frame, ETH_LEN + IP_LEN + 19, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l4, PKT_L4_TCP);
    CHECK_EQ(info.src_port, 0);
}

static void test_tcp_doff_below_minimum(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    frame[ETH_LEN + IP_LEN + 12] = 4 << 4;
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_tcp_doff_exceeds_capture(void)
{
    /* doff = 15 (60 bytes); IP says 80 bytes of TCP but only 20 captured. */
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    put16(frame + ETH_LEN + 2, IP_LEN + 60);
    frame[ETH_LEN + IP_LEN + 12] = 15 << 4;
    CHECK_EQ(parse_packet(frame, n, &info), PKT_TRUNCATED);
}

static void test_tcp_doff_exceeds_ip_payload(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 20);

    frame[ETH_LEN + IP_LEN + 12] = 15 << 4; /* 60 > 40 declared by IP */
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_tcp_ip_len_too_small_for_tcp(void)
{
    size_t n = build_tcp(frame, PKT_TCP_SYN, 0);

    put16(frame + ETH_LEN + 2, IP_LEN + 10);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_truncated_udp_header(void)
{
    build_udp(frame, 0);
    CHECK_EQ(parse_packet(frame, ETH_LEN + IP_LEN + 7, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l4, PKT_L4_UDP);
}

static void test_udp_length_below_header(void)
{
    size_t n = build_udp(frame, 10);

    put16(frame + ETH_LEN + IP_LEN + 4, 7);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_udp_length_exceeds_ip_payload(void)
{
    size_t n = build_udp(frame, 10);

    put16(frame + ETH_LEN + IP_LEN + 4, 500);
    CHECK_EQ(parse_packet(frame, n, &info), PKT_MALFORMED);
}

static void test_truncated_icmp_header(void)
{
    build_icmp(frame, 3, 1, 0);
    CHECK_EQ(parse_packet(frame, ETH_LEN + IP_LEN + 4, &info), PKT_TRUNCATED);
    CHECK_EQ(info.l4, PKT_L4_ICMP);
}

/* Every prefix of every valid frame must parse without reading past len. */
static void test_every_prefix_is_safe(void)
{
    size_t lens[4];
    static uint8_t copies[4][256];
    uint8_t *heap;

    lens[0] = build_tcp(frame, PKT_TCP_SYN, 12);
    memcpy(copies[0], frame, lens[0]);
    lens[1] = build_udp(frame, 12);
    memcpy(copies[1], frame, lens[1]);
    lens[2] = build_icmp(frame, 0, 0, 12);
    memcpy(copies[2], frame, lens[2]);
    lens[3] = ETH_LEN;
    build_eth(copies[3], PKT_ETHERTYPE_IPV6);

    for (int k = 0; k < 4; k++) {
        for (size_t len = 0; len <= lens[k]; len++) {
            /* Exact-size heap copy lets ASan catch any over-read. */
            heap = malloc(len ? len : 1);
            CHECK(heap != NULL);
            if (heap == NULL)
                return;
            memcpy(heap, copies[k], len);
            enum pkt_status st = parse_packet(heap, len, &info);
            CHECK(st == PKT_OK || st == PKT_TRUNCATED || st == PKT_MALFORMED);
            if (len == lens[k])
                CHECK_EQ(st, PKT_OK);
            free(heap);
        }
    }
}

static void test_random_fuzz(void)
{
    uint32_t seed = 0x12345678u;
    char line[256];

    for (int iter = 0; iter < 200000; iter++) {
        size_t len;
        uint8_t *heap;

        seed = seed * 1664525u + 1013904223u;
        len = (seed >> 8) % 128;
        heap = malloc(len ? len : 1);
        if (heap == NULL) {
            CHECK(0);
            return;
        }
        for (size_t i = 0; i < len; i++) {
            seed = seed * 1664525u + 1013904223u;
            heap[i] = (uint8_t)(seed >> 24);
        }
        /* Bias toward IPv4 so deeper layers get exercised. */
        if (len >= ETH_LEN + 1 && (iter & 1)) {
            heap[12] = 0x08;
            heap[13] = 0x00;
            heap[ETH_LEN] = (uint8_t)(0x40 | (heap[ETH_LEN] & 0x0F));
        }
        enum pkt_status st = parse_packet(heap, len, &info);
        if (!(st == PKT_OK || st == PKT_TRUNCATED || st == PKT_MALFORMED))
            CHECK(0);
        if (info.payload_captured > info.payload_len &&
            info.frag_offset == 0 && info.l4 != PKT_L4_NONE)
            CHECK(0);
        pkt_format(&info, line, sizeof(line));
        free(heap);
    }
}

/* ---- formatting --------------------------------------------------------- */

static void test_format_tcp(void)
{
    char line[256];
    size_t n = build_tcp(frame, PKT_TCP_SYN | PKT_TCP_ACK, 5);

    parse_packet(frame, n, &info);
    pkt_format(&info, line, sizeof(line));
    CHECK(strcmp(line, "TCP  10.0.0.1:43210 -> 10.0.0.2:443 len=59 ttl=64 "
                       "flags=[SA] payload=5") == 0);
}

static void test_format_malformed_and_small_buffer(void)
{
    char line[256], tiny[8];
    size_t n = build_udp(frame, 4);
    int full;

    put16(frame + ETH_LEN + IP_LEN + 4, 3);
    parse_packet(frame, n, &info);
    full = pkt_format(&info, line, sizeof(line));
    CHECK(strstr(line, "[malformed]") != NULL);
    CHECK_EQ(full, strlen(line));

    CHECK_EQ(pkt_format(&info, tiny, sizeof(tiny)), full);
    CHECK_EQ(strlen(tiny), sizeof(tiny) - 1);
    CHECK_EQ(pkt_format(&info, NULL, 0), full);
}

int main(void)
{
    RUN(test_ethernet_fields);
    RUN(test_ipv4_fields);
    RUN(test_tcp_syn_ack_with_payload);
    RUN(test_tcp_all_flags);
    RUN(test_tcp_with_options);
    RUN(test_ip_options);
    RUN(test_udp);
    RUN(test_icmp_echo);
    RUN(test_ethernet_padding_ignored);
    RUN(test_ipv6_recognised);
    RUN(test_arp_and_other_ethertypes);
    RUN(test_other_ip_protocol);
    RUN(test_first_fragment_parses_l4);
    RUN(test_non_first_fragment_skips_l4);
    RUN(test_null_and_empty);
    RUN(test_truncated_ethernet);
    RUN(test_truncated_ipv4_header);
    RUN(test_ihl_below_minimum);
    RUN(test_ihl_exceeds_capture);
    RUN(test_wrong_ip_version);
    RUN(test_total_len_below_header);
    RUN(test_snapped_capture_reports_declared_payload);
    RUN(test_truncated_tcp_header);
    RUN(test_tcp_doff_below_minimum);
    RUN(test_tcp_doff_exceeds_capture);
    RUN(test_tcp_doff_exceeds_ip_payload);
    RUN(test_tcp_ip_len_too_small_for_tcp);
    RUN(test_truncated_udp_header);
    RUN(test_udp_length_below_header);
    RUN(test_udp_length_exceeds_ip_payload);
    RUN(test_truncated_icmp_header);
    RUN(test_every_prefix_is_safe);
    RUN(test_random_fuzz);
    RUN(test_format_tcp);
    RUN(test_format_malformed_and_small_buffer);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
