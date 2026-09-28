#include <linux/if_ether.h>

#include "rx_ring.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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

static unsigned page_size(void)
{
    long p = sysconf(_SC_PAGESIZE);

    return p > 0 ? (unsigned)p : 4096u;
}

/* One 16-byte frame at offset 256. Status is published last, and the
 * block header is not wiped with memset: the producer is concurrently
 * loading block_status. */
static void plant_frame(struct tpacket_block_desc *b, unsigned block_size,
                        uint8_t mark, uint8_t pkttype)
{
    uint8_t *base = (uint8_t *)b;
    struct tpacket3_hdr *hdr;
    struct sockaddr_ll *sll;
    uint8_t *mac;
    unsigned mac_from_hdr;

    memset(base + sizeof(*b), 0, block_size - sizeof(*b));
    b->version = 0;
    b->offset_to_priv = 0;
    b->hdr.bh1.num_pkts = 1;
    b->hdr.bh1.offset_to_first_pkt = 256;
    b->hdr.bh1.blk_len = 0;
    hdr = (struct tpacket3_hdr *)(base + 256);
    mac_from_hdr = (unsigned)TPACKET_ALIGN(sizeof(*hdr)) + sizeof(*sll);
    sll = (struct sockaddr_ll *)((uint8_t *)hdr + TPACKET_ALIGN(sizeof(*hdr)));
    mac = (uint8_t *)hdr + mac_from_hdr;
    memset(mac, mark, 16);
    hdr->tp_snaplen = 16;
    hdr->tp_len = 100;
    hdr->tp_mac = (uint16_t)mac_from_hdr;
    hdr->tp_sec = 5;
    hdr->tp_nsec = 250;
    hdr->tp_next_offset = 0;
    sll->sll_pkttype = pkttype;
    b->hdr.bh1.num_pkts = 1;
    b->hdr.bh1.offset_to_first_pkt = 256;
    __atomic_store_n(&b->hdr.bh1.block_status, TP_STATUS_USER, __ATOMIC_RELEASE);
}

static void test_cursor_two_frames(void)
{
    uint8_t mem[2048];
    struct tpacket_block_desc *b = (struct tpacket_block_desc *)mem;
    struct tpacket3_hdr *a;
    struct tpacket3_hdr *c;
    struct sockaddr_ll *sll;
    struct rx_cursor cur;
    struct rx_frame fr;
    unsigned mac_from_hdr;

    memset(mem, 0, sizeof(mem));
    mac_from_hdr = (unsigned)TPACKET_ALIGN(sizeof(*a)) + sizeof(*sll);
    b->hdr.bh1.num_pkts = 2;
    b->hdr.bh1.offset_to_first_pkt = 128;

    a = (struct tpacket3_hdr *)(mem + 128);
    a->tp_next_offset = 256;
    a->tp_snaplen = 4;
    a->tp_len = 4;
    a->tp_mac = (uint16_t)mac_from_hdr;
    a->tp_sec = 9;
    a->tp_nsec = 8;
    sll = (struct sockaddr_ll *)((uint8_t *)a + TPACKET_ALIGN(sizeof(*a)));
    sll->sll_pkttype = PACKET_OUTGOING;
    ((uint8_t *)a)[mac_from_hdr] = 0x11;

    c = (struct tpacket3_hdr *)(mem + 128 + 256);
    c->tp_next_offset = 0;
    c->tp_snaplen = 4;
    c->tp_len = 9;
    c->tp_mac = (uint16_t)mac_from_hdr;
    sll = (struct sockaddr_ll *)((uint8_t *)c + TPACKET_ALIGN(sizeof(*c)));
    sll->sll_pkttype = PACKET_HOST;
    ((uint8_t *)c)[mac_from_hdr] = 0x22;

    rx_cursor_init(&cur, b, sizeof(mem));
    CHECK_EQ(rx_cursor_next(&cur, &fr), 1);
    CHECK_EQ(fr.cap_len, 4);
    CHECK_EQ(fr.orig_len, 4);
    CHECK_EQ(fr.data[0], 0x11);
    CHECK_EQ(fr.pkttype, PACKET_OUTGOING);
    CHECK_EQ(fr.ts.tv_sec, 9);
    CHECK_EQ(fr.ts.tv_nsec, 8);
    CHECK_EQ(rx_cursor_next(&cur, &fr), 1);
    CHECK_EQ(fr.data[0], 0x22);
    CHECK_EQ(fr.pkttype, PACKET_HOST);
    CHECK_EQ(fr.orig_len, 9);
    CHECK_EQ(rx_cursor_next(&cur, &fr), 0);
}

static void test_cursor_rejects_bad_geometry(void)
{
    uint8_t mem[512];
    struct tpacket_block_desc *b = (struct tpacket_block_desc *)mem;
    struct rx_cursor cur;
    struct rx_frame fr;

    memset(mem, 0, sizeof(mem));
    b->hdr.bh1.num_pkts = 1;
    b->hdr.bh1.offset_to_first_pkt = 8; /* inside the block header */
    rx_cursor_init(&cur, b, sizeof(mem));
    CHECK_EQ(rx_cursor_next(&cur, &fr), 0);

    b->hdr.bh1.offset_to_first_pkt = 4000; /* past the buffer we claim */
    rx_cursor_init(&cur, b, sizeof(mem));
    CHECK_EQ(rx_cursor_next(&cur, &fr), 0);

    b->hdr.bh1.num_pkts = 2;
    b->hdr.bh1.offset_to_first_pkt = 128;
    rx_cursor_init(&cur, b, sizeof(mem));
    /* next_offset is 0, so the second claimed frame is not walked. */
    CHECK_EQ(rx_cursor_next(&cur, &fr), 1);
    CHECK_EQ(fr.cap_len, 0);
    CHECK_EQ(rx_cursor_next(&cur, &fr), 0);
}

static void test_cursor_clamps_snaplen(void)
{
    uint8_t mem[256];
    struct tpacket_block_desc *b = (struct tpacket_block_desc *)mem;
    struct tpacket3_hdr *hdr;
    struct rx_cursor cur;
    struct rx_frame fr;

    memset(mem, 0, sizeof(mem));
    b->hdr.bh1.num_pkts = 1;
    b->hdr.bh1.offset_to_first_pkt = 64;
    hdr = (struct tpacket3_hdr *)(mem + 64);
    hdr->tp_snaplen = 100000;
    hdr->tp_len = 100000;
    hdr->tp_mac = 32;
    rx_cursor_init(&cur, b, sizeof(mem));
    CHECK_EQ(rx_cursor_next(&cur, &fr), 1);
    CHECK(fr.cap_len < sizeof(mem));
    CHECK_EQ(fr.orig_len, 100000);
    CHECK(fr.cap_len <= MAX_PACKET_LEN);
}

struct pipe_ctx {
    struct rx_ring *rx;
    atomic_int stop;
    unsigned rounds;
};

static void *produce(void *arg)
{
    struct pipe_ctx *ctx = arg;

    if (rx_ring_produce(ctx->rx, &ctx->stop) != 0)
        atomic_store(&ctx->stop, 1);
    return NULL;
}

static void test_block_handoff(void)
{
    struct pipe_ctx ctx;
    pthread_t th;
    unsigned block_size = page_size();
    unsigned rounds = 8;
    unsigned n;
    unsigned i;
    int err;

    if (block_size < 4096)
        block_size = 4096;
    ctx.rx = rx_ring_local(4, block_size);
    CHECK(ctx.rx != NULL);
    if (ctx.rx == NULL)
        return;
    atomic_init(&ctx.stop, 0);
    for (i = 0; i < 4; i++)
        plant_frame(rx_ring_block(ctx.rx, i), block_size, (uint8_t)(i + 1),
                    PACKET_HOST);

    err = pthread_create(&th, NULL, produce, &ctx);
    CHECK_EQ(err, 0);
    if (err != 0) {
        rx_ring_close(ctx.rx);
        return;
    }

    for (n = 0; n < rounds; n++) {
        for (i = 0; i < 4; i++) {
            unsigned idx = 99;
            struct rx_cursor cur;
            struct rx_frame fr;
            int spins = 0;

            while (!rx_ring_peek(ctx.rx, &idx)) {
                struct timespec nap = { 0, 1000000 };

                if (++spins > 2000) {
                    CHECK(spins <= 2000);
                    atomic_store(&ctx.stop, 1);
                    pthread_join(th, NULL);
                    rx_ring_close(ctx.rx);
                    return;
                }
                nanosleep(&nap, NULL);
            }
            CHECK_EQ(idx, i);
            rx_cursor_init(&cur, rx_ring_block(ctx.rx, idx), block_size);
            CHECK_EQ(rx_cursor_next(&cur, &fr), 1);
            CHECK_EQ(fr.data[0], (n == 0 ? i + 1 : 0x40 + i));
            CHECK_EQ(fr.orig_len, 100);
            CHECK_EQ(rx_cursor_next(&cur, &fr), 0);
            rx_ring_retire(ctx.rx);
            if (n + 1 < rounds)
                plant_frame(rx_ring_block(ctx.rx, i), block_size,
                            (uint8_t)(0x40 + i), PACKET_OUTGOING);
        }
    }

    atomic_store(&ctx.stop, 1);
    pthread_join(th, NULL);
    {
        struct rx_info info;

        rx_ring_get_info(ctx.rx, &info);
        CHECK_EQ(info.blocks, 4);
        CHECK(info.frames >= (uint64_t)rounds * 4u);
    }
    rx_ring_close(ctx.rx);
}

static void test_live_loopback(void)
{
    int fd;
    int udp;
    struct rx_ring *rx;
    struct pipe_ctx ctx;
    pthread_t th;
    struct sockaddr_ll sll;
    struct sockaddr_in to;
    const char marker[] = "phase5-marker";
    int saw = 0;
    int spins = 0;
    unsigned ifindex;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        printf("  (no CAP_NET_RAW, live capture skipped)\n");
        return;
    }
    rx = rx_ring_open(fd, 4u * (size_t)MAX_PACKET_LEN);
    if (rx == NULL) {
        CHECK(rx != NULL);
        close(fd);
        return;
    }

    ifindex = if_nametoindex("lo");
    CHECK(ifindex != 0);
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)ifindex;
    CHECK_EQ(bind(fd, (struct sockaddr *)&sll, sizeof(sll)), 0);

    ctx.rx = rx;
    atomic_init(&ctx.stop, 0);
    CHECK_EQ(pthread_create(&th, NULL, produce, &ctx), 0);

    udp = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(udp >= 0);
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(9);
    to.sin_addr.s_addr = htonl(0x7f000001);
    if (udp >= 0)
        sendto(udp, marker, sizeof(marker), 0, (struct sockaddr *)&to,
               sizeof(to));

    while (!saw && spins < 2000) {
        unsigned idx;
        struct rx_cursor cur;
        struct rx_frame fr;

        if (!rx_ring_peek(rx, &idx)) {
            struct timespec nap = { 0, 1000000 };

            spins++;
            nanosleep(&nap, NULL);
            if (udp >= 0 && spins % 50 == 0)
                sendto(udp, marker, sizeof(marker), 0, (struct sockaddr *)&to,
                       sizeof(to));
            continue;
        }
        rx_cursor_init(&cur, rx_ring_block(rx, idx), rx_ring_block_size(rx));
        while (rx_cursor_next(&cur, &fr)) {
            if (fr.cap_len >= sizeof(marker) &&
                memmem(fr.data, fr.cap_len, marker, sizeof(marker)) != NULL)
                saw = 1;
        }
        rx_ring_retire(rx);
    }
    CHECK_EQ(saw, 1);

    atomic_store(&ctx.stop, 1);
    pthread_join(th, NULL);
    if (udp >= 0)
        close(udp);
    rx_ring_close(rx);
    close(fd);
}

int main(void)
{
    RUN(test_cursor_two_frames);
    RUN(test_cursor_rejects_bad_geometry);
    RUN(test_cursor_clamps_snaplen);
    RUN(test_block_handoff);
    RUN(test_live_loopback);
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
