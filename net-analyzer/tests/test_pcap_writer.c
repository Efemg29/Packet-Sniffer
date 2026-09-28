#include "pcap_writer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static struct pcap_writer g_w;

static uint32_t rd32(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, sizeof(v));
    return v;
}

static uint16_t rd16(const uint8_t *p)
{
    uint16_t v;

    memcpy(&v, p, sizeof(v));
    return v;
}

static int little_endian(void)
{
    const uint16_t one = 1;

    return *(const uint8_t *)&one == 1;
}

static void tmp_path(char *out, size_t len)
{
    int fd;

    snprintf(out, len, "/tmp/test_pcap_XXXXXX");
    fd = mkstemp(out);
    if (fd >= 0)
        close(fd);
}

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    long n;

    *len = 0;
    if (fp == NULL)
        return NULL;
    fseek(fp, 0, SEEK_END);
    n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = malloc(n > 0 ? (size_t)n : 1);
    if (buf != NULL && n > 0 && fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(fp);
    if (buf != NULL)
        *len = (size_t)n;
    return buf;
}

static void test_global_header_layout(void)
{
    static const uint8_t le[PCAP_GLOBAL_HDR_LEN] = {
        0xd4, 0xc3, 0xb2, 0xa1,     /* magic */
        0x02, 0x00, 0x04, 0x00,     /* version 2.4 */
        0x00, 0x00, 0x00, 0x00,     /* thiszone */
        0x00, 0x00, 0x00, 0x00,     /* sigfigs */
        0xff, 0xff, 0x00, 0x00,     /* snaplen 65535 */
        0x01, 0x00, 0x00, 0x00,     /* LINKTYPE_ETHERNET */
    };
    uint8_t h[PCAP_GLOBAL_HDR_LEN];

    pcap_encode_global_header(h);
    CHECK_EQ(rd32(h + 0), 0xa1b2c3d4u);
    CHECK_EQ(rd16(h + 4), 2);
    CHECK_EQ(rd16(h + 6), 4);
    CHECK_EQ(rd32(h + 8), 0);
    CHECK_EQ(rd32(h + 12), 0);
    CHECK_EQ(rd32(h + 16), 65535);
    CHECK_EQ(rd32(h + 20), 1);
    if (little_endian())
        CHECK(memcmp(h, le, sizeof(le)) == 0);
}

static void test_record_header_layout(void)
{
    struct timespec ts = { 1700000000, 123456789 };
    uint8_t h[PCAP_RECORD_HDR_LEN];

    pcap_encode_record_header(h, &ts, 60, 60);
    CHECK_EQ(rd32(h + 0), 1700000000u);
    CHECK_EQ(rd32(h + 4), 123456);
    CHECK_EQ(rd32(h + 8), 60);
    CHECK_EQ(rd32(h + 12), 60);
    if (little_endian()) {
        CHECK_EQ(h[0], 0x00);               /* 1700000000 = 0x6553f100 */
        CHECK_EQ(h[1], 0xf1);
        CHECK_EQ(h[2], 0x53);
        CHECK_EQ(h[3], 0x65);
        CHECK_EQ(h[8], 60);
    }

    /* Wire length larger than what was captured. */
    pcap_encode_record_header(h, &ts, 100, 1514);
    CHECK_EQ(rd32(h + 8), 100);
    CHECK_EQ(rd32(h + 12), 1514);
}

static void test_record_header_edge_cases(void)
{
    struct timespec ts = { 5, 999999999 };
    uint8_t h[PCAP_RECORD_HDR_LEN];

    pcap_encode_record_header(h, &ts, 10, 10);
    CHECK_EQ(rd32(h + 4), 999999);          /* usec never reaches 1e6 */

    /* incl_len is clamped to the snaplen; orig_len keeps the wire length. */
    pcap_encode_record_header(h, &ts, 65536, 70000);
    CHECK_EQ(rd32(h + 8), 65535);
    CHECK_EQ(rd32(h + 12), 70000);

    /* orig_len can never be smaller than incl_len. */
    pcap_encode_record_header(h, &ts, 200, 50);
    CHECK_EQ(rd32(h + 8), 200);
    CHECK_EQ(rd32(h + 12), 200);

    /* Invalid timestamps become 0 rather than garbage. */
    ts.tv_sec = -1;
    ts.tv_nsec = 5;
    pcap_encode_record_header(h, &ts, 1, 1);
    CHECK_EQ(rd32(h + 0), 0);
    CHECK_EQ(rd32(h + 4), 0);
    ts.tv_sec = 7;
    ts.tv_nsec = 2000000000L;
    pcap_encode_record_header(h, &ts, 1, 1);
    CHECK_EQ(rd32(h + 0), 7);
    CHECK_EQ(rd32(h + 4), 0);
    pcap_encode_record_header(h, NULL, 1, 1);
    CHECK_EQ(rd32(h + 0), 0);
}

static void test_file_round_trip(void)
{
    static uint8_t big[MAX_PACKET_LEN];
    uint8_t small[60];
    struct timespec t1 = { 1000, 1000 }, t2 = { 1001, 2000000 },
                    t3 = { 1002, 999999000 };
    char path[64];
    size_t len, off, i;
    uint8_t *buf;

    for (i = 0; i < sizeof(small); i++)
        small[i] = (uint8_t)i;
    for (i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)(i * 7);

    tmp_path(path, sizeof(path));
    CHECK_EQ(pcap_open(&g_w, path), 0);
    CHECK_EQ(g_w.bytes, PCAP_GLOBAL_HDR_LEN);
    CHECK_EQ(pcap_write(&g_w, &t1, small, sizeof(small), sizeof(small)), 0);
    CHECK_EQ(pcap_write(&g_w, &t2, NULL, 0, 0), 0);
    CHECK_EQ(pcap_write(&g_w, &t3, big, sizeof(big), 70000), 0);
    CHECK_EQ(g_w.packets, 3);
    CHECK_EQ(g_w.unflushed, 3);
    CHECK_EQ(pcap_flush(&g_w), 0);
    CHECK_EQ(g_w.unflushed, 0);
    CHECK_EQ(pcap_close(&g_w), 0);
    CHECK_EQ(pcap_close(&g_w), 0);          /* idempotent */

    buf = slurp(path, &len);
    CHECK(buf != NULL);
    CHECK_EQ(len, PCAP_GLOBAL_HDR_LEN + 3 * PCAP_RECORD_HDR_LEN +
                  sizeof(small) + 0 + 65535);
    CHECK_EQ(len, g_w.bytes);
    if (buf != NULL && len == g_w.bytes) {
        CHECK_EQ(rd32(buf), PCAP_MAGIC);
        off = PCAP_GLOBAL_HDR_LEN;

        CHECK_EQ(rd32(buf + off + 0), 1000);
        CHECK_EQ(rd32(buf + off + 4), 1);
        CHECK_EQ(rd32(buf + off + 8), 60);
        CHECK_EQ(rd32(buf + off + 12), 60);
        CHECK(memcmp(buf + off + 16, small, sizeof(small)) == 0);
        off += PCAP_RECORD_HDR_LEN + sizeof(small);

        CHECK_EQ(rd32(buf + off + 0), 1001);
        CHECK_EQ(rd32(buf + off + 4), 2000);
        CHECK_EQ(rd32(buf + off + 8), 0);
        CHECK_EQ(rd32(buf + off + 12), 0);
        off += PCAP_RECORD_HDR_LEN;

        CHECK_EQ(rd32(buf + off + 0), 1002);
        CHECK_EQ(rd32(buf + off + 4), 999999);
        CHECK_EQ(rd32(buf + off + 8), 65535);
        CHECK_EQ(rd32(buf + off + 12), 70000);
        CHECK(memcmp(buf + off + 16, big, 65535) == 0);
    }
    free(buf);
    unlink(path);
}

static void test_many_records(void)
{
    uint8_t frame[128];
    struct timespec ts = { 42, 0 };
    char path[64];
    size_t len, off = PCAP_GLOBAL_HDR_LEN;
    uint8_t *buf;
    uint32_t i, bad = 0;
    const uint32_t n = 20000;       /* crosses the stdio buffer many times */

    tmp_path(path, sizeof(path));
    CHECK_EQ(pcap_open(&g_w, path), 0);
    for (i = 0; i < n; i++) {
        uint32_t l = 14 + i % 100;

        memset(frame, (int)(i & 0xff), l);
        ts.tv_nsec = (long)i * 1000L;
        if (pcap_write(&g_w, &ts, frame, l, l) != 0)
            bad++;
    }
    CHECK_EQ(bad, 0);
    CHECK_EQ(pcap_close(&g_w), 0);

    buf = slurp(path, &len);
    CHECK_EQ(len, g_w.bytes);
    for (i = 0; buf != NULL && i < n && off + PCAP_RECORD_HDR_LEN <= len; i++) {
        uint32_t l = rd32(buf + off + 8);

        if (l != 14 + i % 100 || rd32(buf + off + 4) != i ||
            buf[off + PCAP_RECORD_HDR_LEN] != (uint8_t)(i & 0xff))
            bad++;
        off += PCAP_RECORD_HDR_LEN + l;
    }
    CHECK_EQ(i, n);
    CHECK_EQ(off, len);
    CHECK_EQ(bad, 0);
    free(buf);
    unlink(path);
}

static void test_open_errors(void)
{
    struct timespec ts = { 1, 0 };
    uint8_t b = 0;

    CHECK_EQ(pcap_open(&g_w, "/nonexistent-dir/x.pcap"), ENOENT);
    CHECK(g_w.fp == NULL);
    CHECK_EQ(pcap_write(&g_w, &ts, &b, 1, 1), ENOENT);
    CHECK_EQ(pcap_flush(&g_w), ENOENT);
    CHECK_EQ(pcap_close(&g_w), ENOENT);
    CHECK_EQ(g_w.packets, 0);

    CHECK_EQ(pcap_open(&g_w, NULL), EINVAL);
    CHECK_EQ(pcap_close(&g_w), EINVAL);
}

static void test_write_error_is_sticky(void)
{
    static uint8_t frame[4096];
    struct timespec ts = { 1, 0 };
    int i, rc = 0;

    if (access("/dev/full", W_OK) != 0) {
        printf("  (skipped: no /dev/full)\n");
        return;
    }
    /* The header write is flushed at open, so /dev/full fails right away. */
    rc = pcap_open(&g_w, "/dev/full");
    CHECK_EQ(rc, ENOSPC);
    CHECK_EQ(pcap_close(&g_w), ENOSPC);

    /* Failures inside the stdio buffer surface at the latest on close. */
    g_w.fp = fopen("/dev/full", "wb");
    CHECK(g_w.fp != NULL);
    if (g_w.fp == NULL)
        return;
    g_w.err = 0;
    setvbuf(g_w.fp, g_w.iobuf, _IOFBF, sizeof(g_w.iobuf));
    rc = 0;
    for (i = 0; i < 200 && rc == 0; i++)
        rc = pcap_write(&g_w, &ts, frame, sizeof(frame), sizeof(frame));
    CHECK_EQ(rc, ENOSPC);
    CHECK_EQ(pcap_write(&g_w, &ts, frame, 1, 1), ENOSPC);
    CHECK_EQ(pcap_close(&g_w), ENOSPC);
}

int main(void)
{
    RUN(test_global_header_layout);
    RUN(test_record_header_layout);
    RUN(test_record_header_edge_cases);
    RUN(test_file_round_trip);
    RUN(test_many_records);
    RUN(test_open_errors);
    RUN(test_write_error_is_sticky);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
