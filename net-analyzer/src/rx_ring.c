#include "rx_ring.h"

#include <errno.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Producer owns the block until it publishes; consumer owns it until retire. */
#define RX_WITH_KERNEL 0u
#define RX_WITH_USER   1u

#define RX_MAX_BLOCKS 256u
#define RX_MAX_BLOCK  (4u << 20)          /* 4 MiB */
#define RX_RETIRE_MS  100u

struct rx_ring {
    int fd;                               /* packet socket, or -1 if local */
    uint8_t *map;
    size_t map_len;
    unsigned block_size;
    unsigned block_nr;
    int local;

    /* Counting handoff. The block index is head % block_nr (producer)
     * and tail % block_nr (consumer); both sides walk in the same order. */
    atomic_size_t head;
    size_t tail_cache;
    atomic_size_t tail;
    size_t head_cache;

    atomic_uint_fast64_t frames;
    atomic_uint_fast64_t blocks_ready;
    atomic_uint *owner;                   /* one per block */
};

static unsigned round_up_pow2_u(unsigned n, unsigned min)
{
    unsigned p = min ? min : 1u;

    while (p < n) {
        if (p > UINT_MAX / 2u)
            return 0;
        p <<= 1u;
    }
    return p;
}

static int publish(struct rx_ring *rx)
{
    size_t head = atomic_load_explicit(&rx->head, memory_order_relaxed);

    if (head - rx->tail_cache >= rx->block_nr) {
        rx->tail_cache = atomic_load_explicit(&rx->tail, memory_order_acquire);
        if (head - rx->tail_cache >= rx->block_nr)
            return 0;
    }
    atomic_store_explicit(&rx->head, head + 1, memory_order_release);
    return 1;
}

static void wait_spin(unsigned *spins)
{
    static const struct timespec nap = { 0, 100000 };

    if (*spins < 64) {
        (*spins)++;
        sched_yield();
    } else {
        nanosleep(&nap, NULL);
    }
}

static int stopped(atomic_int *stop)
{
    return atomic_load_explicit(stop, memory_order_relaxed) != 0;
}

static int wait_block(struct rx_ring *rx, atomic_int *stop)
{
    if (rx->fd < 0) {
        static const struct timespec nap = { 0, 200000 };

        nanosleep(&nap, NULL);
        return stopped(stop) ? -1 : 0;
    }

    struct pollfd pfd;

    pfd.fd = rx->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    for (;;) {
        int pr = poll(&pfd, 1, 250);

        if (pr < 0) {
            if (errno == EINTR) {
                if (stopped(stop))
                    return -1;
                continue;
            }
            return -1;
        }
        return 0;
    }
}

static int alloc_common(struct rx_ring **out, unsigned blocks, unsigned block_size,
                        int fd, int local, void *map, size_t map_len)
{
    struct rx_ring *rx;
    unsigned i;

    rx = malloc(sizeof(*rx));
    if (rx == NULL)
        return -1;
    memset(rx, 0, sizeof(*rx));
    rx->owner = malloc((size_t)blocks * sizeof(*rx->owner));
    if (rx->owner == NULL) {
        free(rx);
        return -1;
    }
    rx->fd = fd;
    rx->map = map;
    rx->map_len = map_len;
    rx->block_size = block_size;
    rx->block_nr = blocks;
    rx->local = local;
    atomic_init(&rx->head, 0);
    atomic_init(&rx->tail, 0);
    atomic_init(&rx->frames, 0);
    atomic_init(&rx->blocks_ready, 0);
    for (i = 0; i < blocks; i++)
        atomic_init(&rx->owner[i], RX_WITH_KERNEL);
    *out = rx;
    return 0;
}

struct rx_ring *rx_ring_open(int fd, size_t budget_bytes)
{
    struct rx_ring *rx = NULL;
    struct tpacket_req3 req;
    long page;
    unsigned frame, block_size, blocks, fpb;
    int version = TPACKET_V3;
    void *map;
    size_t map_len;
    unsigned char *p;
    size_t off;

    if (fd < 0 || budget_bytes == 0) {
        errno = EINVAL;
        return NULL;
    }
    page = sysconf(_SC_PAGESIZE);
    if (page < 1) {
        errno = EINVAL;
        return NULL;
    }

    frame = (unsigned)TPACKET_ALIGN(TPACKET3_HDRLEN + MAX_PACKET_LEN);
    block_size = round_up_pow2_u(frame, (unsigned)page);
    if (block_size == 0) {
        errno = EINVAL;
        return NULL;
    }
    /* Prefer fewer, larger blocks up to 4 MiB, but keep at least two. */
    while (block_size < RX_MAX_BLOCK &&
           budget_bytes / (block_size * 2u) >= 2u &&
           block_size <= UINT_MAX / 2u)
        block_size <<= 1u;

    if (budget_bytes / block_size < 2u)
        blocks = 2u;
    else
        blocks = (unsigned)(budget_bytes / block_size);
    if (blocks > RX_MAX_BLOCKS)
        blocks = RX_MAX_BLOCKS;

    fpb = block_size / frame;
    if (fpb == 0) {
        errno = EINVAL;
        return NULL;
    }

    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version,
                   sizeof(version)) != 0)
        return NULL;

    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_block_nr = blocks;
    req.tp_frame_size = frame;
    req.tp_frame_nr = fpb * blocks;
    req.tp_retire_blk_tov = RX_RETIRE_MS;
    req.tp_sizeof_priv = 0;
    req.tp_feature_req_word = 0;
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0)
        return NULL;

    map_len = (size_t)block_size * blocks;
    map = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
        return NULL;

    /* Fault the mapping in now so the first packet does not pay for it. */
    p = map;
    for (off = 0; off < map_len; off += (size_t)page) {
        volatile uint8_t *vp = p + off;

        (void)*vp;
    }

    if (alloc_common(&rx, blocks, block_size, fd, 0, map, map_len) != 0) {
        munmap(map, map_len);
        return NULL;
    }
    return rx;
}

struct rx_ring *rx_ring_local(unsigned blocks, unsigned block_size)
{
    struct rx_ring *rx = NULL;
    void *map;
    size_t map_len;
    long page;

    page = sysconf(_SC_PAGESIZE);
    if (blocks < 2 || blocks > RX_MAX_BLOCKS || block_size < 512 ||
        page < 1 || (block_size % (unsigned)page) != 0) {
        errno = EINVAL;
        return NULL;
    }
    map_len = (size_t)block_size * blocks;
    map = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED)
        return NULL;
    if (alloc_common(&rx, blocks, block_size, -1, 1, map, map_len) != 0) {
        munmap(map, map_len);
        return NULL;
    }
    return rx;
}

void rx_ring_close(struct rx_ring *rx)
{
    if (rx == NULL)
        return;
    if (rx->map != NULL)
        munmap(rx->map, rx->map_len);
    free(rx->owner);
    free(rx);
}

unsigned rx_ring_block_size(const struct rx_ring *rx)
{
    return rx->block_size;
}

struct tpacket_block_desc *rx_ring_block(struct rx_ring *rx, unsigned index)
{
    return (struct tpacket_block_desc *)(rx->map +
                                         (size_t)index * rx->block_size);
}

int rx_ring_produce(struct rx_ring *rx, atomic_int *stop)
{
    unsigned i = 0;
    unsigned spins = 0;

    while (!stopped(stop)) {
        struct tpacket_block_desc *b = rx_ring_block(rx, i);
        uint32_t status = __atomic_load_n(&b->hdr.bh1.block_status,
                                           __ATOMIC_ACQUIRE);
        uint32_t own = atomic_load_explicit(&rx->owner[i], memory_order_acquire);

        if (own != RX_WITH_KERNEL || (status & TP_STATUS_USER) == 0) {
            if (wait_block(rx, stop) != 0) {
                if (stopped(stop))
                    return 0;
                return -1;
            }
            continue;
        }

        if (b->hdr.bh1.num_pkts == 0) {
            __atomic_store_n(&b->hdr.bh1.block_status, TP_STATUS_KERNEL,
                             __ATOMIC_RELEASE);
            i = (i + 1u) % rx->block_nr;
            spins = 0;
            continue;
        }

        /* Re-check ownership in this iteration. try-publish does not wait,
         * so a consumer cannot retire a block we have not handed over, and
         * we do not publish from a status observed on an earlier pass. */
        if (!publish(rx)) {
            wait_spin(&spins);
            continue;
        }
        atomic_fetch_add_explicit(&rx->frames, b->hdr.bh1.num_pkts,
                                  memory_order_relaxed);
        atomic_fetch_add_explicit(&rx->blocks_ready, 1, memory_order_relaxed);
        atomic_store_explicit(&rx->owner[i], RX_WITH_USER, memory_order_release);
        i = (i + 1u) % rx->block_nr;
        spins = 0;
    }
    return 0;
}

int rx_ring_peek(struct rx_ring *rx, unsigned *index)
{
    size_t tail = atomic_load_explicit(&rx->tail, memory_order_relaxed);

    if (tail == rx->head_cache) {
        rx->head_cache = atomic_load_explicit(&rx->head, memory_order_acquire);
        if (tail == rx->head_cache)
            return 0;
    }
    /* owner[i] is stored after the slot is published, so a full queue never
     * leaves a block marked user-owned. Acquire it before touching frames. */
    if (atomic_load_explicit(&rx->owner[tail % rx->block_nr],
                             memory_order_acquire) != RX_WITH_USER)
        return 0;
    *index = (unsigned)(tail % rx->block_nr);
    return 1;
}

void rx_ring_retire(struct rx_ring *rx)
{
    size_t tail = atomic_load_explicit(&rx->tail, memory_order_relaxed);
    unsigned index = (unsigned)(tail % rx->block_nr);
    struct tpacket_block_desc *b = rx_ring_block(rx, index);

    __atomic_store_n(&b->hdr.bh1.block_status, TP_STATUS_KERNEL,
                     __ATOMIC_RELEASE);
    atomic_store_explicit(&rx->owner[index], RX_WITH_KERNEL, memory_order_release);
    atomic_store_explicit(&rx->tail, tail + 1, memory_order_release);
}

void rx_ring_get_info(const struct rx_ring *rx, struct rx_info *out)
{
    out->blocks = rx->block_nr;
    out->block_size = rx->block_size;
    out->map_len = rx->map_len;
    out->frames = atomic_load_explicit(&rx->frames, memory_order_relaxed);
    out->blocks_ready = atomic_load_explicit(&rx->blocks_ready,
                                             memory_order_relaxed);
}

void rx_cursor_init(struct rx_cursor *c, struct tpacket_block_desc *block,
                    unsigned block_size)
{
    uint32_t off;

    c->block = block;
    c->pkt = NULL;
    c->block_size = block_size;
    c->left = 0;
    if (block == NULL || block_size < sizeof(*block))
        return;
    off = block->hdr.bh1.offset_to_first_pkt;
    if (block->hdr.bh1.num_pkts == 0)
        return;
    if (off < sizeof(*block) || off >= block_size)
        return;
    c->left = block->hdr.bh1.num_pkts;
}

/* True when [off, off+n) sits inside the block. n may be 0. */
static int span_ok(const struct rx_cursor *c, size_t off, size_t n)
{
    if (off > c->block_size)
        return 0;
    if (n > c->block_size - off)
        return 0;
    return 1;
}

int rx_cursor_next(struct rx_cursor *c, struct rx_frame *out)
{
    const struct tpacket3_hdr *hdr;
    const uint8_t *base;
    size_t hdr_off;
    size_t mac_off;
    size_t sll_off;
    uint32_t snap;

    if (c->left == 0)
        return 0;

    base = (const uint8_t *)c->block;
    if (c->pkt == NULL) {
        hdr_off = c->block->hdr.bh1.offset_to_first_pkt;
    } else {
        const struct tpacket3_hdr *prev = (const struct tpacket3_hdr *)c->pkt;
        size_t prev_off = (size_t)((const uint8_t *)prev - base);

        if (prev->tp_next_offset == 0 ||
            prev_off > c->block_size ||
            prev->tp_next_offset > c->block_size - prev_off)
            return 0;
        hdr_off = prev_off + prev->tp_next_offset;
    }
    if (!span_ok(c, hdr_off, sizeof(*hdr)))
        return 0;

    hdr = (const struct tpacket3_hdr *)(base + hdr_off);
    c->pkt = (const uint8_t *)hdr;
    c->left--;

    memset(out, 0, sizeof(*out));
    out->ts.tv_sec = (time_t)hdr->tp_sec;
    out->ts.tv_nsec = (long)hdr->tp_nsec;
    out->orig_len = hdr->tp_len;
    snap = hdr->tp_snaplen;

    if (hdr->tp_mac > c->block_size - hdr_off)
        snap = 0;
    else {
        mac_off = hdr_off + hdr->tp_mac;
        if (snap > c->block_size - mac_off)
            snap = (uint32_t)(c->block_size - mac_off);
        out->data = base + mac_off;
    }
    if (snap > MAX_PACKET_LEN)
        snap = MAX_PACKET_LEN;
    out->cap_len = snap;
    if (out->data == NULL)
        out->data = base;

    sll_off = hdr_off + TPACKET_ALIGN(sizeof(*hdr));
    if (span_ok(c, sll_off, sizeof(struct sockaddr_ll))) {
        const struct sockaddr_ll *sll =
            (const struct sockaddr_ll *)(base + sll_off);

        out->pkttype = sll->sll_pkttype;
    }
    return 1;
}
