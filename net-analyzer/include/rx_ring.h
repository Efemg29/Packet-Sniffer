#ifndef NET_ANALYZER_RX_RING_H
#define NET_ANALYZER_RX_RING_H

#include "config.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Memory-mapped AF_PACKET ring (TPACKET_V3).
 *
 * The kernel writes frames straight into the mapping. Thread 1 is the only
 * producer: it waits until a block is ready and hands that block to Thread 2.
 * Thread 2 walks the frames in place (no copy) and retires the block, which
 * returns it to the kernel. The hot path never allocates.
 *
 * A block is exclusively owned. The producer will not hand the same block
 * over again until the consumer has retired it.
 */

struct tpacket_block_desc;

struct rx_ring;

struct rx_frame {
    const uint8_t *data;
    uint32_t cap_len;          /* bytes at data[], clamped to the block */
    uint32_t orig_len;         /* on-wire length */
    struct timespec ts;
    uint8_t pkttype;           /* sll_pkttype */
};

struct rx_cursor {
    struct tpacket_block_desc *block;
    const uint8_t *pkt;        /* current tpacket3_hdr, or NULL */
    unsigned block_size;
    uint32_t left;
};

struct rx_info {
    unsigned blocks;
    unsigned block_size;
    size_t map_len;
    uint64_t frames;           /* frames handed to the consumer */
    uint64_t blocks_ready;     /* blocks handed to the consumer */
};

/* Socket must not be bound yet. budget_bytes is the memory ceiling
 * (rounded up to at least two blocks). Returns NULL on failure; errno
 * is set and the socket is left unusable for recvfrom — reopen it. */
struct rx_ring *rx_ring_open(int fd, size_t budget_bytes);

/* Userspace stand-in for tests: anonymous blocks, no packet socket.
 * Blocks start owned by the producer with status TP_STATUS_KERNEL. */
struct rx_ring *rx_ring_local(unsigned blocks, unsigned block_size);

void rx_ring_close(struct rx_ring *rx);

unsigned rx_ring_block_size(const struct rx_ring *rx);
struct tpacket_block_desc *rx_ring_block(struct rx_ring *rx, unsigned index);

/* Producer. Returns 0 when *stop is set, -1 on a poll error. */
int rx_ring_produce(struct rx_ring *rx, atomic_int *stop);

/* Consumer. rx_ring_peek() returns 1 and writes the block index, or 0
 * when none is waiting. The block stays valid until rx_ring_retire(). */
int rx_ring_peek(struct rx_ring *rx, unsigned *index);
void rx_ring_retire(struct rx_ring *rx);

void rx_ring_get_info(const struct rx_ring *rx, struct rx_info *out);

/* Walk one block. rx_cursor_next() returns 1, or 0 when the block is
 * exhausted or a header falls outside it. */
void rx_cursor_init(struct rx_cursor *c, struct tpacket_block_desc *block,
                    unsigned block_size);
int rx_cursor_next(struct rx_cursor *c, struct rx_frame *out);

#endif
