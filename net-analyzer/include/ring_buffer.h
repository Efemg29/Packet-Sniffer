#ifndef NET_ANALYZER_RING_BUFFER_H
#define NET_ANALYZER_RING_BUFFER_H

#include "config.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Lockless single-producer / single-consumer frame ring.
 *
 * All slots are allocated once in rb_init(); the push/pop paths never
 * allocate. Exactly one thread may call the producer functions and exactly
 * one (other) thread may call the consumer functions.
 *
 * Producer:  s = rb_reserve(rb);  fill s;  rb_commit(rb);
 *            (or rb_record_drop(rb) when rb_reserve() returns NULL)
 * Consumer:  s = rb_peek(rb);     read s;  rb_release(rb);
 */

#define RB_CACHELINE 64

struct rb_slot {
    struct timespec ts;       /* capture time (CLOCK_REALTIME) */
    uint32_t cap_len;         /* bytes stored in data[] */
    uint32_t orig_len;        /* on-wire length; may exceed cap_len */
    uint8_t  pkttype;         /* sll_pkttype (PACKET_HOST, PACKET_OUTGOING, ...) */
    uint8_t  data[MAX_PACKET_LEN];
};

struct ring_buffer {
    struct rb_slot *slots;
    size_t capacity;          /* power of two */
    size_t mask;
    size_t map_len;

    /* Written by the producer only. */
    _Alignas(RB_CACHELINE) atomic_size_t head;
    size_t tail_cache;        /* producer's last view of tail */
    atomic_uint_fast64_t pushed;
    atomic_uint_fast64_t dropped;

    /* Written by the consumer only. */
    _Alignas(RB_CACHELINE) atomic_size_t tail;
    size_t head_cache;        /* consumer's last view of head */
    atomic_uint_fast64_t popped;
};

struct rb_stats {
    uint64_t pushed;
    uint64_t popped;
    uint64_t dropped;
    size_t   in_use;
};

/*
 * Allocate `capacity` slots (rounded up to a power of two, min 2) and
 * pre-fault them. Returns 0, or -1 with errno set.
 */
int  rb_init(struct ring_buffer *rb, size_t capacity);
void rb_destroy(struct ring_buffer *rb);

/* Producer side. rb_reserve() returns NULL when the ring is full. */
struct rb_slot *rb_reserve(struct ring_buffer *rb);
void rb_commit(struct ring_buffer *rb);
void rb_record_drop(struct ring_buffer *rb);

/* Consumer side. rb_peek() returns NULL when the ring is empty. */
const struct rb_slot *rb_peek(struct ring_buffer *rb);
void rb_release(struct ring_buffer *rb);

/* Safe from any thread; counters are read independently (not a snapshot). */
void rb_get_stats(struct ring_buffer *rb, struct rb_stats *out);

#endif
