#include "ring_buffer.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

static size_t round_up_pow2(size_t n)
{
    size_t p = 2;

    while (p < n) {
        if (p > SIZE_MAX / 2)
            return 0;
        p <<= 1;
    }
    return p;
}

int rb_init(struct ring_buffer *rb, size_t capacity)
{
    size_t cap;
    void *mem;

    if (rb == NULL || capacity == 0) {
        errno = EINVAL;
        return -1;
    }
    cap = round_up_pow2(capacity);
    if (cap == 0 || cap > SIZE_MAX / sizeof(struct rb_slot)) {
        errno = EOVERFLOW;
        return -1;
    }

    memset(rb, 0, sizeof(*rb));
    rb->map_len = cap * sizeof(struct rb_slot);

    /* MAP_POPULATE pre-faults every page so the hot path never page-faults
     * on first touch of a slot. */
    mem = mmap(NULL, rb->map_len, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (mem == MAP_FAILED)
        return -1;

    rb->slots = mem;
    rb->capacity = cap;
    rb->mask = cap - 1;
    atomic_init(&rb->head, 0);
    atomic_init(&rb->tail, 0);
    atomic_init(&rb->pushed, 0);
    atomic_init(&rb->popped, 0);
    atomic_init(&rb->dropped, 0);
    return 0;
}

void rb_destroy(struct ring_buffer *rb)
{
    if (rb == NULL || rb->slots == NULL)
        return;
    munmap(rb->slots, rb->map_len);
    rb->slots = NULL;
    rb->capacity = 0;
}

struct rb_slot *rb_reserve(struct ring_buffer *rb)
{
    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);

    if (head - rb->tail_cache >= rb->capacity) {
        /* Acquire pairs with the consumer's release in rb_release(): once we
         * see the new tail, the consumer has finished reading that slot. */
        rb->tail_cache = atomic_load_explicit(&rb->tail, memory_order_acquire);
        if (head - rb->tail_cache >= rb->capacity)
            return NULL;
    }
    return &rb->slots[head & rb->mask];
}

void rb_commit(struct ring_buffer *rb)
{
    size_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);

    /* Release publishes the slot contents written since rb_reserve(). */
    atomic_store_explicit(&rb->head, head + 1, memory_order_release);
    atomic_store_explicit(&rb->pushed,
                          atomic_load_explicit(&rb->pushed,
                                               memory_order_relaxed) + 1,
                          memory_order_relaxed);
}

void rb_record_drop(struct ring_buffer *rb)
{
    atomic_store_explicit(&rb->dropped,
                          atomic_load_explicit(&rb->dropped,
                                               memory_order_relaxed) + 1,
                          memory_order_relaxed);
}

const struct rb_slot *rb_peek(struct ring_buffer *rb)
{
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    if (tail == rb->head_cache) {
        rb->head_cache = atomic_load_explicit(&rb->head, memory_order_acquire);
        if (tail == rb->head_cache)
            return NULL;
    }
    return &rb->slots[tail & rb->mask];
}

void rb_release(struct ring_buffer *rb)
{
    size_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    atomic_store_explicit(&rb->tail, tail + 1, memory_order_release);
    atomic_store_explicit(&rb->popped,
                          atomic_load_explicit(&rb->popped,
                                               memory_order_relaxed) + 1,
                          memory_order_relaxed);
}

void rb_get_stats(struct ring_buffer *rb, struct rb_stats *out)
{
    size_t head, tail;

    out->pushed  = atomic_load_explicit(&rb->pushed, memory_order_relaxed);
    out->popped  = atomic_load_explicit(&rb->popped, memory_order_relaxed);
    out->dropped = atomic_load_explicit(&rb->dropped, memory_order_relaxed);
    /* Tail first: head can only grow, so head - tail never underflows. */
    tail = atomic_load_explicit(&rb->tail, memory_order_acquire);
    head = atomic_load_explicit(&rb->head, memory_order_acquire);
    out->in_use = head - tail;
    if (out->in_use > rb->capacity)
        out->in_use = rb->capacity;
}
