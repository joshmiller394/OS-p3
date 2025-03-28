#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include <stdint.h>
#include "lab.h"

// Macros to handle fatal mmap/munmap errors
#define handle_error_and_die(msg) \
    do {                          \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

#ifndef UINT64_C
#define UINT64_C(value) (value##ULL)
#endif

/**
 * @brief Convert the given number of bytes into the smallest integer k
 *        such that 2^k >= bytes. Uses only bit-shifts and comparisons.
 *
 * @param bytes The number of bytes
 * @return size_t The exponent k
 */
size_t btok(size_t bytes)
{
    // If bytes <= 0, this might return 0, but typically your caller
    // should handle "size=0" as a special case.
    if (bytes == 0) {
        return 0;
    }
    size_t k = 0;
    uint64_t block_size = UINT64_C(1) << k; // start at 1
    while (block_size < bytes) {
        k++;
        block_size = UINT64_C(1) << k;
    }
    return k;
}

/**
 * @brief Compute the buddy of a given block. We get the offset from pool->base,
 *        XOR with (1 << buddy->kval), and convert back to a pointer.
 *
 * @param pool   The memory pool
 * @param buddy  The memory block for which we want the buddy
 * @return struct avail*  The buddy block
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
    // Convert to uintptr_t for address arithmetic
    uintptr_t base_addr   = (uintptr_t) pool->base;
    uintptr_t buddy_addr  = (uintptr_t) buddy;
    uintptr_t offset      = buddy_addr - base_addr;

    // XOR the offset with (1 << buddy->kval)
    offset ^= ((uintptr_t)1 << buddy->kval);

    // Convert back to pointer
    return (struct avail *)(base_addr + offset);
}

/**
 * @brief Remove a block from its doubly-linked free list.
 *
 * @param block The block to remove
 */
static inline void remove_block(struct avail *block)
{
    block->prev->next = block->next;
    block->next->prev = block->prev;
    block->next = block->prev = NULL; // optional (for debugging)
}

/**
 * @brief Insert a free block at the front of pool->avail[k].
 *
 * @param pool   The memory pool
 * @param block  The block to insert
 * @param k      Which free list index
 */
static inline void insert_block_front(struct buddy_pool *pool, struct avail *block, size_t k)
{
    struct avail *head = &pool->avail[k];
    block->next = head->next;
    block->prev = head;
    head->next->prev = block;
    head->next = block;

    block->tag  = BLOCK_AVAIL;
    block->kval = (unsigned short)k;
}

/**
 * @brief Attempt to coalesce a newly-freed block with its buddy up the chain.
 *
 * @param pool   The memory pool
 * @param block  The block to coalesce
 */
static void coalesce(struct buddy_pool *pool, struct avail *block)
{
    // Keep coalescing as long as it’s smaller than the entire pool
    // and the buddy is also free and at the same k.
    while (block->kval < pool->kval_m)
    {
        struct avail *bud = buddy_calc(pool, block);
        if (bud->tag == BLOCK_AVAIL && bud->kval == block->kval)
        {
            // Remove buddy from free list
            remove_block(bud);

            // Merge them into a larger block at the lower address
            // whichever has the lower address becomes the merged block
            struct avail *lower = (bud < block) ? bud : block;
            lower->kval = block->kval + 1;
            block = lower;
        }
        else {
            // can't coalesce further
            break;
        }
    }
    // Insert final block into the appropriate free list
    insert_block_front(pool, block, block->kval);
}

/**
 * @brief Allocate a block of at least size bytes from the buddy pool.
 *        Return NULL if pool==NULL or size==0 or if no block can satisfy the request.
 *
 * @param pool The memory pool
 * @param size The requested size in bytes
 * @return void*  A pointer to the user memory or NULL if OOM
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    // Per spec: If size=0 or pool=NULL => return NULL
    if (!pool || size == 0) {
        return NULL;
    }

    // We store metadata in struct avail at start of the block;
    // user data begins immediately after. So we must add overhead.
    size_t overhead = sizeof(struct avail);
    size_t needed   = size + overhead;

    // 1) Compute exponent k so that 2^k >= needed
    size_t k = btok(needed);

    // 2) Enforce the smallest block size is 2^SMALLEST_K:
    if (k < SMALLEST_K) {
        k = SMALLEST_K;
    }

    // 3) If k > pool->kval_m, we cannot satisfy
    if (k > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // 4) Find a free block of size >= 2^k
    size_t i;
    for (i = k; i <= pool->kval_m; i++)
    {
        // if there's an actual block (not just sentinel) in pool->avail[i]
        if (pool->avail[i].next != &pool->avail[i]) {
            break;
        }
    }

    // If no free block found
    if (i > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // 5) Remove that block from the free list
    struct avail *block = pool->avail[i].next;
    remove_block(block);

    // 6) Split down to exactly k if needed
    while (i > k)
    {
        i--;
        // Buddy of half-size
        struct avail *buddy = (struct avail *)((uintptr_t)block + ((uintptr_t)1 << i));
        buddy->tag  = BLOCK_AVAIL;
        buddy->kval = (unsigned short)i;
        // Insert buddy into free list
        insert_block_front(pool, buddy, i);
        // block is now half-size
        block->kval = (unsigned short)i;
    }

    // 7) Mark block as reserved
    block->tag = BLOCK_RESERVED;

    // 8) Return pointer to user data (right after struct avail)
    return (void *)((uintptr_t)block + overhead);
}

/**
 * @brief Free a previously allocated pointer. If ptr is NULL, do nothing.
 *
 * @param pool The memory pool
 * @param ptr  The pointer returned by buddy_malloc
 */
void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (!pool || !ptr) {
        // Freed a null pointer => do nothing
        return;
    }
    // The block’s metadata is right before the user pointer
    struct avail *block = (struct avail *)((uintptr_t)ptr - sizeof(struct avail));

    // Mark it free
    block->tag = BLOCK_AVAIL;

    // Coalesce it with buddies if possible
    coalesce(pool, block);
}

/**
 * @brief Reallocate memory pointer to a new size. If ptr==NULL, acts like malloc.
 *        If size==0, frees ptr and returns NULL. Otherwise copies old data.
 *
 * @param pool The memory pool
 * @param ptr  Old pointer
 * @param size Requested new size
 * @return void* The new pointer or NULL if OOM
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    if (!pool) {
        return NULL;
    }
    if (!ptr) {
        // If ptr is NULL, just malloc
        return buddy_malloc(pool, size);
    }
    if (size == 0) {
        // Freed and return NULL
        buddy_free(pool, ptr);
        return NULL;
    }

    // 1) Allocate new block
    void *new_block = buddy_malloc(pool, size);
    if (!new_block) {
        // OOM
        return NULL;
    }

    // 2) Copy old data (up to min of old and new sizes)
    //    The old block’s total capacity = (1 << old_k) minus overhead
    struct avail *old_block = (struct avail *)((uintptr_t)ptr - sizeof(struct avail));
    size_t old_capacity = ((size_t)1 << old_block->kval) - sizeof(struct avail);

    size_t copy_size = (old_capacity < size) ? old_capacity : size;
    memcpy(new_block, ptr, copy_size);

    // 3) Free old block
    buddy_free(pool, ptr);

    // 4) Return new block
    return new_block;
}

/**
 * @brief Initialize a buddy pool with at least size bytes. Rounds up to power of two.
 *
 * @param pool A pointer to the buddy_pool struct
 * @param size The requested size in bytes
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    if (!pool) {
        return; // no-op if given null
    }

    // If user requests size=0, use default 2^DEFAULT_K
    size_t kval = 0;
    if (size == 0) {
        kval = DEFAULT_K;
    } else {
        kval = btok(size);
    }

    // Enforce bounds: at least MIN_K, at most (MAX_K-1)
    if (kval < MIN_K) {
        kval = MIN_K;
    }
    if (kval >= MAX_K) {
        kval = MAX_K - 1;
    }

    // Clear the pool struct
    memset(pool, 0, sizeof(struct buddy_pool));

    // Save
    pool->kval_m  = kval;
    pool->numbytes= ((size_t)1 << kval);

    // Memory map a block of raw memory
    pool->base = mmap(
        NULL,
        pool->numbytes,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (pool->base == MAP_FAILED) {
        handle_error_and_die("buddy_init mmap failed");
    }

    // Initialize all sentinel nodes [0..MAX_K-1]
    for (size_t i = 0; i < MAX_K; i++) {
        pool->avail[i].tag  = BLOCK_UNUSED; // sentinel unused
        pool->avail[i].kval = (unsigned short)i;
        pool->avail[i].next = &pool->avail[i]; // points to itself
        pool->avail[i].prev = &pool->avail[i];
    }

    // Add one big free block at exponent = kval
    struct avail *big = (struct avail *) pool->base;
    big->tag  = BLOCK_AVAIL;
    big->kval = (unsigned short)kval;
    big->next = big->prev = &pool->avail[kval];

    pool->avail[kval].next = big;
    pool->avail[kval].prev = big;
}

/**
 * @brief Destroy the buddy pool (munmap), then clear the structure.
 *
 * @param pool The memory pool
 */
void buddy_destroy(struct buddy_pool *pool)
{
    if (!pool) {
        return;
    }
    // Unmap
    if (munmap(pool->base, pool->numbytes) == -1) {
        handle_error_and_die("buddy_destroy");
    }
    // Clear
    memset(pool, 0, sizeof(struct buddy_pool));
}

int myMain(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    // Quick test of btok
    printf("Testing btok...\n");
    // 1 -> K=0, but recall we never actually do 2^0 blocks for real usage.
    printf("btok(1) = %zu\n", btok(1));
    // 2 -> K=1
    printf("btok(2) = %zu\n", btok(2));
    // 1024 -> K=10
    printf("btok(1024) = %zu\n", btok(1024));

    // Quick usage test
    printf("\nTesting buddy_init(0) => default 2^%d = %zu bytes\n", DEFAULT_K, (size_t)1 << DEFAULT_K);
    struct buddy_pool pool;
    buddy_init(&pool, 0); // default size of 2^DEFAULT_K
    printf("Pool size is 2^%zu = %zu bytes\n", pool.kval_m, pool.numbytes);

    // Allocate a small block
    void *p1 = buddy_malloc(&pool, 100);
    printf("buddy_malloc(100) -> %p\n", p1);

    // Realloc it bigger
    void *p2 = buddy_realloc(&pool, p1, 5000);
    printf("buddy_realloc(p1, 5000) -> %p\n", p2);

    // Free it
    buddy_free(&pool, p2);

    // Destroy
    buddy_destroy(&pool);

    // Done
    printf("\nAll done with myMain tests.\n");
    return 0;
}
