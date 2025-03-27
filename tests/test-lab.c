#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "harness/unity.h"
#include "../src/lab.h"

/**
 *  Declare a global (or static file-scope) buddy_pool,
 *  plus any global size you want to init with.
 */
static struct buddy_pool g_pool;
static const size_t g_pool_size = (UINT64_C(1) << MIN_K);

/**
 * Helper that checks if the buddy pool is "full":
 * i.e., a single free block at index `kval_m` and nothing else.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  for (size_t i = 0; i < pool->kval_m; i++)
  {
    assert(pool->avail[i].next == &pool->avail[i]);
    assert(pool->avail[i].prev == &pool->avail[i]);
    assert(pool->avail[i].tag  == BLOCK_UNUSED);
    assert(pool->avail[i].kval == i);
  }

  assert(pool->avail[pool->kval_m].next->tag  == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Helper that checks if the buddy pool is "empty":
 * i.e., no free blocks at any index from [0..kval_m].
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  for (size_t i = 0; i <= pool->kval_m; i++)
  {
    assert(pool->avail[i].next == &pool->avail[i]);
    assert(pool->avail[i].prev == &pool->avail[i]);
    assert(pool->avail[i].tag  == BLOCK_UNUSED);
    assert(pool->avail[i].kval == i);
  }
}

//=================================================
// Unity boilerplate
//=================================================

/**
 * setUp runs before each test. Here we do a standard buddy_init on g_pool
 * with a consistent size.
 */
void setUp(void)
{
    // If we want to test an entire range of sizes, we cannot do it here.
    // But for tests needing the same size, let's do this:
    buddy_init(&g_pool, g_pool_size);
}

/**
 * tearDown runs after each test. We destroy the buddy pool,
 * so the next test starts fresh.
 */
void tearDown(void)
{
    buddy_destroy(&g_pool);
}

//=================================================
// Tests
//=================================================

/**
 * Example test that just ensures we start with a full pool and do a 1-byte allocation + free.
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");

  // Now that we have setUp/tearDown, we do NOT need to buddy_init/destroy here.
  // We can directly operate on g_pool:

  void *mem = buddy_malloc(&g_pool, 1);
  // Additional optional asserts...
  buddy_free(&g_pool, mem);

  // Should be back to "full" after free
  check_buddy_pool_full(&g_pool);
}

/**
 * Test a single block that (nearly) consumes the entire memory pool
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");

  // Our g_pool is already init to (1 << MIN_K).
  // We'll ask for nearly that entire block:
  size_t total_bytes = g_pool.numbytes;
  size_t ask = total_bytes - sizeof(struct avail);

  void *mem = buddy_malloc(&g_pool, ask);
  TEST_ASSERT_NOT_NULL(mem);

  // Check metadata
  struct avail *tmp = (struct avail *)mem - 1;
  TEST_ASSERT_EQUAL_UINT16(MIN_K, tmp->kval);
  TEST_ASSERT_EQUAL_UINT16(BLOCK_RESERVED, tmp->tag);

  // Pool should now be "empty"
  check_buddy_pool_empty(&g_pool);

  // Another allocation should fail
  void *fail = buddy_malloc(&g_pool, 5);
  TEST_ASSERT_NULL(fail);
  TEST_ASSERT_EQUAL_INT(ENOMEM, errno);

  // Freed => back to full
  buddy_free(&g_pool, mem);
  check_buddy_pool_full(&g_pool);
}

/**
 * Another example test.
 * Because setUp/tearDown handle the init/destroy,
 * we can just use the global g_pool freely.
 */
void test_buddy_malloc_zero_bytes(void)
{
  fprintf(stderr, "->Testing buddy_malloc(0) returns NULL\n");

  // Since setUp gave us a fresh g_pool:
  void *p = buddy_malloc(&g_pool, 0);
  TEST_ASSERT_NULL_MESSAGE(p, "buddy_malloc(0) should return NULL");

  // Pool should remain full
  check_buddy_pool_full(&g_pool);
}

/**
 * Show that buddy_free(NULL) does nothing to g_pool
 */
void test_buddy_free_null(void)
{
  fprintf(stderr, "->Testing buddy_free(NULL) does nothing\n");

  buddy_free(&g_pool, NULL); // Freed a null pointer

  // Should remain full
  check_buddy_pool_full(&g_pool);
}

/**
 * Realloc that grows a block
 */
void test_buddy_realloc_grow(void)
{
  fprintf(stderr, "->Testing buddy_realloc grows a block\n");

  void *ptr = buddy_malloc(&g_pool, 100);
  TEST_ASSERT_NOT_NULL(ptr);

  void *bigger = buddy_realloc(&g_pool, ptr, 1000);
  TEST_ASSERT_NOT_NULL(bigger);

  // Freed the old pointer internally
  buddy_free(&g_pool, bigger);

  // Should be full again
  check_buddy_pool_full(&g_pool);
}

/**
 * Realloc that shrinks a block
 */
void test_buddy_realloc_shrink(void)
{
  fprintf(stderr, "->Testing buddy_realloc shrinks a block\n");

  void *ptr = buddy_malloc(&g_pool, 1000);
  TEST_ASSERT_NOT_NULL(ptr);

  void *smaller = buddy_realloc(&g_pool, ptr, 10);
  TEST_ASSERT_NOT_NULL(smaller);

  buddy_free(&g_pool, smaller);

  check_buddy_pool_full(&g_pool);
}

/**
 * Test coalescing: allocate two buddies, free them,
 * see if the pool coalesces fully.
 */
void test_buddy_coalescing(void)
{
  fprintf(stderr, "->Testing buddy coalescing\n");

  // We'll do two small allocations that end up side by side
  void *p1 = buddy_malloc(&g_pool, 64);
  void *p2 = buddy_malloc(&g_pool, 64);
  TEST_ASSERT_NOT_NULL(p1);
  TEST_ASSERT_NOT_NULL(p2);

  buddy_free(&g_pool, p1);
  buddy_free(&g_pool, p2);

  // Should coalesce back to a full block
  check_buddy_pool_full(&g_pool);
}

/**
 * Example specialized test that tries multiple sizes (MIN_K..DEFAULT_K).
 * This test is a *bit* special because it does its own init/destroy loops
 * inside. We'll override the default setUp/tearDown approach for this test
 * by re-initializing the pool each time inside the test.
 *
 * If you want to do so, you can either:
 *  - remove the buddy_destroy(&g_pool) in tearDown if you want to do a single usage,
 *  - or create a local buddy_pool variable for each iteration to avoid messing with global.
 */
void test_buddy_init_variations(void)
{
  fprintf(stderr, "->Testing buddy_init with multiple sizes inside one test.\n");

  // We'll use a *local* pool each time, ignoring g_pool from setUp:
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
  {
    struct buddy_pool local_pool;
    size_t size = UINT64_C(1) << i;
    buddy_init(&local_pool, size);

    check_buddy_pool_full(&local_pool);
    buddy_destroy(&local_pool);
  }
}

//=================================================
// Test runner
//=================================================
int main(void)
{
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%u\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();

  // Normal tests that rely on the global setUp/tearDown
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_buddy_malloc_zero_bytes);
  RUN_TEST(test_buddy_free_null);
  RUN_TEST(test_buddy_realloc_grow);
  RUN_TEST(test_buddy_realloc_shrink);
  RUN_TEST(test_buddy_coalescing);

  // A specialized test that does its own repeated init/destroy:
  RUN_TEST(test_buddy_init_variations);

  return UNITY_END();
}
