/*
 * mm-naive.c - The least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by allocating a
 * new page as needed.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused.
 *
 * The heap check and free check always succeeds, because the
 * allocator doesn't depend on any of the old data.
 *
 * This implementation makes use of an explicit free list. The rules for
 * allocation are to find the first available block that fits the amount to be
 * allocated. This first fit strategy can be modified easily by changing the logic
 * contained within find_available_block.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

// TODO: Use compact header/footer.
// typedef int block_header;
// typedef int block_footer;
typedef struct page_node {
  struct page_node *next;
  struct page_node *prev;
} page_node;

typedef struct list_node {
 struct list_node *prev;
 struct list_node *next;
} list_node;

typedef struct {
  size_t size;
  char allocated;
} block_header;

typedef struct {
  size_t size;
  int filler;
} block_footer;

// ----------------------------- MACROS ---------------------------------

/* always use 16-byte alignment */
#define ALIGNMENT 16
#define BLOCK_SIZE(size) (size / ALIGNMENT)

/* the overhead for a block is calculated as the size of the header + size of footer */
#define BLOCK_OVERHEAD (sizeof(block_header) + sizeof(block_footer))
// TODO: Use the void* to store an explicit list!

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

/* Page size is size we want + page_node + block overhead plus the terminator block */
#define NEW_PAGE_SIZE(size) (PAGE_ALIGN(size + sizeof(page_node) + (BLOCK_OVERHEAD + sizeof(list_node)) + sizeof(block_header))<<4)
/* rounds up to the nearest multiple of (mem_pagesize()<<4)*/
#define PAGE_ALIGN(sz) (((sz) + ((mem_pagesize())-1)) & ~((mem_pagesize())-1))

/* Available size is the page size - the size of page node - terminator block */
#define AVAILABLE_SIZE(size) (ALIGN(size - sizeof(page_node) - sizeof(block_header)))
#define FIRST_BLKP(page) (page + sizeof(page_node) + sizeof(block_header))

/* rounds down to the nearest multiple of (mem_pagesize() <<4)*/
#define ADDRESS_PAGE_START(p) ((void *)(((size_t)p) & ~(mem_pagesize()-1)))

/* gets the header/footer from a payload pointer */
#define HDRP(bp) ((char *)(bp) - sizeof(block_header))
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - BLOCK_OVERHEAD)

// TODO: Use compact header/footer.
// #define GET(p) (*(int *)(p))
// #define PUT(p, val) (*(int *)(p) = (val))

/* gets the size/allocated for a pointer that points to a header */
#define GET_SIZE(p) ((block_header *)(p))->size
#define GET_ALLOC(p) ((block_header *)(p))->allocated

#define NEXT_PAGE(p) ((page_node *)(p))->next
#define PREV_PAGE(p) ((page_node *)(p))->prev

// TODO: Use compact header/footer.
// #define GET_ALLOC(p) (GET(p) & 0x1)
// #define GET_SIZE(p) (GET(p) & ~0xF)
// #define PACK(size, alloc) ((size) | (alloc))

/* gets the next/prev block pointer given a block pointer */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE((char *)(bp) - BLOCK_OVERHEAD))

#define NEXT_FREE(node) (((list_node *)(node))->next)
#define PREV_FREE(node) (((list_node *)(node))->prev)

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

// ----------------------------- /MACROS ---------------------------------

// ----------------------------- DEBUGGING ---------------------------------
// #define DEBUG 1
// #define DEBUG_MALLOC 1
// #define DEBUG_FREE 1
// #define DEBUG_CREATE_PAGE 1
// #define DEBUG_PAGE_REMOVE 1
// #define DEBUG_ASSERTS 1
// #define DEBUG_COALESCE 1
// #define DEBUG_MM_CHECK 1
// #define DEBUG_MM_CHECK_VERBOSE 1
// #define DEBUG_FREE_LIST 1
// #define DEBUG_FIND_AVAILABLE 1
// ----------------------------- /DEBUGGING ---------------------------------

void *first_page = NULL;
void *free_list = NULL;

int ptr_is_mapped(void *p, size_t len)
{
  void *s = ADDRESS_PAGE_START(p);
  // printf("PAGE: %p, SIZE: %zu\n", s, BLOCK_SIZE(PAGE_ALIGN((p + len) - s)));
  return mem_is_mapped(s, PAGE_ALIGN((p + len) - s));
}

void remove_from_free_list(list_node *node)
{
  #if DEBUG || DEBUG_FREE_LIST
  // printf("\n================= REMOVE FREE LIST ===============\n");
  printf("REMOVE FREE LIST: %p\n", HDRP(node));
  #endif
  if (PREV_FREE(node) != NULL && ptr_is_mapped(PREV_FREE(node), BLOCK_OVERHEAD))
  {
    NEXT_FREE(PREV_FREE(node)) = NEXT_FREE(node);
    #if DEBUG || DEBUG_FREE_LIST
    printf("SET NEXT: %p -> %p\n", HDRP(node->prev), HDRP(node->next));
    #endif
  }
  else
  {
    free_list = NEXT_FREE(node);
    #if DEBUG || DEBUG_FREE_LIST
    printf("FREE LIST -> %p\n", HDRP(free_list));
    #endif
  }
  if (NEXT_FREE(node)) PREV_FREE(NEXT_FREE(node)) = PREV_FREE(node);
  #if DEBUG || DEBUG_FREE_LIST
  printf("SET PREV: %p -> %p\n", HDRP(node->next), HDRP(node->prev));
  #endif

  #if DEBUG || DEBUG_FREE_LIST
  // printf("================= /REMOVE FREE LIST ===============\n");
  #endif
}

void add_to_free_list(list_node *node)
{
  #if DEBUG || DEBUG_FREE_LIST
  // printf("\n================= ADD FREE LIST ===============\n");
  printf("ADD FREE LIST: %p\n", HDRP(node));
  #endif
  if (free_list != NULL)
  {
    ((list_node*)free_list)->prev = node;
    #if DEBUG || DEBUG_FREE_LIST
    printf("SET NEXT (ADD): %p -> %p\n", HDRP(node), HDRP(free_list));
    #endif
  }

  node->next = free_list;
  node->prev = NULL;

  free_list = node;
  #if DEBUG || DEBUG_FREE_LIST
  printf("FREE LIST -> %p\n", HDRP(free_list));
  // printf("================= /ADD FREE LIST ===============\n");
  #endif
}

void set_allocated(void *bp, size_t size)
{
  remove_from_free_list(bp);

  size_t extra_size = GET_SIZE(HDRP(bp)) - size;
  if (extra_size > ALIGN(1 + BLOCK_OVERHEAD))
  {
    GET_SIZE(HDRP(bp)) = size;
    GET_SIZE(FTRP(bp)) = size;

    GET_SIZE(HDRP(NEXT_BLKP(bp))) = extra_size;
    GET_SIZE(FTRP(NEXT_BLKP(bp))) = extra_size;
    GET_ALLOC(HDRP(NEXT_BLKP(bp))) = 0;

    add_to_free_list((list_node *)NEXT_BLKP(bp));

    #if DEBUG || DEBUG_MALLOC || DEBUG_ASSERTS
    if (GET_SIZE(HDRP(NEXT_BLKP(bp))) != extra_size)
    {
      printf("INVALID REMAINING SIZE. GOT: %zu, EXPECTED: %zu\n", BLOCK_SIZE(GET_SIZE(HDRP(NEXT_BLKP(bp)))), BLOCK_SIZE(extra_size));
      exit(0);
    }
    #endif
  }

  #if DEBUG || DEBUG_MALLOC || DEBUG_ASSERTS
  if (size < BLOCK_OVERHEAD || BLOCK_SIZE(GET_SIZE(HDRP(bp))) < 2)
  {
    printf("Tried to allocate something too small.\n");
    exit(0);
  }
  #endif

  #if DEBUG || DEBUG_MALLOC
  printf("ALLOCATED: %zu, AT: %p\n", BLOCK_SIZE(GET_SIZE(HDRP(bp))), HDRP(bp));
  printf("REMAINING: %zu, AT: %p\n", BLOCK_SIZE(GET_SIZE(HDRP(NEXT_BLKP(bp)))), HDRP(NEXT_BLKP(bp)));
  #endif

  GET_ALLOC(HDRP(bp)) = 1;
}

void *create_page(size_t size)
{
  size_t new_size = NEW_PAGE_SIZE(size);
  void *new_page = mem_map(new_size);

  // Failed to get a new page.
  if (new_page == NULL) return NULL;

  NEXT_PAGE(new_page) = NULL;
  PREV_PAGE(new_page) = NULL;

  void *first_bp = FIRST_BLKP(new_page);
  add_to_free_list(first_bp);

  GET_SIZE(HDRP(first_bp)) = AVAILABLE_SIZE(new_size);
  GET_SIZE(FTRP(first_bp)) = AVAILABLE_SIZE(new_size);
  GET_ALLOC(HDRP(first_bp)) = 0;

  // Set the terminator block size.
  GET_SIZE(HDRP(NEXT_BLKP(first_bp))) = 0;
  GET_ALLOC(HDRP(NEXT_BLKP(first_bp))) = 1;

  #if DEBUG || DEBUG_CREATE_PAGE
  printf("NEW PAGE: %p, TOTAL BLOCKS: %zu, AVAIL BLOCKS: %zu, START: %p, TERM: %p\n", new_page, BLOCK_SIZE(NEW_PAGE_SIZE(size)), BLOCK_SIZE(AVAILABLE_SIZE(new_size)), HDRP(FIRST_BLKP(new_page)),  HDRP(NEXT_BLKP(FIRST_BLKP(new_page))));
  if (AVAILABLE_SIZE(new_size) != ALIGN(AVAILABLE_SIZE(new_size)))
  {
    printf("Size is not a multiple of: %d\n", ALIGNMENT);
  }
  #endif

  // Prolog block
  set_allocated(first_bp, ALIGN(sizeof(list_node) + BLOCK_OVERHEAD));

  return new_page;
}

void *find_available_block(size_t size)
{
  list_node *node = free_list;
  while (node != NULL)
  {
    if (!GET_ALLOC(HDRP(node)) && GET_SIZE(HDRP(node)) >= size)
    {
      #if DEBUG || DEBUG_FIND_AVAILABLE
      printf("AVAILABLE BLOCK: %p, %zu\n", HDRP(node), BLOCK_SIZE(GET_SIZE(HDRP(node))));
      #endif
      return node;
    }
    node = node->next;
  }
  return NULL;
}

void *last_page()
{
  void *current_page = first_page;
  while (NEXT_PAGE(current_page) != NULL)
  {
    current_page = NEXT_PAGE(current_page);
  }
  return current_page;
}

/*
 * mm_malloc - Allocate a block by using bytes from first_bp,
 *     grabbing a new page if necessary.
 */
void *mm_malloc(size_t size)
{
  #if DEBUG || DEBUG_MALLOC
  printf("\n================= MALLOC ===============\n");
  #endif

  // TODO: Use compact header/footer.
  // int need_size = max(size, sizeof(list_node));
  // int new_size = ALIGN(need_size + BLOCK_OVERHEAD);
  int need_size = MAX(size, sizeof(list_node));
  int new_size = ALIGN(need_size + BLOCK_OVERHEAD);

  #if DEBUG || DEBUG_MALLOC
  printf("WANT: %d\n", BLOCK_SIZE(new_size));
  #endif

  if (free_list != NULL)
  {
    void *bp = find_available_block(new_size);
    if (bp != NULL)
    {
      set_allocated(bp, new_size);

      #if DEBUG || DEBUG_MALLOC
      printf("================= /MALLOC ===============\n");
      #endif

      return bp;
    }
  }
  void *new_page = create_page(new_size);
  if (first_page != NULL)
  {
    void *last = last_page();
    NEXT_PAGE(last) = new_page;
    PREV_PAGE(new_page) = last;
  }
  else
  {
    first_page = new_page;
  }

  // Skip the prolog block.
  void *new_bp = free_list;
  set_allocated(new_bp, new_size);

  #if DEBUG || DEBUG_MALLOC
  printf("================= /MALLOC ===============\n");
  #endif

  return new_bp;
}

void empty_page()
{
  #if DEBUG || DEBUG_PAGE_REMOVE
  printf("\n================= EMPTY PAGE ===============\n");
  #endif

  void *current_page = NEXT_PAGE(first_page);
  while (current_page != NULL)
  {
    void *first_bp = NEXT_BLKP(FIRST_BLKP(current_page));

    // IF our next block is the terminator block and the first block after the prolog block is free.
    if (GET_ALLOC(HDRP(first_bp)) == 0 && GET_SIZE(HDRP(NEXT_BLKP(first_bp))) == 0)
    {
      remove_from_free_list(first_bp);

      if (current_page == first_page)
      {
        first_page = NEXT_PAGE(current_page);
      }
      if (PREV_PAGE(current_page) != NULL)
      {
        NEXT_PAGE(PREV_PAGE(current_page)) = NEXT_PAGE(current_page);
      }
      if (NEXT_PAGE(current_page) != NULL)
      {
        PREV_PAGE(NEXT_PAGE(current_page)) = PREV_PAGE(current_page);
      }

      void *remove_page = current_page;
      current_page = NEXT_PAGE(remove_page);

      #if DEBUG || DEBUG_PAGE_REMOVE
      printf("REMOVED EMPTY PAGE AT: %p, BLOCKS: %zu\n", remove_page, BLOCK_SIZE(PAGE_ALIGN(GET_SIZE(HDRP(first_bp)))));
      #endif

      mem_unmap(remove_page, PAGE_ALIGN(GET_SIZE(HDRP(first_bp))));
    }
    else
    {
      current_page = NEXT_PAGE(current_page);
    }
  }
  #if DEBUG || DEBUG_PAGE_REMOVE
  printf("================= /EMPTY PAGE ===============\n");
  #endif
}

void *coalesce(void *bp)
{
  size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(bp)));
  size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
  size_t size = GET_SIZE(HDRP(bp));

  #if DEBUG || DEBUG_COALESCE
  printf("\n================= COALESCE ===============\n");

  printf("PREV BEFORE %p, alloc: %d, size: %zu\n", HDRP(PREV_BLKP(bp)), GET_ALLOC(HDRP(PREV_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(PREV_BLKP(bp)))));
  printf("CURR BEFORE %p, alloc: %d, size: %zu\n", HDRP(bp),            GET_ALLOC(HDRP(bp)),            BLOCK_SIZE(GET_SIZE(HDRP(bp))));
  printf("NEXT BEFORE %p, alloc: %d, size: %zu\n", HDRP(NEXT_BLKP(bp)), GET_ALLOC(HDRP(NEXT_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(NEXT_BLKP(bp)))));
  #endif

  if (prev_alloc && next_alloc)  /* Case 1 */
  {
    add_to_free_list(bp);
  }
  else if (prev_alloc && !next_alloc)   /* Case 2 */
  {
    remove_from_free_list((list_node *)NEXT_BLKP(bp));
    add_to_free_list(bp);

    size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
    GET_SIZE(HDRP(bp)) = size;
    GET_SIZE(FTRP(bp)) = size;
  }
  else if (!prev_alloc && next_alloc) /* Case 3 */
  {
    size += GET_SIZE(HDRP(PREV_BLKP(bp)));
    GET_SIZE(FTRP(bp)) = size;
    GET_SIZE(HDRP(PREV_BLKP(bp))) = size;
    bp = PREV_BLKP(bp);
  }
  else /* Case 4 */
  {
    remove_from_free_list((list_node *)NEXT_BLKP(bp));

    size += (GET_SIZE(HDRP(PREV_BLKP(bp)))
             + GET_SIZE(HDRP(NEXT_BLKP(bp))));
    GET_SIZE(HDRP(PREV_BLKP(bp))) = size;
    GET_SIZE(FTRP(NEXT_BLKP(bp))) = size;
    bp = PREV_BLKP(bp);

  }

  #if DEBUG || DEBUG_COALESCE

  printf("PREV AFTER %p, alloc: %d, size: %zu\n", HDRP(PREV_BLKP(bp)), GET_ALLOC(HDRP(PREV_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(PREV_BLKP(bp)))));
  printf("CURR AFTER %p, alloc: %d, size: %zu\n", HDRP(bp),            GET_ALLOC(HDRP(bp)),            BLOCK_SIZE(GET_SIZE(HDRP(bp))));
  printf("NEXT AFTER %p, alloc: %d, size: %zu\n", HDRP(NEXT_BLKP(bp)), GET_ALLOC(HDRP(NEXT_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(NEXT_BLKP(bp)))));

  if (GET_SIZE(HDRP(bp)) != GET_SIZE(FTRP(bp)))
  {
    printf("DEBUG_COALESCE: %p header and footer size don't match. Header: %zu, Footer: %zu\n", HDRP(bp), GET_SIZE(HDRP(bp)), GET_SIZE(FTRP(bp)));
  }

  printf("================= /COALESCE ===============\n");
  #endif
  return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
  #if DEBUG || DEBUG_FREE
  printf("\n================= FREE ===============\n");
  printf("FREE: %p\n", HDRP(ptr));
  #endif

  GET_ALLOC(HDRP(ptr)) = 0;
  coalesce(ptr);
  empty_page();

  #if DEBUG || DEBUG_FREE
  printf("================= /FREE ===============\n");
  #endif
}

/*
 * check_coalesce - Returns 1 if everything is coalesce properly.
 *
 */
int check_coalesce(void *bp)
{
  #if DEBUG || DEBUG_MM_CHECK_VERBOSE
  printf("PREV %p, alloc: %d, size: %zu\n", HDRP(PREV_BLKP(bp)), GET_ALLOC(HDRP(PREV_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(PREV_BLKP(bp)))));
  printf("CURR %p, alloc: %d, size: %zu\n", HDRP(bp),            GET_ALLOC(HDRP(bp)),            BLOCK_SIZE(GET_SIZE(HDRP(bp))));
  printf("NEXT %p, alloc: %d, size: %zu\n", HDRP(NEXT_BLKP(bp)), GET_ALLOC(HDRP(NEXT_BLKP(bp))), BLOCK_SIZE(GET_SIZE(HDRP(NEXT_BLKP(bp)))));
  #endif

  size_t curr_alloc = GET_ALLOC(HDRP(bp));
  size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(bp)));
  size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));

  return curr_alloc || (prev_alloc && next_alloc);
}

/*
 * mm_check - Check whether freeing the given `p`, which means that
 *            calling mm_free(p) leaves the heap in an ok state.
 */
int mm_can_free(void *p)
{
  if (!ptr_is_mapped(p, BLOCK_OVERHEAD)) return 0;
  if (!ptr_is_mapped(p, GET_SIZE(HDRP(p)))) return 0;
  if (GET_SIZE(HDRP(p)) == 0) return 0;
  if (GET_SIZE(HDRP(p)) != GET_SIZE(FTRP(p))) return 0;
  // printf("CAN FREE: %p, %d\n", p, GET_ALLOC(HDRP(p)));
  return GET_ALLOC(HDRP(p));
}

/*
 * mm_check - Check whether the heap is ok, so that mm_malloc()
 *            and proper mm_free() calls won't crash.
 */
int mm_check()
{
  #if DEBUG
  printf("\n================= CHECK ===============\n");
  #endif

  void *current_page = first_page;

  while (current_page != NULL)
  {
    if (!ptr_is_mapped(current_page, sizeof(page_node)))
    {
      return 0;
    }

    // Check correctness on the prolog block.
    if (GET_SIZE(HDRP(FIRST_BLKP(current_page))) != ALIGN(BLOCK_OVERHEAD + sizeof(list_node)) || GET_ALLOC(HDRP(FIRST_BLKP(current_page))) != 1)
    {
      #if DEBUG || DEBUG_MM_CHECK
      printf("First block on page %p is not correct. PTR: %p, ALLOC: %d, SIZE: %zu\n", current_page, HDRP(FIRST_BLKP(current_page)), GET_ALLOC(HDRP(FIRST_BLKP(current_page))), BLOCK_SIZE(GET_SIZE(HDRP(FIRST_BLKP(current_page)))));
      #endif
      return 0;
    }

    void *bp = NEXT_BLKP(FIRST_BLKP(current_page));
    while (GET_SIZE(HDRP(bp)) != 0)
    {
      if (!ptr_is_mapped(bp, BLOCK_OVERHEAD)) return 0;
      if (!ptr_is_mapped(bp, GET_SIZE(HDRP(bp)))) return 0;
      if (GET_SIZE(HDRP(bp)) == 0) return 0;
      if (GET_SIZE(HDRP(bp)) != GET_SIZE(FTRP(bp))) return 0;
      if (GET_ALLOC(HDRP(bp)) != 0 && GET_ALLOC(HDRP(bp)) != 1) return 0;
      bp = NEXT_BLKP(bp);
    }

    // Check our terminator block for correctness.
    if (GET_ALLOC(HDRP(bp)) != 1)
    {
      #if DEBUG || DEBUG_MM_CHECK
      printf("Terminator block is incorrect. PTR: %p, SIZE: %zu, ALLOC: %d\n", bp, GET_SIZE(HDRP(bp)), GET_ALLOC(HDRP(bp)));
      #endif
      return 0;
    }

    current_page = NEXT_PAGE(current_page);
  }


  list_node *node = free_list;
  if (node != NULL && PREV_FREE(node) != NULL)
  {
    #if DEBUG || DEBUG_MM_CHECK
    printf("The previous of the start of the free list is not NULL. %p\n", HDRP(node));
    #endif
    return 0;
  }
  while (node != NULL)
  {
    // printf("CAN FREE: %p, %d\n", p, GET_ALLOC(HDRP(p)));
    if (!ptr_is_mapped(node, BLOCK_OVERHEAD)) return 0;
    if (!ptr_is_mapped(node, GET_SIZE(HDRP(node)))) return 0;
    if (GET_SIZE(HDRP(node)) == 0) return 0;
    if (GET_SIZE(HDRP(node)) != GET_SIZE(FTRP(node))) return 0;
    if (GET_ALLOC(HDRP(node))) return 0;
    node = node->next;
  }

  #if DEBUG
  printf("\n================= /CHECK ===============\n");
  #endif

  return 1;
}

/*
 * mm_init - initialize the malloc package.
 * The mm_init function will be called once per benchmark run,
 * so it can be called multiple times in the same run of mdriver.
 * Your mm_init function should reset your implementation
 * to its initial state in each case.
 */
int mm_init(void)
{
  free_list = NULL;
  first_page = NULL;
  return 0;
}
