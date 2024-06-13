#ifndef _CACHE_EXT_LIB_BPF_H
#define _CACHE_EXT_LIB_BPF_H 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CACHE_EXT_CONTINUE_ITER 0
#define CACHE_EXT_STOP_ITER 1
#define CACHE_EXT_EVICT_NODE 2
#define CACHE_EXT_MAX_ITER_REACHED 8
#define CACHE_EXT_EVICT_ARRAY_FILLED 9

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct page_cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      bool(less_fn)(struct cache_ext_list_node *a,
				  		struct cache_ext_list_node *b),
				  struct sampling_options *opts,
				  struct page_cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;

#define BITS_PER_LONG 64
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#define bitop(op, nr, addr)						\
	((__builtin_constant_p(nr) &&					\
	  __builtin_constant_p((uintptr_t)(addr) != (uintptr_t)NULL) &&	\
	  (uintptr_t)(addr) != (uintptr_t)NULL &&			\
	  __builtin_constant_p(*(const unsigned long *)(addr))) ?	\
	 const##op(nr, addr) : op(nr, addr))

#define test_bit(nr, addr)		bitop(_test_bit, nr, addr)
#define _test_bit

static __always_inline bool
generic_test_bit(unsigned long nr, const volatile unsigned long *addr)
{
	/*
	 * Unlike the bitops with the '__' prefix above, this one *is* atomic,
	 * so `volatile` must always stay here with no cast-aways. See
	 * `Documentation/atomic_bitops.txt` for the details.
	 */
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline unsigned long *folio_flags(struct folio *folio, unsigned n)
{
	struct page *page = &folio->page;
	return &page[n].flags;
}


static inline bool folio_test_uptodate(struct folio *folio)
{
	bool ret = generic_test_bit(PG_uptodate, folio_flags(folio, 0));

	return ret;
}

static inline bool folio_test_lru(struct folio *folio)
{
	bool ret = generic_test_bit(PG_lru, folio_flags(folio, 0));

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Generic Utils //////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

static inline u32 bpf_get_random(u32 min, u32 max) {
	// TODO: This has modulo bias, not sure if we should address it.
	u32 temp;
	if (min > max) {
		temp = min;
		min = max;
		max = temp;
	}
	return min + bpf_get_prandom_u32() % (max - min + 1);
}

#endif /* _CACHE_EXT_LIB_BPF_H */