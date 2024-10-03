#ifndef _CACHE_EXT_LIB_BPF_H
#define _CACHE_EXT_LIB_BPF_H 1

#define U32_MAX		((u32)~0U)
#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Generic

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

// cache_ext BPF API

#define CACHE_EXT_CONTINUE_ITER 0
#define CACHE_EXT_STOP_ITER 1
#define CACHE_EXT_EVICT_NODE 2
#define CACHE_EXT_MAX_ITER_REACHED 8
#define CACHE_EXT_EVICT_ARRAY_FILLED 9

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_move_to_head(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_move_to_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct page_cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *a),
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

#define FOLIO_PF_ANY		0
#define pgoff_t unsigned long


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

static inline bool folio_test_dirty(struct folio *folio)
{
	bool ret = generic_test_bit(PG_dirty, folio_flags(folio, 0));

	return ret;
}

static inline bool folio_test_writeback(struct folio *folio)
{
	bool ret = generic_test_bit(PG_writeback, folio_flags(folio, 0));

	return ret;
}


static __always_inline bool folio_test_head(struct folio *folio)
{
	return generic_test_bit(PG_head, folio_flags(folio, FOLIO_PF_ANY));
}

static inline bool folio_test_large(struct folio *folio)
{
	return folio_test_head(folio);
}


static inline bool folio_test_hugetlb(struct folio *folio)
{
	return folio_test_large(folio) &&
		generic_test_bit(PG_hugetlb, folio_flags(folio, 1));
}

static inline loff_t i_size_read(const struct inode *inode)
{
	// IMPORTANT: This assumes a 64-bit kernel.
	// TODO: Don't compile if that's not the case.
	return inode->i_size;
}


/* from pagemap.h */
static inline pgoff_t folio_index(struct folio *folio)
{
	// TODO: Handle swapcache
	// if (unlikely(folio_test_swapcache(folio)))
	//         return swapcache_index(folio);
	return folio->index;
}


///////////////////////////////////////////////////////////////////////////////
// Generic Utils //////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// Generate a random number in [0, max).
static inline u32 bpf_get_random_unbiased(u32 max) {
	// XXX: Address modulo bias.
	if (max == 0) {
		return 0;
	}
	u32 max_divisible = U32_MAX - (U32_MAX % max);
	u32 max_retries = 10;
	u32 res;
	for (int i = 0; i < max_retries; i++) {
		res = bpf_get_prandom_u32();
		if (res < max_divisible) {
			return res % max;
		}
	}
	bpf_printk("bpf_get_random: max_retries reached\n");
	return res % max;
}

// Generate a random number in [0, max).
static inline u32 bpf_get_random_biased(u32 max) {
	// XXX: Address modulo bias.
	if (max == 0) {
		return 0;
	}
	return bpf_get_prandom_u32() % max;
}


///////////////////////////////////////////////////////////////////////////////
// Scan PIDs map //////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, bool);
    __uint(max_entries, 100);
} scan_pids SEC(".maps");

static inline bool is_scanning_pid() {
	// Get thread id
	__u64 pid = bpf_get_current_pid_tgid();
	pid = pid & 0xFFFFFFFF;
	// Check if pid is in scan_pids map
	u8 *ret = bpf_map_lookup_elem(&scan_pids, &pid);
	if (ret != NULL) {
		return true;
	}
	return false;
}

#endif /* _CACHE_EXT_LIB_BPF_H */