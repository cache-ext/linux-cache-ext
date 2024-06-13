#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

/* Test inode */
__u64 TEST_INODE_INO = -1;

inline bool is_test_inode(struct folio *folio)
{
	if (folio->mapping == NULL) {
		return false;
	}
	if (folio->mapping->host == NULL) {
		return false;
	}
	return folio->mapping->host->i_ino == TEST_INODE_INO;
}

/*
 * Maps
 */

#define NUM_BUCKETS 10
#define MAX_PAGES (1(UL) << 20)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, NUM_BUCKETS);
} lfu_list_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, MAX_PAGES);
}

inline u64
get_lfu_list()
{
	int zero = 0;
	u64 *lfu_list;
	lfu_list = bpf_map_lookup_elem(&lfu_list_map, &zero);
	if (!lfu_list) {
		return 0;
	}
	return *lfu_list;
}

static inline int access_to_idx(int access)
{
	for (int i = 0; i < NUM_BUCKETS; i++) {
		access = access / 2;
		if (access == 0) {
			return i;
		}
	}
	return NUM_BUCKETS - 1;
}

// SEC("struct_ops.s/lfu_init")
// s32 lfu_init(struct mem_cgroup *memcg)
s32 BPF_STRUCT_OPS_SLEEPABLE(lfu_init, struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the lfu_init hook! :D\n");
	for (int i = 0; i < NUM_BUCKETS; i++) {
		u64 lfu_list = bpf_cache_ext_ds_registry_new_list(memcg);
		if (lfu_list == 0) {
			bpf_printk(
				"page_cache_ext: Failed to create lfu_list\n");
			return -1;
		}
		bpf_map_update_elem(&lfu_list_map, &i, &lfu_list, BPF_ANY);
	}
	bpf_printk("page_cache_ext: Created lfu lists\n");
}

void BPF_STRUCT_OPS(lfu_folio_added, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the lfu_folio_added hook! :D\n");
	if (!is_test_inode(folio)) {
		return;
	}
	u64 lfu_list = get_lfu_list();
	if (lfu_list == 0) {
		bpf_printk("page_cache_ext: Failed to get lfu_list\n");
		return;
	}
	int ret = bpf_cache_ext_list_add(lfu_list, folio);
	if (ret != 0) {
		bpf_printk("page_cache_ext: Failed to add folio to lfu_list\n");
		return;
	}
	dbg_printk("page_cache_ext: Added folio to lfu_list\n");
}

void BPF_STRUCT_OPS(lfu_folio_accessed, struct folio *folio)
{
	int ret;
	u64 lfu_list;
	dbg_printk("page_cache_ext: Hi from the lfu_folio_accessed hook! :D\n");

	if (!is_test_inode(folio)) {
		return;
	}

	ret = bpf_cache_ext_list_del(folio);
	if (ret != 0) {
		bpf_printk(
			"page_cache_ext: Failed to delete folio from lfu_list\n");
		return;
	}
	lfu_list = get_lfu_list();
	if (lfu_list == 0) {
		bpf_printk("page_cache_ext: Failed to get lfu_list\n");
		return;
	}
	ret = bpf_cache_ext_list_add(lfu_list, folio);
	if (ret != 0) {
		bpf_printk("page_cache_ext: Failed to add folio to lfu_list\n");
		return;
	}
	dbg_printk("page_cache_ext: Moved folio to lfu_list tail\n");
}

void BPF_STRUCT_OPS(lfu_folio_evicted, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the lfu_folio_evicted hook! :D\n");
	u64 lfu_list = get_lfu_list();
	if (lfu_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get lfu_list on evicted path\n");
		return;
	}
	bpf_cache_ext_list_del(folio);
}

static int iterate_lfu(int idx, struct cache_ext_list_node *node)
{
	// TODO: Implement the folio_mark_uptodate function to make sure the folios
	// are valid to be evicted.
	// TODO: Also check the PG_lru flag.

	// bpf_printk("cache_ext: Iterate idx %d\n", idx);
	if (!folio_test_uptodate(node->folio) || !folio_test_lru(node->folio))
		bpf_printk("cache_ext: Iterate idx %d\n", idx);
	if ((idx < 30) && (!folio_test_uptodate(node->folio) ||
			   !folio_test_lru(node->folio))) {
		return CACHE_EXT_CONTINUE_ITER;
	}
	return CACHE_EXT_EVICT_NODE;
	// return CACHE_EXT_STOP_ITER;
	// bpf_printk("cache_ext: Iterate idx %d\n", idx);
	// if (idx < 30) return 0;
	// ctx->folios_to_evict[0] = node->folio;
	// ctx->nr_folios_to_evict = 1;
	// return CACHE_EXT_STOP_ITER;
}

// SEC("struct_ops/lfu_evict_folios")
// void lfu_evict_folios(struct page_cache_ext_eviction_ctx *eviction_ctx,
// 		      struct mem_cgroup *memcg)
void BPF_STRUCT_OPS(lfu_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	// dbg_printk("page_cache_ext: Hi from the lfu_evict_folios hook! :D\n");
	// bpf_printk("page_cache_ext: Evicting pages!\n");
	u64 lfu_list = get_lfu_list();
	if (lfu_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get lfu_list on eviction path\n");
		return;
	}
	int ret = bpf_cache_ext_list_iterate(memcg, lfu_list, iterate_lfu,
					     eviction_ctx);
}

SEC(".struct_ops.link")
struct page_cache_ext_ops lfu_ops = {
	.init = (void *)lfu_init,
	.evict_folios = (void *)lfu_evict_folios,
	.folio_accessed = (void *)lfu_folio_accessed,
	.folio_evicted = (void *)lfu_folio_evicted,
	.folio_added = (void *)lfu_folio_added,
};