#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "page_cache_ext_mru.bpf.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

#define DEBUG

#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

/*
 * Maps
 */

// Map to store the linked list pointer
// Single key-value
// This is not working. Maybe we need to register destructors for cache_ext_list?

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} mru_list_map SEC(".maps");

inline u64 get_mru_list()
{
	int zero = 0;
	u64 *mru_list;
	mru_list = bpf_map_lookup_elem(&mru_list_map, &zero);
	if (!mru_list) {
		return 0;
	}
	return *mru_list;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the mru_init hook! :D\n");
	int zero = 0;
	u64 mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (mru_list == 0) {
		bpf_printk("page_cache_ext: Failed to create mru_list\n");
		return -1;
	}
	bpf_printk("page_cache_ext: Created mru_list: %llu\n", mru_list);
	bpf_map_update_elem(&mru_list_map, &zero, &mru_list, BPF_ANY);
	return 0;
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the mru_folio_added hook! :D\n");
	u64 mru_list = get_mru_list();
	if (mru_list == 0) {
		bpf_printk("page_cache_ext: Failed to get mru_list\n");
		return;
	}
	int ret = bpf_cache_ext_list_add(mru_list, folio);
	if (ret != 0) {
		bpf_printk("page_cache_ext: Failed to add folio to mru_list\n");
		return;
	}
	bpf_printk("page_cache_ext: Added folio to mru_list\n");
}

void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
	int ret;
	u64 mru_list;
	dbg_printk("page_cache_ext: Hi from the mru_folio_accessed hook! :D\n");

	ret = bpf_cache_ext_list_del(folio);
	if (ret != 0) {
		bpf_printk(
			"page_cache_ext: Failed to delete folio from mru_list\n");
		return;
	}
	mru_list = get_mru_list();
	if (mru_list == 0) {
		bpf_printk("page_cache_ext: Failed to get mru_list\n");
		return;
	}
	ret = bpf_cache_ext_list_add_tail(mru_list, folio);
	if (ret != 0) {
		bpf_printk("page_cache_ext: Failed to add folio to mru_list\n");
		return;
	}
	bpf_printk("page_cache_ext: Moved folio to mru_list tail\n");
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the mru_folio_evicted hook! :D\n");
	u64 mru_list = get_mru_list();
	if (mru_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get mru_list on evicted path\n");
		return;
	}
	bpf_cache_ext_list_del(folio);
}

static int iterate_mru(u64 list, struct cache_ext_list_node *node,
		       struct page_cache_ext_eviction_ctx *ctx)
{
	if (ctx->request_nr_folios_to_evict - ctx->nr_folios_to_evict <= 0) {
		return CACHE_EXT_STOP_ITER;
	}
	ctx->folios_to_evict[ctx->nr_folios_to_evict - 1] = node->folio;
	ctx->nr_folios_to_evict++;
	return 0;
}

void BPF_STRUCT_OPS(mru_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the mru_evict_folios hook! :D\n");
	u64 mru_list = get_mru_list();
	if (mru_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get mru_list on eviction path\n");
		return;
	}
	int ret = bpf_cache_ext_list_iterate(memcg, mru_list, iterate_mru,
					     eviction_ctx);
}

SEC(".struct_ops.link")
struct page_cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
	.folio_evicted = (void *)mru_folio_evicted,
	.folio_added = (void *)mru_folio_added,
};