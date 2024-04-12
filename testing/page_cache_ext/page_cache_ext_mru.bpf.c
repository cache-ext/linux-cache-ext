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
struct map_value {
	struct cache_ext_list __kptr_untrusted *mru_list;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} mru_list_map SEC(".maps");

inline struct cache_ext_list *get_mru_list()
{
	int zero = 0;
	struct map_value *v = bpf_map_lookup_elem(&mru_list_map, &zero);
	if (!v) {
		return NULL;
	}
	return v->mru_list;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the mru_init hook! :D\n");
	int zero = 0;
	struct cache_ext_list *mru_list;
	struct map_value map_value = {}, *map_value_ptr;
	bpf_map_update_elem(&mru_list_map, &zero, &map_value, BPF_NOEXIST);
	map_value_ptr = bpf_map_lookup_elem(&mru_list_map, &zero);
	if (!map_value_ptr) {
		bpf_printk("page_cache_ext: Failed to lookup mru_list_map\n");
		return -1;
	}
	if (map_value_ptr->mru_list) {
		bpf_printk("page_cache_ext: map_value_ptr->mru_list already exists\n");
		return -1;
	}
	mru_list = cache_ext_ds_registry_new_list(memcg);
	if (!mru_list) {
		bpf_printk("page_cache_ext: Failed to create mru_list\n");
		return -1;
	}
	bpf_kptr_xchg(&map_value_ptr->mru_list, mru_list);
	return 0;
}

void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the mru_folio_accessed hook! :D\n");
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the mru_folio_evicted hook! :D\n");
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the mru_folio_added hook! :D\n");
}

void BPF_STRUCT_OPS(mru_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx)
{
	dbg_printk("page_cache_ext: Hi from the mru_evict_folios hook! :D\n");
}

SEC(".struct_ops.link")
struct page_cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
	.folio_evicted = (void *)mru_folio_evicted,
	.folio_added = (void *)mru_folio_added,
};