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

/*
 * Maps
 */

#define MAX_PAGES (1 << 20)

struct folio_metadata {
	u64 accesses;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct folio_metadata);
	__uint(max_entries, MAX_PAGES);
} folio_metadata_map SEC(".maps");

/* Counter for list size */
__u64 list_size = 0;

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

// Maps from folio to metadata
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 1);
} sampling_list_map SEC(".maps");

inline u64 get_sampling_list()
{
	int zero = 0;
	u64 *sampling_list;
	sampling_list = bpf_map_lookup_elem(&sampling_list_map, &zero);
	if (!sampling_list) {
		return 0;
	}
	return *sampling_list;
}

// SEC("struct_ops.s/sampling_init")
s32 BPF_STRUCT_OPS_SLEEPABLE(sampling_init, struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the sampling_init hook! :D\n");
	int zero = 0;
	u64 sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("page_cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("page_cache_ext: Created sampling_list: %llu\n",
		   sampling_list);
	bpf_map_update_elem(&sampling_list_map, &zero, &sampling_list, BPF_ANY);
	return 0;
}

void BPF_STRUCT_OPS(sampling_folio_added, struct folio *folio)
{
	dbg_printk(
		"page_cache_ext: Hi from the sampling_folio_added hook! :D\n");
	if (!is_test_inode(folio)) {
		return;
	}
	u64 sampling_list = get_sampling_list();
	if (sampling_list == 0) {
		bpf_printk("page_cache_ext: Failed to get sampling_list\n");
		return;
	}
	int ret = 0;
	// Add the folio to the head with probability 1 / (list_size + 1)

	u32 die_roll =
		bpf_get_random(1, __sync_fetch_and_add(&list_size, 0) + 1);
	if (die_roll == 1) {
		ret = bpf_cache_ext_list_add(sampling_list, folio);
	} else {
		ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	}
	if (ret != 0) {
		bpf_printk(
			"page_cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
	__sync_fetch_and_add(&list_size, 1);
	dbg_printk("page_cache_ext: Added folio to sampling_list\n");
}

void BPF_STRUCT_OPS(sampling_folio_accessed, struct folio *folio)
{
	// TODO: Update folio metadata with other values we want to track
    struct folio_metadata *meta;
    u64 key = (u64)folio;
    meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
    if (!meta) {
        struct folio_metadata new_meta = {0};
        bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
        meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
        if (!meta) {
            bpf_printk("page_cache_ext: Failed to update folio metadata\n");
            return;
        }
    }
    __sync_fetch_and_add(&meta->accesses, 1);
}

void BPF_STRUCT_OPS(sampling_folio_evicted, struct folio *folio)
{
	dbg_printk(
		"page_cache_ext: Hi from the sampling_folio_evicted hook! :D\n");
	u64 sampling_list = get_sampling_list();
	if (sampling_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get sampling_list on evicted path\n");
		return;
	}
	bpf_cache_ext_list_del(folio);
	__sync_fetch_and_add(&list_size, -1);
	u64 key = (u64)folio;
    bpf_map_delete_elem(&folio_metadata_map, &key);
}

static bool bpf_less_fn(struct cache_ext_list_node *a, struct cache_ext_list_node *b) {
    struct folio_metadata *meta_a;
    struct folio_metadata *meta_b;
    u64 key_a = (u64)a->folio;
    u64 key_b = (u64)b->folio;
    meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
    meta_b = bpf_map_lookup_elem(&folio_metadata_map, &key_b);
    if (!meta_a || !meta_b) {
        return 0;
    }
    return meta_a->accesses < meta_b->accesses;
}

void BPF_STRUCT_OPS(sampling_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	dbg_printk("page_cache_ext: Hi from the sampling_evict_folios hook! :D\n");
	u64 sampling_list = get_sampling_list();
	if (sampling_list == 0) {
		bpf_printk(
			"page_cache_ext: Failed to get sampling_list on eviction path\n");
		return;
	}
    // TODO: What does the eviction interface look like for sampling?
    bpf_cache_ext_list_sample(
        memcg,
        sampling_list,
        bpf_less_fn,
        eviction_ctx->request_nr_folios_to_evict * 10,
        eviction_ctx->request_nr_folios_to_evict,
        eviction_ctx);
}

SEC(".struct_ops.link")
struct page_cache_ext_ops sampling_ops = {
	.init = (void *)sampling_init,
	.evict_folios = (void *)sampling_evict_folios,
	.folio_accessed = (void *)sampling_folio_accessed,
	.folio_evicted = (void *)sampling_folio_evicted,
	.folio_added = (void *)sampling_folio_added,
};