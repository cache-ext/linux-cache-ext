#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT		2  /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX	(9223372036854775807LL)

// Set from userspace. In terms of number of pages.
const volatile size_t cache_size;

struct folio_metadata {
	s64 freq;
};

struct ghost_entry {
	u64 address_space;
	u64 offset;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_entry);
	__type(value, u8);
	__uint(max_entries, 393216);  // (2GiB / 4KiB) * 0.75, adjust as necessary (TODO)
	__uint(map_flags, BPF_F_NO_COMMON_LRU);  // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

static u64 main_list;
static u64 small_list;

/*
 * This is an approximate value based on what we choose to evict, not what is
 * actually evicted.
 */
static u64 small_list_size = 0;

static inline bool is_folio_relevant(struct folio *folio) {
	if (!folio || !folio->mapping || !folio->mapping->host)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline struct folio_metadata *get_folio_metadata(struct folio *folio) {
	u64 key = (u64)folio;
	return bpf_map_lookup_elem(&folio_metadata_map, &key);
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline bool folio_in_ghost(struct folio *folio) {
	struct ghost_entry key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};
	// TODO: handle non-ENOENT errors
	return bpf_map_delete_elem(&ghost_map, &key) != -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3fifo_init, struct mem_cgroup *memcg)
{
	main_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (main_list == 0) {
		bpf_printk("cache_ext: init: Failed to create main_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

	small_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (small_list == 0) {
		bpf_printk("cache_ext: init: Failed to create small_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created small_list: %llu\n", small_list);

	return 0;
}

static s64 bpf_s3fifo_score_fn(struct cache_ext_list_node *a) {
	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;

	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	struct folio_metadata *data = get_folio_metadata(a->folio);
	if (!data) {
		bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
		return INT64_MAX;
	}

	s64 freq = __sync_sub_and_fetch(&data->freq, 1);
	if (freq < 0)
		data->freq = 0;

	return freq;
}

static void evict_main(struct page_cache_ext_eviction_ctx *eviction_ctx,
		       struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 0, move to tail, freq--.
	 * Otherwise, evict. (When evicting, move to tail in the meantime).
	 */

	struct sampling_options opts = {
		.sample_size = 32,
	};

	if (bpf_cache_ext_list_sample(memcg, main_list, bpf_s3fifo_score_fn, &opts, eviction_ctx)) {
		bpf_printk("cache_ext: evict: Failed to sample main_list\n");
		return;
	}
}

static void evict_small(struct page_cache_ext_eviction_ctx *eviction_ctx,
			struct mem_cgroup *memcg)
{
	/*
	 * Iterate from head. If freq > 1, move to main list, otherwise evict.
	 * (When evicting, move to tail in the meantime).
	 * 
	 * Use the iterate interface.
	 */
}

void BPF_STRUCT_OPS(s3fifo_evict_folios, struct page_cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	if (small_list_size >= cache_size / 10)
		evict_small(eviction_ctx, memcg);
	else
		evict_main(eviction_ctx, memcg);
}

void BPF_STRUCT_OPS(s3fifo_folio_accessed, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	struct folio_metadata *data = get_folio_metadata(folio);
	if (!data) {
		bpf_printk("cache_ext: accessed: Failed to get metadata\n");
		return;
	}

	// Cap frequency at 3
	if (__sync_add_and_fetch(&data->freq, 1) >= 3)
		data->freq = 3;
}

void BPF_STRUCT_OPS(s3fifo_folio_evicted, struct folio *folio) {
	u64 key = (u64)folio;
	u8 ghost_val = 0;
	
	if (bpf_cache_ext_list_del(folio)) {
		bpf_printk("page_cache_ext: Failed to delete folio from sampling_list\n");
		return;
	}

	struct ghost_entry ghost_key = {
		.address_space = (u64)folio->mapping->host,
		.offset = folio->index,
	};

	// Don't return early, we want to delete the folio metadata regardless
	if (bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY))
		bpf_printk("cache_ext: evicted: Failed to add to ghost_map\n");

	if (bpf_map_delete_elem(&folio_metadata_map, &key))
		bpf_printk("cache_ext: evicted: Failed to delete metadata\n");
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3fifo_folio_added, struct folio *folio) {
	if (!is_folio_relevant(folio))
		return;

	u64 key = (u64)folio;
	struct folio_metadata new_meta = {
		.freq = 0,
	};

	u64 list_to_add = folio_in_ghost(folio) ? main_list : small_list;

	if (bpf_cache_ext_list_add_tail(list_to_add, folio)) {
		// TODO: add back to ghost_map?
		bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
		return;
	}

	if (bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY)) {
		// TODO: add back to ghost_map? + error check delete call?
		bpf_cache_ext_list_del(folio);
		bpf_printk("cache_ext: added: Failed to create folio metadata\n");
		return;
	}
}

SEC(".struct_ops.link")
struct page_cache_ext_ops s3fifo_ops = {
	.init = (void *)s3fifo_init,
	.evict_folios = (void *)s3fifo_evict_folios,
	.folio_accessed = (void *)s3fifo_folio_accessed,
	.folio_evicted = (void *)s3fifo_folio_evicted,
	.folio_added = (void *)s3fifo_folio_added,
};
