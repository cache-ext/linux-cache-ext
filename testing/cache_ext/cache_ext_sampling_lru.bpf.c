#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

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
	u64 last_access_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} sampling_list_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} is_first_eviction SEC(".maps");

#define MAX_STAT_NAME_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[MAX_STAT_NAME_LEN]);
	__type(value, s64);
	__uint(max_entries, 256);
} stats SEC(".maps");

/* App type for specific optimizations */
enum App {
	GENERIC,
	LEVELDB,
};

// Keys for stats
char STAT_SCAN_PAGES[MAX_STAT_NAME_LEN] = "scan_pages";
char STAT_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "total_pages";
char STAT_EVICTED_SCAN_PAGES[MAX_STAT_NAME_LEN] = "evicted_scan_pages";
char STAT_EVICTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "evicted_total_pages";

/* Counter for list size */
__u64 list_size = 0;
int APP_TYPE = LEVELDB;

#ifdef STATS_ENABLED
inline void update_stat(char (*stat_name)[MAX_STAT_NAME_LEN], s64 delta) {
	// bpf_printk("update_stat!\n");
	u64 *counter = bpf_map_lookup_elem(&stats, stat_name);
	if (!counter) {
		u64 zero = 0;
		bpf_map_update_elem(&stats, stat_name, &zero, BPF_NOEXIST);
		counter = bpf_map_lookup_elem(&stats, stat_name);
	}
	if (counter) {
		__sync_fetch_and_add(counter, delta);
	}
}
#else
inline void update_stat(char (*stat_name)[MAX_STAT_NAME_LEN], s64 delta) {}
#endif

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

inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio) {
		// bpf_printk("folio not relevant because it's null\n");
		return false;
	}
	if (folio->mapping == NULL) {
		// bpf_printk("folio not relevant because it's mapping is null\n");
		return false;
	}
	if (folio->mapping->host == NULL) {
		// bpf_printk("folio not relevant because it's host is null\n");
		return false;
	}
	bool res = inode_in_watchlist(folio->mapping->host->i_ino);
	// if (!res) {
	// 	bpf_printk("folio not relevant because it's inode is not in watchlist, inode %llu\n",
	// 		   folio->mapping->host->i_ino);

	// }
	return res;
}

// SEC("struct_ops.s/sampling_init")
s32 BPF_STRUCT_OPS_SLEEPABLE(sampling_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the sampling_init hook! :D\n");
	int zero = 0;
	u64 sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created sampling_list: %llu\n",
		   sampling_list);
	bpf_map_update_elem(&sampling_list_map, &zero, &sampling_list, BPF_ANY);
	return 0;
}

void BPF_STRUCT_OPS(sampling_folio_added, struct folio *folio)
{
	dbg_printk(
		"cache_ext: Hi from the sampling_folio_added hook! :D\n");
	if (!is_folio_relevant(folio)) {
		return;
	}
	u64 sampling_list = get_sampling_list();
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to get sampling_list\n");
		return;
	}
	int ret = bpf_cache_ext_list_add_tail(sampling_list, folio);
	if (ret != 0) {
		bpf_printk(
			"cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
	__sync_fetch_and_add(&list_size, 1);
	dbg_printk("cache_ext: Added folio to sampling_list\n");

	update_stat(&STAT_TOTAL_PAGES, 1);

	// Create folio metadata
	u64 key = (u64)folio;
	struct folio_metadata new_meta = { .last_access_time = bpf_ktime_get_ns() };
	bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
}

void BPF_STRUCT_OPS(sampling_folio_accessed, struct folio *folio)
{
	if (!is_folio_relevant(folio)) {
		return;
	}
	// TODO: Update folio metadata with other values we want to track
	struct folio_metadata *meta;
	u64 key = (u64)folio;
	meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
		struct folio_metadata new_meta = { 0 };
		int ret = bpf_map_update_elem(&folio_metadata_map, &key,
					      &new_meta, BPF_ANY);
		if (ret != 0) {
			bpf_printk(
				"cache_ext: Failed to create folio metadata in accessed. Return value: %d\n",
				ret);
			return;
		}
		meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
		if (meta == NULL) {
			bpf_printk("cache_ext: Failed to get created folio metadata in accessed\n");
			return;
		}
	}
	meta->last_access_time = bpf_ktime_get_ns();
	// __sync_fetch_and_add(&meta->accesses, 1);
}

void BPF_STRUCT_OPS(sampling_folio_evicted, struct folio *folio)
{
	dbg_printk(
		"cache_ext: Hi from the sampling_folio_evicted hook! :D\n");
	int ret = bpf_cache_ext_list_del(folio);

	__sync_fetch_and_add(&list_size, -1);
	u64 key = (u64)folio;
	bpf_map_delete_elem(&folio_metadata_map, &key);
	update_stat(&STAT_TOTAL_PAGES, -1);
	update_stat(&STAT_EVICTED_TOTAL_PAGES, 1);

}

static inline bool is_last_page_in_file(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	if (!mapping) {
		return false;
	}
	struct inode *inode = mapping->host;
	if (!inode) {
		return false;
	}
	// TODO: Handle hugepages
	if (folio_test_large(folio) ||  folio_test_hugetlb(folio)) {
		bpf_printk("cache_ext: Hugepages not supported\n");
		return false;
	}
	unsigned long long file_size = i_size_read(inode);
	unsigned long long page_index = folio_index(folio);
	unsigned long long page_size = 4096;
	unsigned long long last_page_index = (file_size + page_size - 1) / page_size - 1;
	return page_index == last_page_index;
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node *a)
{
	s64 score = 0;
	struct folio_metadata *meta_a;
	u64 key_a = (u64)a->folio;
	meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
	if (!meta_a) {
		bpf_printk("cache_ext: Failed to get metadata\n");
		return 0;
	}
	score = meta_a->last_access_time;
	if (APP_TYPE == LEVELDB) {
		// In leveldb, the index block is at the end of the file.
		bool is_last_page = is_last_page_in_file(a->folio);
		if (is_last_page) {
			// bpf_printk("cache_ext: Found last page in file\n");
			score += 100000;
		}
	}

	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) {
		return -1;
	}
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) {
		return -1;
	}
	return score;
}

void BPF_STRUCT_OPS(sampling_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	int zero = 0, one = 1;
	u64 *first_eviction = bpf_map_lookup_elem(&is_first_eviction, &zero);
	if (first_eviction == NULL || *first_eviction == 0) {
		bpf_map_update_elem(&is_first_eviction, &zero, &one, BPF_ANY);
		bpf_printk("cache_ext: First eviction, list size is %llu\n",
			   __sync_fetch_and_add(&list_size, 0));
	}
	dbg_printk(
		"cache_ext: Hi from the sampling_evict_folios hook! :D\n");
	u64 sampling_list = get_sampling_list();
	if (sampling_list == 0) {
		bpf_printk(
			"cache_ext: Failed to get sampling_list on eviction path\n");
		return;
	}
	// TODO: What does the eviction interface look like for sampling?
	struct sampling_options sampling_opts = {
		.sample_size = 10,
	};
	bpf_cache_ext_list_sample(memcg, sampling_list, bpf_lfu_score_fn,
				  &sampling_opts, eviction_ctx);
	dbg_printk("cache_ext: Evicting %d pages (%d requested)\n",
			   eviction_ctx->nr_folios_to_evict,
			   eviction_ctx->request_nr_folios_to_evict);
	dbg_printk("cache_ext: Printing first two and last two folios: %p %p %p %p\n",
			   eviction_ctx->folios_to_evict[0],
			   eviction_ctx->folios_to_evict[1],
			   eviction_ctx->folios_to_evict[32 - 2],
			   eviction_ctx->folios_to_evict[32 - 1]);
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init = (void *)sampling_init,
	.evict_folios = (void *)sampling_evict_folios,
	.folio_accessed = (void *)sampling_folio_accessed,
	.folio_evicted = (void *)sampling_folio_evicted,
	.folio_added = (void *)sampling_folio_added,
};
