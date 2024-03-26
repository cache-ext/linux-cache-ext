#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, args)

#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, __u64);
} folio_ptr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, bool);
} stop_map SEC(".maps");

__u64 zero_key = 0;
__u64 TEST_INODE_INO = -1;

__inline__ __u64 folio_pointer_to_u64(struct folio *folio)
{
	return (__u64)folio;
}

__inline__ void set_stop()
{
	bool stop = true;
	bpf_map_update_elem(&stop_map, &zero_key, &stop, BPF_ANY);
}

__inline__ bool is_stop()
{
	bool *stop = bpf_map_lookup_elem(&stop_map, &zero_key);
	if (stop == NULL) {
		return false;
	}
	return *stop;
}

SEC("tracepoint/filemap/mm_filemap_delete_from_page_cache")
int cachestream__mm_filemap_delete_from_page_cache(void *ctx)
{
	struct trace_event_raw_mm_filemap_op_page_cache *args = ctx;
	return 0;
}

SEC("tracepoint/filemap/mm_filemap_add_to_page_cache")
int cachestream__mm_filemap_add_to_page_cache(void *ctx)
{
	struct trace_event_raw_mm_filemap_op_page_cache *args = ctx;
	return 0;
}

void BPF_STRUCT_OPS(simple_folio_accessed, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the folio_accessed hook! :D\n");
	// Get a valid folio pointer from the test file
	__u64 inode_no = BPF_CORE_READ(folio, mapping, host, i_ino);
	if (inode_no != TEST_INODE_INO) {
		dbg_printk(
			"page_cache_ext: Got: %llu, want %llu\n", inode_no, TEST_INODE_INO);
		return;
	}
	__u64 *val = bpf_map_lookup_elem(&folio_ptr_map, &zero_key);
	if (val == NULL) {
		bpf_map_update_elem(&folio_ptr_map, &zero_key, &folio,
				    BPF_NOEXIST);
	} else {
		dbg_printk("page_cache_ext: Folio pointer already exists: %p\n", *val);
	}

}

void BPF_STRUCT_OPS(simple_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx)
{
	dbg_printk("page_cache_ext: Hi from the eviction hook! :D\n");
	// Try to evict the folio pointer
	if (is_stop()) {
		return;
	}
	bpf_printk("page_cache_ext: Evicting folio pointer\n");
	__u64 *val = bpf_map_lookup_elem(&folio_ptr_map, &zero_key);
	if (val == NULL) {
		dbg_printk("page_cache_ext: Folio pointer not found\n");
		return;
	}
	struct folio *folio = (struct folio *)*val;
	eviction_ctx->nr_folios_to_evict = 1;
	eviction_ctx->folios_to_evict[0] = folio;
	set_stop();
}

SEC(".struct_ops.link")
struct page_cache_ext_ops simple_ops = {
	.evict_folios = (void *)simple_evict_folios,
	.folio_accessed = (void *)simple_folio_accessed,
};