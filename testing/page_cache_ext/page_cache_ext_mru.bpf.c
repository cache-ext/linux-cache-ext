#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "page_cache_ext_mru.bpf.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, args)

// #define DEBUG

#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif


void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the folio_accessed hook! :D\n");
}

void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the folio_accessed hook! :D\n");
}

void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
	dbg_printk("page_cache_ext: Hi from the folio_accessed hook! :D\n");
}

void BPF_STRUCT_OPS(mru_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx)
{
	dbg_printk("page_cache_ext: Hi from the eviction hook! :D\n");
}

SEC(".struct_ops.link")
struct page_cache_ext_ops mru_ops = {
	.evict_folios = (void *)mru_evict_folios,
	.folio_accessed = (void *)mru_folio_accessed,
    .folio_evicted = (void *)mru_folio_evicted,
    .folio_added = (void *)mru_folio_added,
};