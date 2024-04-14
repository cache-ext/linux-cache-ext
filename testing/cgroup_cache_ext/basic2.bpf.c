#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, args)

void BPF_STRUCT_OPS(simple_evict_folios,
		    struct page_cache_ext_eviction_ctx *eviction_ctx)
{
    bpf_printk("hello from other eviction!\n");
}

SEC(".struct_ops.link")
struct page_cache_ext_ops simple_ops = {
	.evict_folios = (void *)simple_evict_folios,
};
