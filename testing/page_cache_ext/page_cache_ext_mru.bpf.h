#ifndef _CACHE_EXT_MRU_BPF_H
#define _CACHE_EXT_MRU_BPF_H 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CACHE_EXT_STOP_ITER 7
#define CACHE_EXT_MAX_ITER_REACHED 8

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_iterate(
	struct mem_cgroup *memcg, u64 list,
	int(iter_fn)(u64 list, struct cache_ext_list_node *node,
		     struct page_cache_ext_eviction_ctx *ctx),
	struct page_cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;

#endif /* _CACHE_EXT_MRU_BPF_H */
