#ifndef _CACHE_EXT_MRU_BPF_H
#define _CACHE_EXT_MRU_BPF_H 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CACHE_EXT_CONTINUE_ITER 0
#define CACHE_EXT_STOP_ITER 1
#define CACHE_EXT_EVICT_NODE 2
#define CACHE_EXT_MAX_ITER_REACHED 8
#define CACHE_EXT_EVICT_ARRAY_FILLED 9

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct page_cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;

#endif /* _CACHE_EXT_MRU_BPF_H */
