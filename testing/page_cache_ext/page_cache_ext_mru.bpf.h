#ifndef _CACHE_EXT_MRU_BPF_H
#define _CACHE_EXT_MRU_BPF_H 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct cache_ext_list *
cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;
struct cache_ext_list_node *
cache_ext_list_node_alloc(struct folio *folio) __ksym;
int cache_ext_list_add(struct cache_ext_list *list, struct folio *folio) __ksym;
int cache_ext_list_add_tail(struct cache_ext_list *list,
			    struct folio *folio) __ksym;
int cache_ext_list_del(struct folio *folio) __ksym;
int cache_ext_list_iterate(struct folio *folio, struct cache_ext_list *list,
			   bpf_callback_t cb,
			   struct page_cache_ext_eviction_ctx *ctx) __ksym;

#endif /* _CACHE_EXT_MRU_BPF_H */
