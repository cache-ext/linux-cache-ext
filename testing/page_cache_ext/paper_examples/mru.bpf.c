s32 mru_init(struct mem_cgroup *memcg)
{
	int zero = 0;
	mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
}

void mru_folio_added(struct folio *folio)
{
	bpf_cache_ext_list_add(mru_list, folio);
}

void mru_folio_accessed(struct folio *folio)
{
	bpf_cache_ext_list_move_to_head(mru_list, folio);
}

void mru_folio_evicted(struct folio *folio)
{
	bpf_cache_ext_list_del(folio);
}

static int iterate_mru(int idx, struct cache_ext_list_node *node)
{
	return CACHE_EXT_EVICT_NODE;
}

void mru_evict_folios(struct page_cache_ext_eviction_ctx *eviction_ctx,
	                struct mem_cgroup *memcg)
{
	int ret = bpf_cache_ext_list_iterate(memcg, mru_list, iterate_mru,
					                     eviction_ctx);
}