/*
 * BPF-Exposed data structures for page_cache_ext.
 */

#include "linux/types.h"
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/memcontrol.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/cache_ext.h>
#include <linux/btf.h>
#include <linux/sort.h>

/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

// TODO: In BPF, we need to add the ability to iterate through the linked list.

/*
 * How does BPF add its own data to a data structure node?
 * - Solution 1: Embed the `cache_ext_list_node` in a BPF-defined struct and
 *               use `bpf_obj_new`. The problem is who initializes the
 *				 `cache_ext_list_node`.
 * - Solution 2: Use some page-local storage to store the BPF data.
 * - Solution 3: Use a map from node to data in BPF. This is slower but easier
 *               to start with we will start here.
 */

struct cache_ext_list *cache_ext_list_alloc(void)
{
	struct cache_ext_list *list =
		kmalloc(sizeof(struct cache_ext_list), GFP_KERNEL);
	if (!list) {
		return NULL;
	}
	INIT_LIST_HEAD(&list->head);
	return list;
}

struct cache_ext_list_node *cache_ext_list_node_alloc(struct folio *folio)
{
	struct cache_ext_list_node *node =
		kmalloc(sizeof(struct cache_ext_list_node), GFP_KERNEL);
	if (!node) {
		return NULL;
	}
	INIT_LIST_HEAD(&node->node);
	node->folio = folio;
	return node;
}

void cache_ext_list_node_free(struct cache_ext_list_node *node)
{
	// TODO: Verify it's isolated first.
	kfree(node);
}

int __cache_ext_list_add_impl(struct cache_ext_list *list, struct folio *folio,
			      bool tail)
{
	struct valid_folios_set *valid_folios_set =
		folio_to_valid_folios_set(folio);
	spinlock_t *bucket_lock =
		valid_folios_set_get_bucket_lock(valid_folios_set, folio);
	spin_lock(bucket_lock);
	struct valid_folio *valid_folio = valid_folios_lookup(folio);
	if (!valid_folio) {
		spin_unlock(bucket_lock);
		return -1;
	}

	// TODO: Make sure the cache_ext_list still exists.

	// Get the global list lock
	cache_ext_ds_registry_write_lock(folio);

	// Is this node already in a list?
	struct cache_ext_list_node *node = valid_folio->cache_ext_node;
	if (!list_empty(&node->node)) {
		cache_ext_ds_registry_write_unlock(folio);
		spin_unlock(bucket_lock);
		return -1;
	}

	if (tail)
		list_add_tail(&valid_folio->cache_ext_node->node, &list->head);
	else
		list_add(&valid_folio->cache_ext_node->node, &list->head);
	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

int cache_ext_list_add(struct cache_ext_list *list, struct folio *folio)
{
	return __cache_ext_list_add_impl(list, folio, false);
}

int cache_ext_list_add_tail(struct cache_ext_list *list, struct folio *folio)
{
	return __cache_ext_list_add_impl(list, folio, true);
}

int cache_ext_list_del(struct folio *folio)
{
	struct valid_folios_set *valid_folios_set =
		folio_to_valid_folios_set(folio);
	spinlock_t *bucket_lock =
		valid_folios_set_get_bucket_lock(valid_folios_set, folio);
	spin_lock(bucket_lock);
	struct valid_folio *valid_folio = valid_folios_lookup(folio);
	if (!valid_folio) {
		spin_unlock(bucket_lock);
		return -1;
	}

	// Get the global list lock
	cache_ext_ds_registry_write_lock(folio);

	// Check if the node is already in no list.
	if (list_empty(&valid_folio->cache_ext_node->node)) {
		cache_ext_ds_registry_write_unlock(folio);
		spin_unlock(bucket_lock);
		return -1;
	}
	// TODO: When deleting, don't poison the pointers.
	list_del(&valid_folio->cache_ext_node->node);
	INIT_LIST_HEAD(&valid_folio->cache_ext_node->node);

	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

#define CACHE_EXT_CONTINUE_ITER 0
#define CACHE_EXT_STOP_ITER 1
#define CACHE_EXT_EVICT_NODE 2
#define CACHE_EXT_MAX_ITER_REACHED 8
#define CACHE_EXT_EVICT_ARRAY_FILLED 9

int cache_ext_list_iterate(struct mem_cgroup *memcg,
			   struct cache_ext_list *list, void *iter_fn,
			   struct page_cache_ext_eviction_ctx *ctx)
{
	uint64_t ret = 0, iter = 0;
	uint64_t max_iter = 512;
	struct cache_ext_list_node *node;
	bpf_callback_t bpf_iter_fn = (bpf_callback_t)iter_fn;

	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_memcg(memcg);
	read_lock(&registry->lock);
	list_for_each_entry(node, &list->head, node) {
		if (iter > max_iter) {
			ret = CACHE_EXT_MAX_ITER_REACHED;
			break;
		}
		// TODO: Ensure that we don't let the callback use any of the list
		// helpers, or we will have a deadlock.
		ret = bpf_iter_fn((u64)iter, (u64)node, (u64)0, (u64)0, (u64)0);
		iter++;
		if (ret == CACHE_EXT_CONTINUE_ITER) {
			continue;
		} else if (ret == CACHE_EXT_STOP_ITER) {
			ret = 0;
			break;
		} else if (ret == CACHE_EXT_EVICT_NODE) {
			ctx->folios_to_evict[ctx->nr_folios_to_evict] =
				node->folio;
			ctx->nr_folios_to_evict++;
			if (ctx->nr_folios_to_evict ==
			    ARRAY_SIZE(ctx->folios_to_evict) - 1) {
				ret = CACHE_EXT_EVICT_ARRAY_FILLED;
				break;
			}
		} else {
			pr_warn("cache_ext: Unknown iterate return code\n");
			break;
		}
	}
	read_unlock(&registry->lock);
	return ret;
}

/*
 * Free the list.
 */
int cache_ext_list_free(struct cache_ext_list *list)
{
	struct cache_ext_list_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list->head, node) {
		list_del(&node->node);
	}
	kfree(list);
	return 0;
}

// BPF API

int bpf_cache_ext_list_add(u64 list, struct folio *folio)
{
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_folio(folio), list);
	if (!list_ptr) {
		return -1;
	}
	return cache_ext_list_add(list_ptr, folio);
};

int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio)
{
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_folio(folio), list);
	if (!list_ptr) {
		return -1;
	}

	return cache_ext_list_add_tail(list_ptr, folio);
};

int bpf_cache_ext_list_del(struct folio *folio)
{
	return cache_ext_list_del(folio);
};

int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct page_cache_ext_eviction_ctx *ctx)
{
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_memcg(memcg), list);
	if (!list_ptr) {
		return -1;
	}
	return cache_ext_list_iterate(memcg, list_ptr, (void *)iter_fn, ctx);
};

int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *a),
			      struct sampling_options *opts,
				  struct page_cache_ext_eviction_ctx *ctx)
{
	// Select the first select_size elements with the lowest score out of
	// sample_size elements in the given list.
	__u32 sample_size = opts->sample_size;

	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_memcg(memcg);
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(registry, list);
	if (!list_ptr) {
		pr_err("cache_ext: list is NULL\n");
		return -1;
	}
	write_lock(&registry->lock);
	if (list_empty(&list_ptr->head)) {
		pr_warn("cache_ext: list is empty\n");
		write_unlock(&registry->lock);
		return 0;
	}
	// Optimization: Snip the front of the list and select the pages without
	// holding the lock.
	// TODO: Get a reference to the page here and drop it after adding it back.
	LIST_HEAD(snipped_list);
	struct cache_ext_list_node *list_node;
	int snipped_list_size = 0;
	int desired_snipped_list_size = sample_size * ctx->request_nr_folios_to_evict;

	while (snipped_list_size < desired_snipped_list_size) {
		if (list_empty(&list_ptr->head)) {
			break;
		}
		list_node = list_first_entry(&list_ptr->head,
					     struct cache_ext_list_node, node);
		list_move(&list_node->node, &snipped_list);
		snipped_list_size++;
	}
	if (snipped_list_size < desired_snipped_list_size) {
		pr_err("cache_ext: Not enough elements in the list. List has %d but want %d\n",
			snipped_list_size, desired_snipped_list_size);
		list_splice(&snipped_list, &list_ptr->head);
		write_unlock(&registry->lock);
		return -1;
	}
	write_unlock(&registry->lock);
	// 1. For every n elements, evict the one with the min score
	int select_every_nth = sample_size;
	ctx->nr_folios_to_evict = 0;
	struct cache_ext_list_node *curr_node = list_first_entry(
		&snipped_list, struct cache_ext_list_node, node);
	for (int i = 0; i < ctx->request_nr_folios_to_evict; i++) {
		struct cache_ext_list_node *min_node = NULL;
		s64 min_score = S64_MAX;
		for (int j = 0; j < select_every_nth; j++) {
			if (curr_node == NULL) {
				pr_warn("cache_ext: curr_node is NULL, ran out of folios to evict\n");
				break;
			}
			s64 curr_score = score_fn(curr_node);
			if (j == 0) {
				min_node = curr_node;
				min_score = curr_score;
				continue;
			} else if (curr_score < min_score) {
				min_score = curr_score;
				min_node = curr_node;
			}
			curr_node = list_next_entry(curr_node, node);
		}
		if (min_node == NULL) {
			pr_warn("cache_ext: min_node is NULL, ran out of folios to evict\n");
			break;
		}
		ctx->folios_to_evict[ctx->nr_folios_to_evict] = min_node->folio;
		ctx->nr_folios_to_evict++;
	}

	// 2. Put everything to the back of the list.
	write_lock(&registry->lock);
	list_splice_tail(&snipped_list, &list_ptr->head);

	write_unlock(&registry->lock);
	return 0;
}

BTF_SET8_START(cache_ext_list_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add_tail)
BTF_ID_FLAGS(func, bpf_cache_ext_list_del)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate)
BTF_ID_FLAGS(func, bpf_cache_ext_list_sample)
BTF_SET8_END(cache_ext_list_ops)

noinline bool cache_ext_is_callback_calling_kfunc_iterate(u32 btf_id)
{
	return (btf_id == cache_ext_list_ops.pairs[3].id) ;
}

noinline bool cache_ext_is_callback_calling_kfunc_sample(u32 btf_id)
{
	return (btf_id == cache_ext_list_ops.pairs[4].id);
}

static const struct btf_kfunc_id_set cache_ext_kfunc_set_list_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_list_ops,
};

/******************************************************************************
 * DS Registry ****************************************************************
 *****************************************************************************/

void cache_ext_ds_registry_init(struct cache_ext_ds_registry *registry)
{
	hash_init(registry->ds_hash);
	rwlock_init(&registry->lock);
	registry->nr_entries = 0;
}

struct cache_ext_ds_registry *
cache_ext_ds_registry_from_memcg(struct mem_cgroup *memcg)
{
	return &memcg->nodeinfo[0]->cache_ext_ds_registry;
}

struct cache_ext_list *cache_ext_ds_registry_new_list(struct mem_cgroup *memcg)
{
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_memcg(memcg);
	struct cache_ext_list *list = cache_ext_list_alloc();
	if (list == NULL) {
		return NULL;
	}
	write_lock(&registry->lock);
	if (registry->nr_entries >= CACHE_EXT_REGISTRY_MAX_ENTRIES) {
		write_unlock(&registry->lock);
		cache_ext_list_free(list);
		return NULL;
	}
	u64 key = (u64)list;
	hash_add(registry->ds_hash, &list->h_node, key);
	registry->nr_entries++;
	write_unlock(&registry->lock);

	return list;
}

struct cache_ext_list *
cache_ext_ds_registry_get(struct cache_ext_ds_registry *registry, u64 list_ptr)
{
	struct cache_ext_list *cur_list;
	u64 key = list_ptr;
	read_lock(&registry->lock);
	hash_for_each_possible(registry->ds_hash, cur_list, h_node, key) {
		if (key == (u64)cur_list) {
			read_unlock(&registry->lock);
			return cur_list;
		}
	}
	read_unlock(&registry->lock);

	return NULL;
}

struct cache_ext_ds_registry *
cache_ext_ds_registry_from_folio(struct folio *folio)
{
	// Get cgroup from folio
	struct mem_cgroup *memcg = folio_memcg(folio);
	// Get pgdat from folio
	pg_data_t *pgdat = folio_pgdat(folio);
	// Get node cgroup
	struct mem_cgroup_per_node *node_cgroup =
		memcg->nodeinfo[pgdat->node_id];
	// Get valid folios set from cgroup
	return &node_cgroup->cache_ext_ds_registry;
}

struct cache_ext_ds_registry *
cache_ext_ds_registry_from_mem_cgroup(struct mem_cgroup *memcg)
{
	return &memcg->nodeinfo[0]->cache_ext_ds_registry;
}

void cache_ext_ds_registry_read_lock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_folio(folio);
	read_lock(&registry->lock);
}

void cache_ext_ds_registry_read_unlock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_folio(folio);
	read_unlock(&registry->lock);
}

void cache_ext_ds_registry_write_lock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_folio(folio);
	write_lock(&registry->lock);
}

void cache_ext_ds_registry_write_unlock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_folio(folio);
	write_unlock(&registry->lock);
}

void cache_ext_ds_registry_del_all(struct mem_cgroup *memcg)
{
	int bkt;
	struct hlist_node *tmp;
	struct cache_ext_list *cur_list;
	struct cache_ext_ds_registry *registry =
		cache_ext_ds_registry_from_memcg(memcg);
	write_lock(&registry->lock);
	hash_for_each_safe(registry->ds_hash, bkt, tmp, cur_list, h_node) {
		hash_del(&cur_list->h_node);
		cache_ext_list_free(cur_list);
	}
	registry->nr_entries = 0;
	write_unlock(&registry->lock);
	struct valid_folios_set *valid_folios_set =
		memcg_to_valid_folios_set(memcg);
	valid_folios_clear_list(valid_folios_set);
}

// BPF API

u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg)
{
	return (u64)cache_ext_ds_registry_new_list(memcg);
}

BTF_SET8_START(cache_ext_registry_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_ds_registry_new_list, KF_SLEEPABLE)
BTF_SET8_END(cache_ext_registry_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_registry_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_registry_ops,
};

static int __init register_cache_ext_kfuncs(void)
{
	int ret;

	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &cache_ext_kfunc_set_list_ops)) ||
	    (ret = register_btf_kfunc_id_set(
		     BPF_PROG_TYPE_STRUCT_OPS,
		     &cache_ext_kfunc_set_registry_ops))) {
		pr_err("cache_ext: failed to register kfunc sets (%d)\n", ret);
		return ret;
	}
	pr_info("version string lalakis1\n");

	pr_info("BTF IDs:\n");
	for (int i = 0; i < cache_ext_list_ops.cnt; i++) {
		pr_info("%d: %d\n", i, cache_ext_list_ops.pairs[i].id);
	}
	return 0;
}

__initcall(register_cache_ext_kfuncs);
