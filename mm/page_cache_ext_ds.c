/*
 * BPF-Exposed data structures for page_cache_ext.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/memcontrol.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/cache_ext.h>

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
	rwlock_init(&list->lock);
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
	atomic64_set(&node->list_backptr, 0);
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

	// Make sure the cache_ext_list still exists.


	// At this point, we don't know if the folio is already in a list.
	// We use the list_backptr to check if it's already in a list.
	// Try to put the folio in this list.
	struct cache_ext_list *old_backptr;
	old_backptr = (struct cache_ext_list *)atomic64_cmpxchg(
		&valid_folio->cache_ext_node->list_backptr, 0, (int64_t)list);
	if (old_backptr != NULL) {
		// Folio is in another list or someone raced with us.
		// TODO: Return something else if it's on our list.
		spin_unlock(bucket_lock);
		if (unlikely(old_backptr == list))
			return 0;
		return -1;
	}
	write_lock(&list->lock);
	if (tail)
		list_add_tail(&valid_folio->cache_ext_node->node, &list->head);
	else
		list_add(&valid_folio->cache_ext_node->node, &list->head);
	write_unlock(&list->lock);
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
		return -1;
	}

	struct cache_ext_list *list = (struct cache_ext_list *)atomic64_read(
		&valid_folio->cache_ext_node->list_backptr);
	if (list == NULL) {
		spin_unlock(bucket_lock);
		return -1;
	}
	struct cache_ext_list *old_backptr;
	old_backptr = (struct cache_ext_list *)atomic64_cmpxchg(
		&valid_folio->cache_ext_node->list_backptr, (int64_t)list, 0);
	if (old_backptr != list) {
		spin_unlock(bucket_lock);
		// Someone raced and removed the folio from the list first.
		if (old_backptr == NULL)
			return 0;
		return -1;
	}
	write_lock(&list->lock);
	list_del(&valid_folio->cache_ext_node->node);
	write_unlock(&list->lock);
	spin_unlock(bucket_lock);
	return 0;
}

#define CACHE_EXT_STOP_ITER 7
#define CACHE_EXT_MAX_ITER_REACHED 8

int cache_ext_list_iterate(struct cache_ext_list *list, bpf_callback_t cb,
			   struct page_cache_ext_eviction_ctx *ctx)
{
	uint64_t ret = 0, iter = 0;
	uint64_t max_iter = 512;
	struct cache_ext_list_node *node;

	read_lock(&list->lock);
	list_for_each_entry(node, &list->head, node) {
		iter++;
		if (iter > max_iter) {
			ret = CACHE_EXT_MAX_ITER_REACHED;
			break;
		}
		// TODO: Ensure that we don't let the callback use any of the list
		// helpers, or we will have a deadlock.
		ret = cb((u64)list, (u64)node, (u64)ctx, 0, 0);
		if (ret != 0) {
			if (ret == CACHE_EXT_STOP_ITER) {
				ret = 0;
			}
			break;
		}
	}
	read_unlock(&list->lock);
	return ret;
}

BTF_SET8_START(cache_ext_list_ops)
BTF_ID_FLAGS(func, cache_ext_list_add)
BTF_ID_FLAGS(func, cache_ext_list_add_tail)
BTF_ID_FLAGS(func, cache_ext_list_del)
BTF_ID_FLAGS(func, cache_ext_list_iterate)
BTF_SET8_END(cache_ext_list_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_list_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_list_ops,
};

static int __init register_cache_ext_kfuncs(void)
{
	int ret;

	if ((ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					     &cache_ext_kfunc_set_list_ops))) {
		pr_err("cache_ext: failed to register kfunc sets (%d)\n", ret);
		return ret;
	}
	return 0;
}

__initcall(register_cache_ext_kfuncs);

/******************************************************************************
 * DS Registry ****************************************************************
 *****************************************************************************/

void cache_ext_ds_registry_init(struct cache_ext_ds_registry *registry)
{
	hash_init(registry->ds_hash);
	rwlock_init(&registry->lock);
}

int cache_ext_ds_registry_add(struct cache_ext_ds_registry *registry,
			      struct cache_ext_list *list)
{
	struct cache_ext_list *cur_list;
	write_lock(&registry->lock);
	u64 key = (u64)list;
	hash_for_each_possible(registry->ds_hash, cur_list, h_node, key) {
		if (key == (u64)cur_list) {
			read_unlock(&registry->lock);
			return -1;
		}
	}
	hash_add(registry->ds_hash, &list->h_node, key);
	write_unlock(&registry->lock);

	return 0;
}

struct cache_ext_list *
cache_ext_ds_registry_get(struct cache_ext_ds_registry *registry,
			  u64 list_ptr)
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


struct cache_ext_ds_registry *cache_ext_ds_registry_from_folio(
	struct folio *folio)
{
	// Get cgroup from folio
	struct mem_cgroup *memcg = folio_memcg(folio);
	// Get pgdat from folio
	pg_data_t *pgdat = folio_pgdat(folio);
	// Get node cgroup
	struct mem_cgroup_per_node *node_cgroup = memcg->nodeinfo[pgdat->node_id];
	// Get valid folios set from cgroup
	return &node_cgroup->cache_ext_ds_registry;
}