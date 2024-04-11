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
#include <linux/btf.h>

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

	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

#define CACHE_EXT_STOP_ITER 7
#define CACHE_EXT_MAX_ITER_REACHED 8

int cache_ext_list_iterate(struct folio *folio, struct cache_ext_list *list,
			   bpf_callback_t cb,
			   struct page_cache_ext_eviction_ctx *ctx)
{
	uint64_t ret = 0, iter = 0;
	uint64_t max_iter = 512;
	struct cache_ext_list_node *node;

	cache_ext_ds_registry_read_lock(folio);
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
	cache_ext_ds_registry_read_unlock(folio);
	return ret;
}

/*
 * Free the list and all its nodes.
 */
int cache_ext_list_free(struct cache_ext_list *list)
{
	struct cache_ext_list_node *node, *tmp;
	list_for_each_entry_safe(node, tmp, &list->head, node) {
		list_del(&node->node);
		cache_ext_list_node_free(node);
	}
	kfree(list);
	return 0;
}

BTF_SET8_START(cache_ext_list_ops)
BTF_ID_FLAGS(func, cache_ext_list_node_alloc, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, cache_ext_list_add, KF_RELEASE)
BTF_ID_FLAGS(func, cache_ext_list_add_tail, KF_RELEASE)
BTF_ID_FLAGS(func, cache_ext_list_del)
BTF_ID_FLAGS(func, cache_ext_list_iterate)
BTF_SET8_END(cache_ext_list_ops)

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
	write_unlock(&registry->lock);
	struct valid_folios_set *valid_folios_set =
		memcg_to_valid_folios_set(memcg);
	valid_folios_clear_list(valid_folios_set);
}

BTF_SET8_START(cache_ext_registry_ops)
BTF_ID_FLAGS(func, cache_ext_ds_registry_new_list,
	     KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
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
	return 0;
}

__initcall(register_cache_ext_kfuncs);