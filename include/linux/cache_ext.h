/*
 * BPF-Exposed data structures for page_cache_ext.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/bpf.h>

/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

/*
 * Indexed Linked List.
 *
 * This is a linked list that is indexed by the folio it contains. This is
 * because we need to be able to quickly:
 * - Find the folio corresponding to a given node.
 * - Find the node corresponding to a given folio.
 *
 * Instead of maintaining a hash-table per list, we can piggyback on the valid
 * folios hashtable we already maintain. It will also keep a pointer to the node
 * in the valid_folio struct.
 */
struct cache_ext_list {
	struct list_head head;
	// This is for the ds registry.
	struct hlist_node h_node;
	rwlock_t lock;
};

struct cache_ext_list_node {
	struct folio *folio;

	atomic64_t list_backptr;
	struct list_head node;
};

/*
 * API
 */

struct cache_ext_list_node *cache_ext_list_node_alloc(struct folio *folio);
void cache_ext_list_node_free(struct cache_ext_list_node *node);
int cache_ext_list_add(struct cache_ext_list *list, struct folio *folio);
int cache_ext_list_add_tail(struct cache_ext_list *list, struct folio *folio);
int cache_ext_list_del(struct folio *folio);
int cache_ext_list_iterate(struct cache_ext_list *list, bpf_callback_t cb,
			   struct page_cache_ext_eviction_ctx *ctx);

/*
 * page_cache_ext data structure registry.
 */


// NOTE: For now, tie the registry lifetime to the struct_ops lifetime.
// Release all the data structures when the struct_ops is released.
// Do not permit any structure to be released while the struct_ops is
// still in use.
struct cache_ext_ds_registry {
	DECLARE_HASHTABLE(ds_hash, 5);
	rwlock_t lock;
};

void cache_ext_ds_registry_init(struct cache_ext_ds_registry *registry);