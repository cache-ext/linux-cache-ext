// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

int filter_memcg_id = -1;

#define MAX_NR_GENS 4

#define assert_valid_gen_1(gen_idx)                                            \
	if (gen_idx < 0 || gen_idx >= MAX_NR_GENS) {                           \
		bpf_printk("cache_ext: Invalid gen index %d\n", gen_idx); \
		return -1;                                                     \
	}

struct debug_stats {
    unsigned long min_seq;
    unsigned long max_seq;
    long nr_pages[MAX_NR_GENS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct debug_stats);
} debug_stats_map SEC(".maps");


static struct debug_stats* get_debug_stats() {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&debug_stats_map, &zero);
}

static void set_debug_stats(struct debug_stats *dbg_stats) {
    __u32 zero = 0;
    bpf_map_update_elem(&debug_stats_map, &zero, dbg_stats, BPF_ANY);
}


SEC("fexit/get_lruvec")
int BPF_PROG(trace_get_lruvec_exit, struct mem_cgroup *memcg, int nid, struct lruvec *ret)
{
    if (filter_memcg_id != -1 && filter_memcg_id != memcg->id.id) return 0;
	bpf_printk("cache_ext: get_lruvec returned lruvec=%llx for memcg=%llx nid=%d\n",
		   (unsigned long long)ret, (unsigned long long)memcg, nid);
	if (ret == NULL) return 0;
    struct lruvec* lruvec = ret;

    struct lru_gen_folio *lrugen = &lruvec->lrugen;
    struct debug_stats dbg_stats;
    unsigned long min_seq = READ_ONCE(lrugen->min_seq[LRU_GEN_FILE]);
    unsigned long max_seq = READ_ONCE(lrugen->max_seq);
    dbg_stats.min_seq = min_seq;
    dbg_stats.max_seq = max_seq;

    unsigned long num_iter = max_seq - min_seq;
    if (num_iter < 0 || num_iter > MAX_NR_GENS) {
        bpf_printk("cache_ext: invalid seq range: min_seq=%d max_seq=%d\n", min_seq, max_seq);
        return 0;
    }
    // unsigned long indexes[MAX_NR_GENS] = {7, 17, 27, 37};
    // for (unsigned int i = 0; i < num_iter; i++) {
    //     unsigned long seq = min_seq + i;
    //     unsigned long gen = seq % MAX_NR_GENS;
    //     assert_valid_gen_1(gen);
    //     // unsigned long stride_gen = 10;
    //     // unsigned long type = LRU_GEN_FILE;
    //     // unsigned long stride_type = 5;
    //     // unsigned long zone = ZONE_NORMAL;
    //     // unsigned long stride_zone = 1;
    //     unsigned long index = indexes[gen];
    //     // unsigned long index = gen*stride_gen + type*stride_type + zone*stride_zone;
    //     if (index >= 0 && index < 40) {
    //         dbg_stats.nr_pages[gen] = READ_ONCE(lrugen->nr_pages[index]);
    //     }
    // }

    int gen = 0;
    for (int index = 7; index <= 37; index += 10) {
        dbg_stats.nr_pages[gen] = READ_ONCE(lrugen->nr_pages[index]);
        gen += 1;
    }
    set_debug_stats(&dbg_stats);
    return 0;
}
