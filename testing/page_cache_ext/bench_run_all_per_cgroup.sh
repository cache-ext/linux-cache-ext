#!/bin/bash

set -e
set -x
set -o pipefail
set -u

# python3 bench_per_cgroup.py \
#     --cpu 8 \
#     --search-path /mydata/cgroup \
#     --data-dir /mydata/cgroup/linuxes/linux \
#     --policy-loader ./page_cache_ext_sampling_per_cgroup.out \
#     --second-policy-loader ./page_cache_ext_mru_per_cgroup.out \
#     --results-file ./results/final_per_cgroup_results.json \
#     --leveldb-db /mydata/leveldb_myycsb_db \
#     --leveldb-temp-db /mydata/cgroup/leveldb_myycsb_db_temp \
#     --benchmark ycsb_c

python3 bench_per_cgroup.py \
    --cpu 8 \
    --search-path /mydata/cgroup \
    --data-dir /mydata/cgroup/linuxes/linux \
    --policy-loader ./page_cache_ext_sampling_per_cgroup.out \
    --second-policy-loader ./page_cache_ext_sampling_per_cgroup.out \
    --results-file ./results/per_cgroup_both_lfu_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --leveldb-temp-db /mydata/cgroup/leveldb_myycsb_db_temp \
    --benchmark ycsb_c

python3 bench_per_cgroup.py \
    --cpu 8 \
    --search-path /mydata/cgroup \
    --data-dir /mydata/cgroup/linuxes/linux \
    --policy-loader ./page_cache_ext_mru_per_cgroup.out \
    --second-policy-loader ./page_cache_ext_mru_per_cgroup.out \
    --results-file ./results/per_cgroup_both_mru_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --leveldb-temp-db /mydata/cgroup/leveldb_myycsb_db_temp \
    --benchmark ycsb_c

python3 bench_per_cgroup.py \
    --cpu 8 \
    --search-path /mydata/cgroup \
    --data-dir /mydata/cgroup/linuxes/linux \
    --policy-loader ./page_cache_ext_sampling_per_cgroup.out \
    --second-policy-loader ./page_cache_ext_mru_per_cgroup.out \
    --results-file ./results/per_cgroup_split_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --leveldb-temp-db /mydata/cgroup/leveldb_myycsb_db_temp \
    --benchmark ycsb_c
