#!/bin/bash

set -e
set -x
set -o pipefail
set -u

# Iterate over policies
POLICIES=(
    "cache_ext_lhd"
    "cache_ext_s3fifo"
    "cache_ext_sampling"
    "cache_ext_fifo"
    "cache_ext_mru"
)

# for POLICY in "${POLICIES[@]}"; do
#     echo "Running policy: ${POLICY}"
#     python3 bench_leveldb.py \
#         --cpu 8 \
#         --policy-loader "./${POLICY}.out" \
#         --results-file "./results/cache_ext_ycsb_results_w_latency.json" \
#         --leveldb-db /mydata/leveldb_myycsb_db \
#         --fadvise-hints "" \
#         --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f
# done

# for POLICY in "${POLICIES[@]}"; do
#     echo "Running policy: ${POLICY}"
#     python3 bench_leveldb.py \
#         --cpu 8 \
#         --policy-loader "./${POLICY}.out" \
#         --results-file "./results/cache_ext_ycsb_results_w_latency.json" \
#         --leveldb-db /mydata/leveldb_myycsb_db \
#         --fadvise-hints "" \
#         --benchmark uniform,uniform_read_write
# done

python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./cache_ext_lhd.out \
    --results-file ./results/cache_ext_ycsb_results_w_latency.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --fadvise-hints "" \
    --benchmark uniform,uniform_read_write

# python3 bench_leveldb.py \
#     --cpu 8 \
#     --policy-loader ./cache_ext_s3fifo.out \
#     --results-file ./results/cache_ext_ycsb_results_w_latency.json \
#     --leveldb-db /mydata/leveldb_myycsb_db \
#     --fadvise-hints "" \
#     --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f

# python3 bench_leveldb.py \
#     --cpu 8 \
#     --policy-loader ./cache_ext_sampling.out \
#     --results-file ./results/cache_ext_ycsb_results_w_latency.json \
#     --leveldb-db /mydata/leveldb_myycsb_db \
#     --fadvise-hints "" \
#     --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f

