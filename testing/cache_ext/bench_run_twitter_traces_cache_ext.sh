#!/bin/bash

set -e
set -x
set -o pipefail
set -u

RESULTS_FOLDER="results_sosp"

cd /mydata/linux/linux/testing/cache_ext

#for cluster in 3 4 5 6 7 8 17 18 24 34 52; do
# for cluster in 17 18 24 34 52; do
# 	python3 bench_twitter_trace.py \
#         --cpu 8 \
#         --policy-loader ./cache_ext_s3fifo.out \
#         --results-file ./results/cache_ext_twitter_traces_${cluster}.json \
#         --leveldb-db /mydata/leveldb_twitter_cluster${cluster}_db \
#         --benchmark twitter_cluster${cluster}_bench
# done

# for cluster in 17 18 24 34 52; do
#     python3 bench_twitter_trace.py \
#         --cpu 8 \
#         --policy-loader ./cache_ext_lhd.out \
#         --results-file ./results/cache_ext_twitter_traces_${cluster}.json \
#         --leveldb-db /mydata/leveldb_twitter_cluster${cluster}_db \
#         --benchmark twitter_cluster${cluster}_bench
# done

for policy in cache_ext_fifo cache_ext_mru cache_ext_s3fifo cache_ext_sampling cache_ext_lhd cache_ext_mglru; do
    for cluster in 17 18 24 34 52; do
        python3 bench_twitter_trace.py \
            --cpu 8 \
            --policy-loader ./${policy}.out \
            --results-file ./results_sosp/cache_ext_twitter_traces_${policy}_${cluster}.json \
            --leveldb-db /mydata/leveldb_twitter_cluster${cluster}_db \
            --benchmark twitter_cluster${cluster}_bench
    done
done
