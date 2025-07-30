#!/bin/bash

set -e
set -x
set -o pipefail
set -u

RESULTS_FOLDER="results_sosp"

# Microbenchmark with fio for CPU overhead
# Assumes the data disk is /dev/sdb
# python3 bench_fio.py \
#     --cpu 8 \
#     --target-dir /mydata/fio_dir \
#     --results-file ${RESULTS_FOLDER}/baseline_mglru_fio_results.json

# Benchmark LevelDB with mixed GET-SCAN
# python3 bench_leveldb.py \
#     --cpu 8 \
#     --policy-loader ./cache_ext_get_scan.out \
#     --results-file ./baseline_mglru_get_scan_results.json \
#     --leveldb-db /mydata/leveldb_db \
#     --benchmark mixed_get_scan

# Benchmark LevelDB with LFU
# python3 bench_leveldb.py \
#     --cpu 8 \
#     --policy-loader ./cache_ext_sampling.out \
#     --results-file ./results/baseline_mglru_ycsb_results.json \
#     --leveldb-db /mydata/leveldb_myycsb_db \
#     --fadvise-hints "" \
#     --benchmark uniform,uniform_read_write #ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f

# Benchmark Twitter traces
# for cluster in 17 18 34 52; do
# 	python3 bench_twitter_trace.py \
#         --cpu 8 \
#         --policy-loader ./cache_ext_sampling.out \
#         --results-file ./results/baseline_mglru_twitter_traces_${cluster}.json \
#         --leveldb-db /mydata/leveldb_twitter_cluster${cluster}_db \
#         --benchmark twitter_cluster${cluster}_bench
# done

# Benchmark Google IO traces
# TRACE_DIR="google_traces/data_cluster1_16TB_20240115_data-00000-of-00100"
# python3 bench_io_trace.py \
#     --cpu 8 \
#     --policy-loader ./baseline_mglru_cache_ext_sampling.out \
#     --results-file io_trace_results.json  \
#     --trace-data-dir $TRACE_DIR

# Benchmark filesearch workload with MRU
# python3 bench_filesearch.py \
#     --cpu 8 \
#     --policy-loader ./cache_ext_mru.out \
#     --results-file ./baseline_mglru_filesearch_results.json  \
#     --data-dir /mydata/filesearch_data

# for cluster in 17 18 24 34 52; do
#     python3 bench_twitter_trace.py \
#         --cpu 8 \
#         --results-file ${RESULTS_FOLDER}/baseline_mglru_twitter_traces_${cluster}.json \
#         --leveldb-db /mydata/leveldb_twitter_cluster${cluster}_db \
#         --benchmark twitter_cluster${cluster}_bench
# done

python3 bench_leveldb.py \
    --cpu 8 \
    --results-file $RESULTS_FOLDER/baseline_mglru_kernel_tweak_lfu_ycsb_results.json \
    --leveldb-db /mydata/leveldb_db \
    --fadvise-hints "" \
    --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_e,ycsb_f,uniform,uniform_read_write
