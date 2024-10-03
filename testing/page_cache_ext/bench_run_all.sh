#!/bin/bash

set -e
set -x
set -o pipefail
set -u

# Microbenchmark with fio for CPU overhead
# Assumes the data disk is /dev/sdb
python3 bench_fio.py \
    --cpu 8 \
    --target-file /dev/sdb \
    --results-file ./fio_results.json

# Benchmark LevelDB with LFU
python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file ./lfu_ycsb_results.json \
    --leveldb-db /mydata/leveldb_db \
    --benchmark ycsb_a,ycsb_b,ycsb_c

# Benchmark LevelDB with mixed GET-SCAN
python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_get_scan.out \
    --results-file ./get_scan_results.json \
    --leveldb-db /mydata/leveldb_db \
    --benchmark mixed_get_scan


# Benchmark Google IO traces
TRACE_DIR="google_traces/data_cluster1_16TB_20240115_data-00000-of-00100"
python3 bench_io_trace.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file io_trace_results.json  \
    --trace-data-dir $TRACE_DIR

# Benchmark filesearch workload with MRU
python3 bench_filesearch.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_mru.out \
    --results-file filesearch_results.json  \
    --data-dir /mydata/filesearch_data
